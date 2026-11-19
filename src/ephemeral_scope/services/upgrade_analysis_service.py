"""Top-level use-case orchestrator."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from packaging.utils import canonicalize_name

from ephemeral_scope.analysis.ast_usage_analyzer import AstUsageAnalyzer
from ephemeral_scope.analysis.test_mapper import TestMapper
from ephemeral_scope.analysis.usage_change_matcher import UsageChangeMatcher
from ephemeral_scope.domain.models import (
    AffectedUsage,
    AnalysisRequest,
    AnalysisWarning,
    ApiChange,
    ApiUsage,
    ClassifiedChange,
    Dependency,
    DependencyUpgrade,
    EvidenceBundle,
    ProjectManifest,
    TestReference,
    UpgradeReport,
)
from ephemeral_scope.evidence.evidence_collector import EvidenceCollector
from ephemeral_scope.ingestion.dependency_parser import DependencyParser
from ephemeral_scope.inference.fact_builder import FactBase, FactBuilder
from ephemeral_scope.inference.prolog_risk_engine import (
    InferenceResult,
    PrologRiskEngine,
    PrologUnavailableError,
    infer,
)
from ephemeral_scope.ingestion.project_loader import ProjectLoader
from ephemeral_scope.ml.release_note_classifier import ReleaseNoteClassifier
from ephemeral_scope.ml.relevance_matcher import RelevanceMatcher
from ephemeral_scope.packages.api_comparator import ApiComparator
from ephemeral_scope.packages.api_snapshot_builder import ApiSnapshotBuilder
from ephemeral_scope.reporting.report_builder import ReportBuilder

logger = logging.getLogger(__name__)


class UpgradeAnalysisService:
    """Owns the use case: analyze(request) -> UpgradeReport.

    Collaborators are injected so the pipeline can be exercised without
    reaching PyPI, GitHub or OSV. The two that depend on the project under
    analysis -- the relevance matcher and the fact builder -- are injected
    as factories and constructed fresh per request, because both accumulate
    state and a shared instance would leak one analysis into the next.
    """

    def __init__(
        self,
        project_loader: ProjectLoader | None = None,
        usage_analyzer: AstUsageAnalyzer | None = None,
        snapshot_builder: ApiSnapshotBuilder | None = None,
        comparator: ApiComparator | None = None,
        matcher: UsageChangeMatcher | None = None,
        evidence_collector: EvidenceCollector | None = None,
        dependency_parser: DependencyParser | None = None,
        release_note_classifier: ReleaseNoteClassifier | None = None,
        relevance_matcher: Callable[..., RelevanceMatcher] | None = None,
        test_mapper: TestMapper | None = None,
        fact_builder: Callable[[], FactBuilder] | None = None,
        risk_engine: PrologRiskEngine | None = None,
        report_builder: ReportBuilder | None = None,
    ) -> None:
        self.project_loader = project_loader or ProjectLoader()
        self.usage_analyzer = usage_analyzer or AstUsageAnalyzer()
        self.snapshot_builder = snapshot_builder or ApiSnapshotBuilder()
        self.comparator = comparator or ApiComparator()
        self.matcher = matcher or UsageChangeMatcher()
        self.evidence_collector = evidence_collector or EvidenceCollector()
        self.dependency_parser = dependency_parser or DependencyParser()
        # Rules only, unless the caller passes a classifier. The application
        # factory in ephemeral_scope.main loads the verified TF-IDF model;
        # constructing it here would import scikit-learn on every test.
        self.release_note_classifier = (
            release_note_classifier or ReleaseNoteClassifier()
        )
        self.relevance_matcher_factory = relevance_matcher or RelevanceMatcher
        self.test_mapper = test_mapper or TestMapper()
        self.fact_builder_factory = fact_builder or FactBuilder
        self.risk_engine = risk_engine or PrologRiskEngine()
        self.report_builder = report_builder or ReportBuilder(engine=self.risk_engine)

    def analyze(self, request: AnalysisRequest) -> UpgradeReport:
        """Run the whole pipeline and return the report.

        Order is the order the evidence depends on: the project is read
        before its usages can be found, usages before they can be matched
        to API changes, and both before a release note can be judged
        relevant to them. Inference comes last because it consumes
        everything else.

        A ZIP is extracted into a temporary directory that is deleted before
        this method returns, including when analysis fails. The report holds
        the paths it already recorded; it does not need the files afterwards.
        """
        with self._open_project(request.project_path) as root:
            return self._analyze(replace(request, project_path=root))

    def _analyze(self, request: AnalysisRequest) -> UpgradeReport:
        manifest = self.load_project(request.project_path)
        manifest = replace(
            manifest,
            dependencies=tuple(self.dependency_parser.parse(manifest)),
        )
        declared = self._declared_dependency(manifest, request.package_name)
        scan = self.usage_analyzer.analyze(manifest, request.package_name)
        usages = list(scan.usages)
        api_changes, snapshot_warnings = self.compare_versions(request)
        affected = self.matcher.match(usages, api_changes)
        # Only changes that land on code the project actually calls. Indexing
        # every package change would mark a note about an unused API as
        # relevant, and a relevant breaking note becomes a medium-risk finding.
        affected_changes = [item.change for item in affected]

        upgrade = DependencyUpgrade(
            package_name=request.package_name,
            current_version=request.current_version,
            target_version=request.target_version,
        )
        evidence = self.evidence_collector.collect(upgrade)
        classified = self.release_note_classifier.classify(evidence.release_notes)
        # The model warning is fixed when the classifier is constructed. It
        # is not request state, so sharing the classifier across requests is
        # safe. Parser and snapshot warnings are local to this call.
        warnings = _analysis_warnings(
            scan.warnings,
            snapshot_warnings,
            getattr(self.release_note_classifier, "warning", None),
        )
        classified = self._score_relevance(
            classified, usages, affected_changes, upgrade
        )
        references = self.test_mapper.map(manifest, [item.usage for item in affected])

        # File reading is done. The report must not keep the absolute paths,
        # because a ZIP's extraction directory is deleted when analyze returns.
        usages, affected, references, declared, warnings = _relative_to_project(
            manifest.root_path, usages, affected, references, declared, warnings
        )

        facts = self._facts(
            upgrade, usages, api_changes, affected, classified, evidence, references
        )
        inference = self._evaluate(
            facts, upgrade, usages, api_changes, affected, classified, evidence, references
        )
        return self.report_builder.build(
            upgrade,
            usages=usages,
            api_changes=api_changes,
            affected=affected,
            classified_changes=classified,
            evidence=evidence,
            test_references=references,
            inference=inference,
            declared_dependency=declared,
            warnings=warnings,
            api_compared=not snapshot_warnings,
        )

    def _declared_dependency(
        self, manifest: ProjectManifest, package_name: str
    ) -> Dependency | None:
        """The project's declaration of ``package_name``, if it has one.

        Absence is a warning, not a failure. A project can use a package it
        never lists directly, because the package is transitive or was
        installed by hand.
        """
        wanted = canonicalize_name(package_name)
        for dependency in manifest.dependencies:
            if canonicalize_name(dependency.name) == wanted:
                return dependency

        logger.warning(
            "%s is not declared by this project; it may be transitive or "
            "installed dynamically. Looked in %s.",
            package_name,
            ", ".join(path.name for path in manifest.dependency_files)
            or "no dependency file",
        )
        return None

    def find_affected_usages(self, request: AnalysisRequest) -> list[AffectedUsage]:
        """Report the places in the project that the upgrade lands on."""
        with self._open_project(request.project_path) as root:
            scoped = replace(request, project_path=root)
            manifest = self.load_project(scoped.project_path)
            usages = list(
                self.usage_analyzer.analyze(manifest, scoped.package_name).usages
            )
            changes, _snapshot_warnings = self.compare_versions(scoped)
            return self.matcher.match(usages, changes)

    @contextmanager
    def _open_project(self, project_path: Path) -> Iterator[Path]:
        """Yield the project root, deleting a ZIP extraction afterwards."""
        path = Path(project_path)
        if path.is_file() and path.suffix == ".zip":
            with TemporaryDirectory(prefix="ephemeral-scope-upload-") as directory:
                yield self.project_loader.extract_zip(path, Path(directory))
            return
        yield path

    def load_project(self, project_path: Path) -> ProjectManifest:
        """Load a directory. ZIP archives are extracted by ``_open_project``."""
        path = Path(project_path)
        if path.is_file() and path.suffix == ".zip":
            raise ValueError(
                "A ZIP must be extracted by the caller, so the directory can "
                "be deleted after analysis."
            )
        return self.project_loader.load_directory(path)

    def compare_versions(self, request: AnalysisRequest) -> tuple[list[ApiChange], tuple[AnalysisWarning, ...]]:
        """Diff the two versions, or report nothing when a snapshot is unusable.

        An empty or failed snapshot is not a package with no API. Diffing it
        against a real one would report every symbol as removed, so the
        comparison is skipped and the failure is returned with the result.
        Nothing is stored on the service.
        """
        old, old_warning = self._snapshot(
            request.package_name, request.current_version
        )
        new, new_warning = self._snapshot(
            request.package_name, request.target_version
        )
        warnings = tuple(
            warning for warning in (old_warning, new_warning) if warning is not None
        )
        if warnings:
            return [], warnings
        return self.comparator.compare(old, new), warnings

    def _snapshot(
        self, package_name: str, version: str
    ) -> tuple[object, AnalysisWarning | None]:
        try:
            snapshot = self.snapshot_builder.build(package_name, version)
        except Exception as exc:
            logger.exception("API snapshot failed for %s==%s", package_name, version)
            return None, AnalysisWarning(
                "api_snapshot",
                f"Package API snapshot incomplete for {package_name}=={version}: {exc}",
            )
        if not getattr(snapshot, "symbols", ()):
            return snapshot, AnalysisWarning(
                "api_snapshot",
                f"Package API snapshot incomplete for {package_name}=={version}: "
                "no public symbols were found",
            )
        return snapshot, None

    def _score_relevance(
        self,
        classified: list[ClassifiedChange],
        usages: list[ApiUsage],
        api_changes: list[ApiChange],
        upgrade: DependencyUpgrade,
    ) -> list[ClassifiedChange]:
        """Score every statement against this project, keeping all of them.

        The matcher is built here rather than stored, because it is the
        project's usages and not a reusable service.
        """
        matcher = self.relevance_matcher_factory(
            usages, api_changes, upgrade.package_name
        )
        return matcher.annotate(classified)

    def _facts(
        self,
        upgrade: DependencyUpgrade,
        usages: list[ApiUsage],
        api_changes: list[ApiChange],
        affected: list[AffectedUsage],
        classified: list[ClassifiedChange],
        evidence: EvidenceBundle,
        references: list[TestReference],
    ) -> FactBase:
        # A new builder per analysis: FactBuilder accumulates, so reusing one
        # would carry the previous request's facts into this one.
        return (
            self.fact_builder_factory()
            .add_upgrade(upgrade)
            .add_usages(usages)
            .add_api_changes(api_changes)
            .add_affected_usages(affected)
            .add_classified_changes(classified)
            .add_evidence(upgrade, evidence)
            .add_test_references(references)
            .build()
        )

    def _evaluate(
        self,
        facts: FactBase,
        upgrade: DependencyUpgrade,
        usages: list[ApiUsage],
        api_changes: list[ApiChange],
        affected: list[AffectedUsage],
        classified: list[ClassifiedChange],
        evidence: EvidenceBundle,
        references: list[TestReference],
    ) -> InferenceResult:
        """Ask Prolog, and fall back to the Python assessor if it is absent.

        A query that fails while Prolog is installed is not caught here.
        That is a broken rule, and the report should not quietly substitute
        a different answer.
        """
        try:
            return self.risk_engine.infer(facts)
        except PrologUnavailableError:
            return infer(
                upgrade,
                usages=usages,
                api_changes=api_changes,
                affected=affected,
                classified_changes=classified,
                evidence=evidence,
                test_references=references,
                engine=self.risk_engine,
            )


def _analysis_warnings(
    parser: tuple[AnalysisWarning, ...],
    snapshots: tuple[AnalysisWarning, ...],
    model: AnalysisWarning | None,
) -> tuple[AnalysisWarning, ...]:
    found = [*parser, *snapshots]
    if model is not None:
        found.append(model)
    return tuple(found)


def _relative(path: Path, root: Path) -> Path:
    """Path relative to the project root, left unchanged when it is outside."""
    try:
        return path.relative_to(root)
    except ValueError:
        return path


def _relative_to_project(
    root: Path,
    usages: list[ApiUsage],
    affected: list[AffectedUsage],
    references: list[TestReference],
    declared: Dependency | None,
    warnings: tuple[AnalysisWarning, ...],
) -> tuple[
    list[ApiUsage],
    list[AffectedUsage],
    list[TestReference],
    Dependency | None,
    tuple[AnalysisWarning, ...],
]:
    relative_usages = [
        replace(usage, file=_relative(usage.file, root)) for usage in usages
    ]
    relative_affected = [
        replace(item, usage=replace(item.usage, file=_relative(item.usage.file, root)))
        for item in affected
    ]
    relative_references = [
        replace(
            reference,
            test_file=_relative(reference.test_file, root),
            source_file=_relative(reference.source_file, root),
        )
        for reference in references
    ]
    if declared is not None:
        declared = replace(
            declared, source_file=_relative(declared.source_file, root)
        )
    relative_warnings = tuple(_relativize_warning(warning, root) for warning in warnings)
    return (
        relative_usages,
        relative_affected,
        relative_references,
        declared,
        relative_warnings,
    )


def _relativize_warning(warning: AnalysisWarning, root: Path) -> AnalysisWarning:
    """Rewrite an absolute project path inside a warning message."""
    prefix = root.as_posix().rstrip("/") + "/"
    message = warning.message.replace(prefix, "")
    if message == warning.message:
        return warning
    return replace(warning, message=message)
