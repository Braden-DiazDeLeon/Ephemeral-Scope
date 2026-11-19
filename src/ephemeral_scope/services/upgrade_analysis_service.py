"""Top-level use-case orchestrator."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from packaging.utils import canonicalize_name

from ephemeral_scope.analysis.ast_usage_analyzer import AstUsageAnalyzer
from ephemeral_scope.analysis.test_mapper import TestMapper
from ephemeral_scope.analysis.usage_change_matcher import UsageChangeMatcher
from ephemeral_scope.domain.models import (
    AffectedUsage,
    AnalysisRequest,
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
        """
        manifest = self.load_project(request.project_path)
        manifest = replace(
            manifest,
            dependencies=tuple(self.dependency_parser.parse(manifest)),
        )
        declared = self._declared_dependency(manifest, request.package_name)
        usages = self.usage_analyzer.analyze(manifest, request.package_name)
        api_changes = self.compare_versions(request)
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
        classified = self._score_relevance(
            classified, usages, affected_changes, upgrade
        )
        references = self.test_mapper.map(manifest, [item.usage for item in affected])

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
        manifest = self.load_project(request.project_path)
        usages = self.usage_analyzer.analyze(manifest, request.package_name)
        changes = self.compare_versions(request)
        return self.matcher.match(usages, changes)

    def load_project(self, project_path: Path) -> ProjectManifest:
        """Accept either a directory or a ZIP archive."""
        path = Path(project_path)
        if path.is_file() and path.suffix == ".zip":
            return self.project_loader.load_zip(path)
        return self.project_loader.load_directory(path)

    def compare_versions(self, request: AnalysisRequest) -> list[ApiChange]:
        old = self.snapshot_builder.build(
            request.package_name, request.current_version
        )
        new = self.snapshot_builder.build(request.package_name, request.target_version)
        return self.comparator.compare(old, new)

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
