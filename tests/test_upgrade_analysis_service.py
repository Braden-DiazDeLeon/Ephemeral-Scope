"""Tests for UpgradeAnalysisService wiring (no network)."""

from pathlib import Path
from unittest.mock import patch

import pytest

from ephemeral_scope.domain.enums import ApiSymbolKind, ChangeType
from ephemeral_scope.domain.models import (
    AnalysisRequest,
    ApiSnapshot,
    ApiSymbol,
    DependencyUpgrade,
    EvidenceBundle,
    ReleaseNoteItem,
    RiskAssessment,
    VulnerabilityRecord,
)
from ephemeral_scope.inference.fact_builder import FactBase
from ephemeral_scope.inference.prolog_risk_engine import InferenceResult
from ephemeral_scope.main import create_service, model_path
from ephemeral_scope.ml.relevance_matcher import RelevanceMatcher
from ephemeral_scope.services.upgrade_analysis_service import UpgradeAnalysisService

APPEND = ApiSymbol(
    qualified_name="pandas.core.frame.DataFrame.append",
    symbol_kind=ApiSymbolKind.METHOD,
    signature="append(self, other, ignore_index=False)",
)
DATAFRAME = ApiSymbol(
    qualified_name="pandas.core.frame.DataFrame",
    symbol_kind=ApiSymbolKind.CLASS,
)


class FakeSnapshotBuilder:
    """Serves canned snapshots so the pipeline never touches PyPI."""

    def __init__(self, by_version: dict[str, tuple[ApiSymbol, ...]]) -> None:
        self.by_version = by_version
        self.calls: list[tuple[str, str]] = []

    def build(self, package_name: str, version: str) -> ApiSnapshot:
        self.calls.append((package_name, version))
        return ApiSnapshot(
            package_name=package_name,
            version=version,
            symbols=self.by_version[version],
        )


@pytest.fixture()
def project(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "report.py").write_text(
        'import pandas as pd\n'
        "\n"
        'df = pd.DataFrame({"a": [1]})\n'
        'df.append({"a": 2})\n'
    )
    (tmp_path / "requirements.txt").write_text("pandas==1.5.3\n")
    return tmp_path


@pytest.fixture()
def service() -> UpgradeAnalysisService:
    return UpgradeAnalysisService(
        snapshot_builder=FakeSnapshotBuilder(
            {"1.5.3": (DATAFRAME, APPEND), "2.0.0": (DATAFRAME,)}
        )
    )


def request_for(project: Path) -> AnalysisRequest:
    return AnalysisRequest(
        project_path=project,
        package_name="pandas",
        current_version="1.5.3",
        target_version="2.0.0",
    )


def test_reports_the_removed_method(service, project):
    affected = service.find_affected_usages(request_for(project))
    assert [a.to_dict(project.resolve()) for a in affected] == [
        {
            "file": "src/report.py",
            "line": 4,
            "symbol": "pandas.DataFrame.append",
            "change": "removed",
        }
    ]


def test_class_reference_alone_is_not_affected(service, project):
    """Line 3 references DataFrame, which still exists in 2.0.0."""
    affected = service.find_affected_usages(request_for(project))
    assert all(a.usage.line != 3 for a in affected)


def test_builds_both_versions(service, project):
    service.find_affected_usages(request_for(project))
    assert service.snapshot_builder.calls == [("pandas", "1.5.3"), ("pandas", "2.0.0")]


def test_project_without_usages_is_clean(service, tmp_path: Path):
    (tmp_path / "main.py").write_text("x = 1\n")
    request = AnalysisRequest(
        project_path=tmp_path,
        package_name="pandas",
        current_version="1.5.3",
        target_version="2.0.0",
    )
    assert service.find_affected_usages(request) == []


def test_accepts_a_zip_archive(service, project, tmp_path: Path):
    import zipfile

    archive = tmp_path / "proj.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for file in project.rglob("*"):
            if file.is_file() and file != archive:
                zf.write(file, file.relative_to(project))

    request = AnalysisRequest(
        project_path=archive,
        package_name="pandas",
        current_version="1.5.3",
        target_version="2.0.0",
    )
    affected = service.find_affected_usages(request)
    assert [a.usage.symbol for a in affected] == ["pandas.DataFrame.append"]
    # The upload directory is gone once the analysis returns. This path is
    # still absolute because find_affected_usages does not build a report.
    assert not affected[0].usage.file.exists()


def test_a_zip_report_uses_project_relative_paths(tmp_path: Path):
    """The deleted extraction directory must not appear in the report."""
    import zipfile

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    project = _full_project(project_dir)
    archive = tmp_path / "project.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        for file in project.rglob("*"):
            if file.is_file():
                zipped.write(file, file.relative_to(project))

    service = UpgradeAnalysisService(
        snapshot_builder=FakeSnapshotBuilder(
            {"1.5.3": (DATAFRAME, APPEND), "2.0.0": (DATAFRAME,)}
        ),
        evidence_collector=FakeEvidenceCollector(EvidenceBundle()),
    )
    report = service.analyze(
        AnalysisRequest(
            project_path=archive,
            package_name="pandas",
            current_version="1.5.3",
            target_version="2.0.0",
        )
    )

    assert report.affected_usages[0].usage.file == Path("src/report.py")
    assert report.recommended_tests == ("tests/test_report.py",)
    assert all(
        "ephemeral-scope-upload-" not in action for action in report.migration_actions
    )
    assert report.declared_dependency is not None
    assert report.declared_dependency.source_file == Path("requirements.txt")
    assert all(
        finding.file is None or "ephemeral-scope-upload-" not in finding.file.as_posix()
        for finding in report.findings
    )
    assert not report.affected_usages[0].usage.file.exists()


class FakeEvidenceCollector:
    """Canned release notes and advisories. Never opens a socket."""

    def __init__(self, bundle: EvidenceBundle) -> None:
        self.bundle = bundle
        self.calls: list[DependencyUpgrade] = []

    def collect(self, upgrade: DependencyUpgrade) -> EvidenceBundle:
        self.calls.append(upgrade)
        return self.bundle


class RecordingEngine:
    """Stands in for Prolog so the test proves what the service hands over."""

    def __init__(self) -> None:
        self.fact_bases: list[FactBase] = []

    def infer(self, facts: FactBase) -> InferenceResult:
        self.fact_bases.append(facts)
        return InferenceResult(assessment=RiskAssessment())


def _full_project(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "report.py").write_text(
        "import pandas as pd\n"
        "\n"
        'df = pd.DataFrame({"a": [1]})\n'
        'df.append({"a": 2})\n'
    )
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_report.py").write_text("import report\n\ndef test_append():\n    pass\n")
    (tmp_path / "requirements.txt").write_text("pandas==1.5.3\n")
    return tmp_path


def test_analyze_returns_a_complete_report_without_network(tmp_path: Path):
    """The acceptance criterion: one request in, one report out.

    Snapshots stand in for package installation and the evidence collector
    stands in for GitHub and OSV, so nothing here can reach the network.
    """
    evidence = FakeEvidenceCollector(
        EvidenceBundle(
            release_notes=(
                ReleaseNoteItem(
                    text=(
                        "Removed the method `DataFrame.append`; "
                        "use `pandas.concat` instead."
                    ),
                    release_version="2.0.0",
                ),
            ),
            current_vulnerabilities=(
                VulnerabilityRecord(
                    vulnerability_id="GHSA-9wx4-h78v-vm56", summary="x"
                ),
            ),
        )
    )
    service = UpgradeAnalysisService(
        snapshot_builder=FakeSnapshotBuilder(
            {"1.5.3": (DATAFRAME, APPEND), "2.0.0": (DATAFRAME,)}
        ),
        evidence_collector=evidence,
    )

    report = service.analyze(
        AnalysisRequest(
            project_path=_full_project(tmp_path),
            package_name="pandas",
            current_version="1.5.3",
            target_version="2.0.0",
        )
    )

    assert evidence.calls == [report.upgrade]
    assert report.overall_risk.value == "high"
    assert report.assessment.upgrade_urgency.value == "high"
    assert [a.usage.symbol for a in report.affected_usages] == [
        "pandas.DataFrame.append"
    ]
    assert report.classified_changes[0].category.value == "breaking_change"
    assert report.classified_changes[0].relevance_score >= 0.5
    assert [v.vulnerability_id for v in report.fixed_vulnerabilities] == [
        "GHSA-9wx4-h78v-vm56"
    ]
    assert any(f.rule_name == "removed_used_api" for f in report.findings)
    assert "Replace pandas.DataFrame.append with pandas.concat." in (
        report.migration_actions
    )
    assert (
        "Upgrade to pandas 2.0.0 to address GHSA-9wx4-h78v-vm56."
        in report.migration_actions
    )
    assert any(
        "test_report.py" in action and "src/report.py" in action
        for action in report.migration_actions
    )


def test_a_missing_prolog_still_returns_the_report(tmp_path: Path):
    service = UpgradeAnalysisService(
        snapshot_builder=FakeSnapshotBuilder(
            {"1.5.3": (DATAFRAME, APPEND), "2.0.0": (DATAFRAME,)}
        ),
        evidence_collector=FakeEvidenceCollector(EvidenceBundle()),
    )

    with patch("shutil.which", return_value=None):
        report = service.analyze(
            AnalysisRequest(
                project_path=_full_project(tmp_path),
                package_name="pandas",
                current_version="1.5.3",
                target_version="2.0.0",
            )
        )

    assert report.inference_engine == "python"
    assert report.overall_risk.value == "high"
    assert report.overall_risk == report.assessment.migration_risk
    assert any(warning.component == "prolog" for warning in report.warnings)
    assert any(f.rule_name == "removed_used_api" for f in report.findings)


def test_the_engine_receives_facts_for_this_analysis_only(tmp_path: Path):
    engine = RecordingEngine()
    service = UpgradeAnalysisService(
        snapshot_builder=FakeSnapshotBuilder(
            {"1.5.3": (DATAFRAME, APPEND), "2.0.0": (DATAFRAME,)}
        ),
        evidence_collector=FakeEvidenceCollector(EvidenceBundle()),
        risk_engine=engine,
    )
    request = AnalysisRequest(
        project_path=_full_project(tmp_path),
        package_name="pandas",
        current_version="1.5.3",
        target_version="2.0.0",
    )

    service.analyze(request)
    service.analyze(request)

    assert len(engine.fact_bases) == 2
    first, second = engine.fact_bases
    assert any("affected_usage" in clause for clause in first.facts)
    # A fresh builder each time: the second run has the same facts once,
    # not twice.
    assert first.facts == second.facts
    assert first is not second


DISAGREEMENT = (
    "This release contains bug fixes and performance improvements."
)


def test_default_model_path_exists(monkeypatch):
    """The no-override path is the repository file, not the working directory."""
    monkeypatch.delenv("EPHEMERAL_SCOPE_MODEL_PATH", raising=False)

    assert model_path().is_file()


def test_default_application_configuration_uses_the_model(tmp_path, monkeypatch):
    """The factory loads the verified model; a bare service does not.

    The sentence is one the keyword rules call a bug fix and the saved
    model calls irrelevant, so a disagreement only appears when the model
    actually ran.
    """
    model = (
        Path(__file__).resolve().parents[1]
        / "models"
        / "release_note_classifier.joblib"
    )
    monkeypatch.setenv("EPHEMERAL_SCOPE_MODEL_PATH", str(model))
    service = create_service()
    service.snapshot_builder = FakeSnapshotBuilder(
        {"1.5.3": (DATAFRAME, APPEND), "2.0.0": (DATAFRAME,)}
    )
    service.evidence_collector = FakeEvidenceCollector(
        EvidenceBundle(
            release_notes=(
                ReleaseNoteItem(text=DISAGREEMENT, release_version="2.0.0"),
            )
        )
    )

    assert service.release_note_classifier.model is not None
    assert UpgradeAnalysisService().release_note_classifier.model is None

    report = service.analyze(
        AnalysisRequest(
            project_path=_full_project(tmp_path),
            package_name="pandas",
            current_version="1.5.3",
            target_version="2.0.0",
        )
    )

    decision = report.classifier_disagreements[0].decision
    assert decision.model_category is not None
    assert decision.rule_category.value == "bug_fix"
    assert decision.model_category.value == "irrelevant"


GET = ApiSymbol(
    qualified_name="requests.api.get",
    symbol_kind=ApiSymbolKind.FUNCTION,
    signature="get(url, params=None, **kwargs)",
)
SEND = ApiSymbol(
    qualified_name="requests.sessions.Session.send",
    symbol_kind=ApiSymbolKind.METHOD,
    signature="send(self, request, **kwargs)",
)
UNUSED_NOTE = "Removed Session.send"


def test_unused_changed_api_is_not_project_relevant(tmp_path: Path):
    """A note about a removed API the project never calls stays irrelevant.

    Indexing every API change would score this 0.7, because Session.send
    changed, and 0.7 clears the threshold for a medium-risk finding.
    """
    root = tmp_path / "proj"
    root.mkdir()
    (root / "client.py").write_text(
        "import requests\nrequests.get('https://example.com')\n"
    )
    (root / "requirements.txt").write_text("requests==2.28.0\n")
    service = UpgradeAnalysisService(
        snapshot_builder=FakeSnapshotBuilder(
            {"2.28.0": (GET, SEND), "2.32.0": (GET,)}
        ),
        evidence_collector=FakeEvidenceCollector(
            EvidenceBundle(
                release_notes=(
                    ReleaseNoteItem(text=UNUSED_NOTE, release_version="2.32.0"),
                )
            )
        ),
    )

    report = service.analyze(
        AnalysisRequest(
            project_path=root,
            package_name="requests",
            current_version="2.28.0",
            target_version="2.32.0",
        )
    )

    note = report.classified_changes[0]
    indexed_everything = RelevanceMatcher(
        report.usages, report.api_changes, "requests"
    ).score(UNUSED_NOTE)

    assert any(change.change_type is ChangeType.REMOVED for change in report.api_changes)
    assert indexed_everything.score >= 0.7
    assert note.relevance_score < 0.5
    assert all(f.rule_name != "relevant_breaking_note" for f in report.findings)


def test_report_records_the_declared_dependency(tmp_path: Path):
    root = _full_project(tmp_path)
    # Different capitalisation from the request: matching is canonical.
    (root / "requirements.txt").write_text("Pandas==1.5.3\n")
    service = UpgradeAnalysisService(
        snapshot_builder=FakeSnapshotBuilder(
            {"1.5.3": (DATAFRAME, APPEND), "2.0.0": (DATAFRAME,)}
        ),
        evidence_collector=FakeEvidenceCollector(EvidenceBundle()),
    )

    report = service.analyze(
        AnalysisRequest(
            project_path=root,
            package_name="pandas",
            current_version="1.5.3",
            target_version="2.0.0",
        )
    )

    declared = report.declared_dependency
    assert declared is not None
    assert declared.name == "Pandas"
    assert declared.specifier == "==1.5.3"
    assert declared.source_file.name == "requirements.txt"


def test_an_undeclared_package_warns_but_is_still_analyzed(tmp_path, caplog):
    root = _full_project(tmp_path)
    (root / "requirements.txt").write_text("flask==2.0.0\n")
    service = UpgradeAnalysisService(
        snapshot_builder=FakeSnapshotBuilder(
            {"1.5.3": (DATAFRAME, APPEND), "2.0.0": (DATAFRAME,)}
        ),
        evidence_collector=FakeEvidenceCollector(EvidenceBundle()),
    )

    with caplog.at_level("WARNING"):
        report = service.analyze(
            AnalysisRequest(
                project_path=root,
                package_name="pandas",
                current_version="1.5.3",
                target_version="2.0.0",
            )
        )

    assert report.declared_dependency is None
    assert "not declared" in caplog.text
    assert any(f.rule_name == "removed_used_api" for f in report.findings)


def test_overall_risk_matches_migration_risk(tmp_path: Path):
    service = UpgradeAnalysisService(
        snapshot_builder=FakeSnapshotBuilder(
            {"1.5.3": (DATAFRAME, APPEND), "2.0.0": (DATAFRAME,)}
        ),
        evidence_collector=FakeEvidenceCollector(EvidenceBundle()),
    )
    report = service.analyze(
        AnalysisRequest(
            project_path=_full_project(tmp_path),
            package_name="pandas",
            current_version="1.5.3",
            target_version="2.0.0",
        )
    )

    assert report.overall_risk == report.assessment.migration_risk
    assert report.overall_risk.value == "high"


def test_an_unchanged_api_is_low_risk(tmp_path: Path):
    """A comparison that ran and found nothing is not an unknown risk."""
    root = tmp_path / "proj"
    root.mkdir()
    (root / "client.py").write_text("import pandas as pd\npd.DataFrame()\n")
    (root / "requirements.txt").write_text("pandas==1.5.3\n")
    service = UpgradeAnalysisService(
        snapshot_builder=FakeSnapshotBuilder(
            {"1.5.3": (DATAFRAME,), "2.0.0": (DATAFRAME,)}
        ),
        evidence_collector=FakeEvidenceCollector(EvidenceBundle()),
    )

    report = service.analyze(
        AnalysisRequest(
            project_path=root,
            package_name="pandas",
            current_version="1.5.3",
            target_version="2.0.0",
        )
    )

    assert not any(warning.component == "api_snapshot" for warning in report.warnings)
    assert report.overall_risk.value == "low"
    assert report.assessment.migration_risk.value == "low"


def test_an_incomplete_snapshot_is_a_warning_not_a_removal(tmp_path: Path):
    service = UpgradeAnalysisService(
        snapshot_builder=FakeSnapshotBuilder({"1.5.3": (), "2.0.0": (DATAFRAME,)}),
        evidence_collector=FakeEvidenceCollector(EvidenceBundle()),
    )

    report = service.analyze(
        AnalysisRequest(
            project_path=_full_project(tmp_path),
            package_name="pandas",
            current_version="1.5.3",
            target_version="2.0.0",
        )
    )

    assert any(warning.component == "api_snapshot" for warning in report.warnings)
    assert all(f.rule_name != "removed_used_api" for f in report.findings)
    assert report.overall_risk.value == "unknown"
    assert report.assessment.migration_risk.value == "unknown"


def test_an_unparseable_source_file_is_reported(tmp_path: Path):
    root = _full_project(tmp_path)
    (root / "src" / "broken.py").write_text("def (\n")
    service = UpgradeAnalysisService(
        snapshot_builder=FakeSnapshotBuilder(
            {"1.5.3": (DATAFRAME, APPEND), "2.0.0": (DATAFRAME,)}
        ),
        evidence_collector=FakeEvidenceCollector(EvidenceBundle()),
    )

    report = service.analyze(
        AnalysisRequest(
            project_path=root,
            package_name="pandas",
            current_version="1.5.3",
            target_version="2.0.0",
        )
    )

    assert any(
        warning.component == "parser" and warning.message.startswith(
            "Source file could not be parsed: src/broken.py"
        )
        for warning in report.warnings
    )
    assert all(str(root) not in warning.message for warning in report.warnings)
    assert any(f.rule_name == "removed_used_api" for f in report.findings)


def test_a_missing_model_file_is_a_warning(tmp_path: Path):
    from ephemeral_scope.ml.release_note_classifier import ReleaseNoteClassifier

    service = UpgradeAnalysisService(
        snapshot_builder=FakeSnapshotBuilder(
            {"1.5.3": (DATAFRAME,), "2.0.0": (DATAFRAME,)}
        ),
        evidence_collector=FakeEvidenceCollector(EvidenceBundle()),
        release_note_classifier=ReleaseNoteClassifier(
            model_path=tmp_path / "missing.joblib"
        ),
    )

    report = service.analyze(
        AnalysisRequest(
            project_path=_full_project(tmp_path),
            package_name="pandas",
            current_version="1.5.3",
            target_version="2.0.0",
        )
    )

    assert any(
        warning.message.startswith("TF-IDF model unavailable")
        for warning in report.warnings
    )
