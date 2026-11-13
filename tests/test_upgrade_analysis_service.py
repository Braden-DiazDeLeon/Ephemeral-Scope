"""Tests for UpgradeAnalysisService wiring (no network)."""

from pathlib import Path

import pytest

from ephemeral_scope.domain.enums import ApiSymbolKind
from ephemeral_scope.domain.models import AnalysisRequest, ApiSnapshot, ApiSymbol
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
