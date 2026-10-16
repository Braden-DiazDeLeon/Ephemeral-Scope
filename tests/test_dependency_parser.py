"""Tests for DependencyParser – pyproject.toml and requirements.txt."""

from pathlib import Path

import pytest

from ephemeral_scope.ingestion.dependency_parser import DependencyParser
from ephemeral_scope.ingestion.project_loader import ProjectLoader


@pytest.fixture()
def fixture_project(tmp_path: Path) -> Path:
    """Fixture project with both dependency file formats."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("import pandas\n")

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\n'
        'dependencies = [\n'
        '    "pandas>=1.5,<2.0",\n'
        '    "requests==2.31.0"\n'
        "]\n"
    )
    (tmp_path / "requirements.txt").write_text(
        "pandas==1.5.3\nrequests>=2.31.0\nnumpy\n"
    )
    return tmp_path


def test_parses_pyproject_and_requirements(fixture_project: Path):
    manifest = ProjectLoader().load_directory(fixture_project)
    deps = DependencyParser().parse(manifest)
    names = {d.name.lower() for d in deps}
    assert "pandas" in names
    assert "requests" in names


def test_pandas_specifier_from_pyproject(fixture_project: Path):
    manifest = ProjectLoader().load_directory(fixture_project)
    deps = DependencyParser().parse(manifest)
    pandas_dep = next(d for d in deps if d.name.lower() == "pandas")
    assert "1.5" in (pandas_dep.specifier or "")


def test_deduplication(fixture_project: Path):
    """Same package in both files should appear once (first source wins)."""
    manifest = ProjectLoader().load_directory(fixture_project)
    deps = DependencyParser().parse(manifest)
    pandas_count = sum(1 for d in deps if d.name.lower() == "pandas")
    assert pandas_count == 1


def test_numpy_from_requirements(fixture_project: Path):
    manifest = ProjectLoader().load_directory(fixture_project)
    deps = DependencyParser().parse(manifest)
    numpy_dep = next((d for d in deps if d.name.lower() == "numpy"), None)
    assert numpy_dep is not None
    assert numpy_dep.specifier is None
