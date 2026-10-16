"""Tests for ProjectLoader – directory and ZIP loading."""

import zipfile
from pathlib import Path

import pytest

from ephemeral_scope.ingestion.project_loader import ProjectLoader


@pytest.fixture()
def sample_project(tmp_path: Path) -> Path:
    """Create a minimal fixture project on disk."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("import pandas\n")
    (tmp_path / "src" / "utils.py").write_text("x = 1\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("def test_one(): ...\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["pandas>=1.5"]\n'
    )
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    # directories that should be ignored
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "lib.py").write_text("")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "cached.py").write_text("")
    return tmp_path


class TestLoadDirectory:
    def test_finds_source_files(self, sample_project: Path):
        manifest = ProjectLoader().load_directory(sample_project)
        names = {p.name for p in manifest.source_files}
        assert "app.py" in names
        assert "utils.py" in names

    def test_finds_test_files(self, sample_project: Path):
        manifest = ProjectLoader().load_directory(sample_project)
        names = {p.name for p in manifest.test_files}
        assert "test_app.py" in names

    def test_ignores_venv_and_pycache(self, sample_project: Path):
        manifest = ProjectLoader().load_directory(sample_project)
        all_files = manifest.source_files + manifest.test_files
        all_parts = {part for p in all_files for part in p.parts}
        assert ".venv" not in all_parts
        assert "__pycache__" not in all_parts

    def test_finds_dependency_files(self, sample_project: Path):
        manifest = ProjectLoader().load_directory(sample_project)
        names = {p.name for p in manifest.dependency_files}
        assert "pyproject.toml" in names
        assert "requirements.txt" in names

    def test_nonexistent_directory_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            ProjectLoader().load_directory(tmp_path / "nope")


class TestLoadZip:
    def test_loads_from_zip(self, sample_project: Path, tmp_path: Path):
        zip_path = tmp_path / "project.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for file in sample_project.rglob("*"):
                if file.is_file():
                    zf.write(file, file.relative_to(sample_project))

        manifest = ProjectLoader().load_zip(zip_path)
        names = {p.name for p in manifest.source_files}
        assert "app.py" in names

    def test_zip_path_traversal_rejected(self, tmp_path: Path):
        zip_path = tmp_path / "evil.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../outside.py", "pwned = True")

        with pytest.raises(ValueError, match="escape"):
            ProjectLoader().load_zip(zip_path)
