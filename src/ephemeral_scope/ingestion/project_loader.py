"""Project ingestion – directory and ZIP loading."""

from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from ephemeral_scope.domain.models import ProjectManifest

_IGNORE_DIRS = {".venv", ".git", "__pycache__", "build"}


class ProjectLoader:
    """Validates and extracts a project discovers Python and test files."""

    def load_directory(self, path: Path) -> ProjectManifest:
        """Load a project from an existing directory"""
        path = Path(path).resolve()
        if not path.is_dir():
            raise FileNotFoundError(f"Directory does not exist: {path}")

        py_files: list[Path] = []
        for p in path.rglob("*.py"):
            if any(part in _IGNORE_DIRS for part in p.relative_to(path).parts):
                continue
            py_files.append(p)

        source_files: list[Path] = []
        test_files: list[Path] = []
        for p in py_files:
            if _is_test_file(p):
                test_files.append(p)
            else:
                source_files.append(p)

        dep_files: list[Path] = []
        for name in ("pyproject.toml", "requirements.txt"):
            candidate = path / name
            if candidate.is_file():
                dep_files.append(candidate)

        return ProjectManifest(
            root_path=path,
            source_files=tuple(sorted(source_files)),
            test_files=tuple(sorted(test_files)),
            dependency_files=tuple(sorted(dep_files)),
        )

    def load_zip(self, archive: Path) -> ProjectManifest:
        """Safely extract a ZIP to a temp directory, then load it."""
        archive = Path(archive).resolve()
        if not archive.is_file():
            raise FileNotFoundError(f"Archive does not exist: {archive}")

        tmp_dir = tempfile.mkdtemp(prefix="ephemeral_scope_")
        tmp_path = Path(tmp_dir).resolve()

        with zipfile.ZipFile(archive, "r") as zf:
            for member in zf.namelist():
                resolved = (tmp_path / member).resolve()
                if not str(resolved).startswith(str(tmp_path) + "/") and resolved != tmp_path:
                    raise ValueError(
                        f"Zip entry would escape target directory: {member}"
                    )
            zf.extractall(tmp_path)

        # If the archive contains a single top-level directory, descend into it.
        top_entries = list(tmp_path.iterdir())
        if len(top_entries) == 1 and top_entries[0].is_dir():
            return self.load_directory(top_entries[0])

        return self.load_directory(tmp_path)


def _is_test_file(path: Path) -> bool:
    """a file is a test if its name or parent directory suggests so."""
    name = path.name
    parts = path.parts
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    if "tests" in parts or "test" in parts:
        return True
    return False
