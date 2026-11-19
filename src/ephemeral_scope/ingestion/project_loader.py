"""Project ingestion – directory and ZIP loading."""

from __future__ import annotations

import zipfile
from pathlib import Path

from ephemeral_scope.domain.models import ProjectManifest

_IGNORE_DIRS = {".venv", ".git", "__pycache__", "build"}

#: Bounds for an uploaded archive. The traversal check stops a ZIP from
#: writing outside its directory; these stop it from filling the disk.
#: A declared size is not trusted on its own: extraction counts the bytes
#: actually written, because a header can understate them.
DEFAULT_MAX_ZIP_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_EXTRACTED_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_FILES = 2_000
DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024
_READ_CHUNK = 1024 * 1024


class ProjectLoader:
    """Validates and extracts a project discovers Python and test files.

    The loader never creates a directory of its own. A ZIP is extracted into
    a directory the caller supplies and is responsible for deleting, so a
    request cannot leave an upload behind after the analysis finishes.
    """

    def __init__(
        self,
        max_zip_bytes: int = DEFAULT_MAX_ZIP_BYTES,
        max_extracted_bytes: int = DEFAULT_MAX_EXTRACTED_BYTES,
        max_files: int = DEFAULT_MAX_FILES,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    ) -> None:
        self.max_zip_bytes = max_zip_bytes
        self.max_extracted_bytes = max_extracted_bytes
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes

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

    def load_zip(self, archive: Path, destination: Path) -> ProjectManifest:
        """Extract ``archive`` into ``destination`` and load that tree.

        ``destination`` belongs to the caller. This method does not create a
        temporary directory and does not delete one.
        """
        return self.load_directory(self.extract_zip(archive, destination))

    def extract_zip(self, archive: Path, destination: Path) -> Path:
        """Extract ``archive`` into ``destination`` and return the project root.

        A single top-level directory is treated as the root, matching the way
        GitHub and most tools wrap a project. Extraction stops when the
        archive, any member, or the running total exceeds its limit.
        """
        archive = Path(archive).resolve()
        if not archive.is_file():
            raise FileNotFoundError(f"Archive does not exist: {archive}")
        if archive.stat().st_size > self.max_zip_bytes:
            raise ValueError(
                f"ZIP is {archive.stat().st_size} bytes; "
                f"the limit is {self.max_zip_bytes}"
            )

        destination = Path(destination).resolve()
        destination.mkdir(parents=True, exist_ok=True)
        self._extract_bounded(archive, destination)

        top_entries = list(destination.iterdir())
        if len(top_entries) == 1 and top_entries[0].is_dir():
            return top_entries[0]
        return destination

    def _extract_bounded(self, archive: Path, destination: Path) -> None:
        total = 0
        files = 0
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                target = _contained(destination, info.filename)
                # The header is a hint. A bomb can understate file_size, so
                # the bytes written are what count.
                if info.file_size > self.max_file_bytes:
                    raise ValueError(
                        f"{info.filename} declares {info.file_size} bytes; "
                        f"the limit per file is {self.max_file_bytes}"
                    )
                files += 1
                if files > self.max_files:
                    raise ValueError(
                        f"ZIP contains more than {self.max_files} files"
                    )

                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with zf.open(info) as source, target.open("wb") as handle:
                    while chunk := source.read(_READ_CHUNK):
                        written += len(chunk)
                        if written > self.max_file_bytes:
                            raise ValueError(
                                f"{info.filename} exceeds the per-file limit "
                                f"of {self.max_file_bytes} bytes"
                            )
                        handle.write(chunk)
                total += written
                if total > self.max_extracted_bytes:
                    raise ValueError(
                        f"ZIP expands past the {self.max_extracted_bytes} byte limit"
                    )


def _contained(destination: Path, member: str) -> Path:
    """The path ``member`` would be written to, or an error if it escapes."""
    # Absolute names and Windows drive paths are entries, not locations.
    name = member.replace("\\", "/")
    if name.startswith("/") or (len(name) >= 2 and name[1] == ":"):
        raise ValueError(f"Zip entry would escape target directory: {member}")
    resolved = (destination / name).resolve()
    if not resolved.is_relative_to(destination):
        raise ValueError(f"Zip entry would escape target directory: {member}")
    return resolved


def _is_test_file(path: Path) -> bool:
    """a file is a test if its name or parent directory suggests so."""
    name = path.name
    parts = path.parts
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    if "tests" in parts or "test" in parts:
        return True
    return False
