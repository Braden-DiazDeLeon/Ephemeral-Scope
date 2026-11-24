"""Uploaded projects, extracted once and analyzed as many times as needed.

Uploading and analyzing are separate steps. The browser uploads a ZIP, gets
back the dependencies it declares, and can then queue several upgrades
against the same extraction without sending the archive again.

Every extraction lives under one base directory this store owns. An entry is
removed when it expires, when the store is full, and when the app shuts down.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from ephemeral_scope.domain.models import Dependency
from ephemeral_scope.ingestion.dependency_parser import DependencyParser
from ephemeral_scope.ingestion.project_loader import (
    DEFAULT_MAX_ZIP_BYTES,
    ProjectLoader,
)

DEFAULT_TTL_SECONDS = 60 * 60
DEFAULT_MAX_PROJECTS = 50
_CHUNK = 1024 * 1024
# Finder and Explorer add these beside the real project directory. Left in
# place they stop the loader from recognising the single top-level folder.
_ARCHIVE_NOISE = {"__MACOSX", ".DS_Store", "Thumbs.db", "desktop.ini"}


class ProjectError(ValueError):
    """The upload is not a usable project archive."""


class ProjectTooLarge(ProjectError):
    """The upload is larger than the archive limit."""


@dataclass(slots=True)
class StoredProject:
    id: str
    name: str
    root: Path
    container: Path
    sha256: str
    source_files: int
    test_files: int
    dependency_files: tuple[str, ...]
    dependencies: tuple[Dependency, ...]
    warnings: tuple[str, ...] = ()
    created_at: float = field(default_factory=time.time)
    #: Analyses still reading the extraction. An entry in use is not evicted.
    in_use: int = 0


class ProjectStore:
    def __init__(
        self,
        base_dir: Path | None = None,
        loader: ProjectLoader | None = None,
        parser: DependencyParser | None = None,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        max_projects: int = DEFAULT_MAX_PROJECTS,
        max_zip_bytes: int = DEFAULT_MAX_ZIP_BYTES,
    ) -> None:
        self._owns_base = base_dir is None
        self.base_dir = (
            Path(tempfile.mkdtemp(prefix="ephemeral-scope-projects-"))
            if base_dir is None
            else Path(base_dir)
        )
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.loader = loader or ProjectLoader()
        self.parser = parser or DependencyParser()
        self.ttl_seconds = ttl_seconds
        self.max_projects = max_projects
        self.max_zip_bytes = max_zip_bytes
        self._projects: dict[str, StoredProject] = {}
        self._lock = threading.Lock()

    def add(self, stream: BinaryIO, filename: str | None) -> StoredProject:
        """Save, extract and inspect an uploaded archive. Blocking."""
        self._evict()
        project_id = uuid.uuid4().hex
        container = self.base_dir / project_id
        container.mkdir(parents=True)
        try:
            archive = container / "upload.zip"
            digest = self._save(stream, archive)
            extracted = container / "project"
            try:
                self.loader.extract_zip(archive, extracted)
            except zipfile.BadZipFile as error:
                raise ProjectError("The file is not a valid ZIP archive.") from error
            except (ValueError, OSError) as error:
                raise ProjectError(str(error)) from error
            finally:
                archive.unlink(missing_ok=True)

            root = _project_root(extracted)
            manifest = self.loader.load_directory(root)
            # The loader resolves symlinks (macOS temp dirs sit behind one),
            # so its root is the one the manifest's paths are relative to.
            root = manifest.root_path
            extracted = extracted.resolve()
            warnings: list[str] = []
            try:
                dependencies = tuple(self.parser.parse(manifest))
            except Exception as error:  # a malformed file is a warning, not a failure
                dependencies = ()
                warnings.append(f"Dependency files could not be parsed: {error}")
            if not manifest.source_files and not manifest.test_files:
                raise ProjectError("The archive contains no Python files.")
            if not manifest.dependency_files:
                warnings.append(
                    "No requirements.txt or pyproject.toml at the project root; "
                    "enter the package and versions by hand."
                )

            project = StoredProject(
                id=project_id,
                name=_display_name(filename, root, extracted),
                root=root,
                container=container,
                sha256=digest,
                source_files=len(manifest.source_files),
                test_files=len(manifest.test_files),
                dependency_files=tuple(
                    path.relative_to(root).as_posix() for path in manifest.dependency_files
                ),
                dependencies=dependencies,
                warnings=tuple(warnings),
            )
        except BaseException:
            shutil.rmtree(container, ignore_errors=True)
            raise

        with self._lock:
            self._projects[project_id] = project
        return project

    def get(self, project_id: str) -> StoredProject | None:
        with self._lock:
            project = self._projects.get(project_id)
            if project is None:
                return None
            if self._expired(project) and project.in_use == 0:
                self._remove(project_id)
                return None
            return project

    def acquire(self, project_id: str) -> StoredProject | None:
        """Like ``get``, and keeps the extraction alive until ``release``."""
        with self._lock:
            project = self._projects.get(project_id)
            if project is None:
                return None
            if self._expired(project) and project.in_use == 0:
                self._remove(project_id)
                return None
            project.in_use += 1
            return project

    def release(self, project_id: str) -> None:
        with self._lock:
            project = self._projects.get(project_id)
            if project is not None and project.in_use > 0:
                project.in_use -= 1

    def close(self) -> None:
        with self._lock:
            for project_id in list(self._projects):
                self._remove(project_id)
        if self._owns_base:
            shutil.rmtree(self.base_dir, ignore_errors=True)

    def __len__(self) -> int:
        with self._lock:
            return len(self._projects)

    def _save(self, stream: BinaryIO, archive: Path) -> str:
        digest = hashlib.sha256()
        written = 0
        with archive.open("wb") as handle:
            while chunk := stream.read(_CHUNK):
                written += len(chunk)
                if written > self.max_zip_bytes:
                    raise ProjectTooLarge(
                        f"The archive is larger than the "
                        f"{self.max_zip_bytes // (1024 * 1024)} MB limit."
                    )
                digest.update(chunk)
                handle.write(chunk)
        if written == 0:
            raise ProjectError("The uploaded file is empty.")
        return digest.hexdigest()

    def _expired(self, project: StoredProject) -> bool:
        return time.time() - project.created_at > self.ttl_seconds

    def _evict(self) -> None:
        with self._lock:
            for project_id, project in list(self._projects.items()):
                if self._expired(project) and project.in_use == 0:
                    self._remove(project_id)
            idle = sorted(
                (p for p in self._projects.values() if p.in_use == 0),
                key=lambda p: p.created_at,
            )
            while len(self._projects) >= self.max_projects and idle:
                self._remove(idle.pop(0).id)

    def _remove(self, project_id: str) -> None:
        project = self._projects.pop(project_id, None)
        if project is not None:
            shutil.rmtree(project.container, ignore_errors=True)


def _project_root(extracted: Path) -> Path:
    """Drop archive noise, then unwrap a single top-level directory."""
    for entry in list(extracted.rglob("*")):
        if entry.name in _ARCHIVE_NOISE and entry.exists():
            if entry.is_dir():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink(missing_ok=True)
    entries = list(extracted.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return extracted


def _display_name(filename: str | None, root: Path, extracted: Path) -> str:
    if root != extracted:
        return root.name[:80]
    stem = Path(filename or "").name
    if stem.lower().endswith(".zip"):
        stem = stem[:-4]
    return (stem or "project")[:80]
