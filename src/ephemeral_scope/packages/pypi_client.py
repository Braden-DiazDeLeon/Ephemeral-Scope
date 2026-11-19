"""PyPI metadata retrieval."""

from __future__ import annotations

import json
import shutil
import tarfile
import tempfile
import threading
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from ephemeral_scope.http_cache import ssl_context as _ssl_context

PYPI_BASE_URL = "https://pypi.org/pypi"

#: Extracted releases live here and are reused. A missing cache used to fall
#: back to mkdtemp, which nothing ever deleted.
DEFAULT_PACKAGE_CACHE = Path(".cache") / "packages"

#: One lock per cache directory and version, so two requests in this process
#: cannot extract the same release into the same directory. Separate worker
#: processes do not share the lock.
_version_locks: dict[str, threading.Lock] = {}
_version_locks_guard = threading.Lock()


class PyPIError(RuntimeError):
    """Raised when package metadata or artifacts cannot be retrieved"""


class PyPIClient:
    """Retrieves package metadata and the selected version artifacts"""

    def __init__(
        self,
        base_url: str = PYPI_BASE_URL,
        cache_dir: Path | None = DEFAULT_PACKAGE_CACHE,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.cache_dir = Path(cache_dir) if cache_dir is not None else DEFAULT_PACKAGE_CACHE
        self.timeout = timeout

    def fetch_metadata(self, package_name: str, version: str) -> dict:
        """Return the PyPI JSON metadata document for one release"""
        url = f"{self.base_url}/{package_name}/{version}/json"
        try:
            with urllib.request.urlopen(
                url, timeout=self.timeout, context=_ssl_context()
            ) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            raise PyPIError(
                f"Could not fetch metadata for {package_name}=={version}: {exc}"
            ) from exc

    def download_source(self, package_name: str, version: str) -> Path:
        """Download and extract a release, returning the directory holding its code.

        The extracted tree is kept at ``.cache/packages/{package}-{version}/``
        and reused. The downloaded archive itself is removed once extracted.
        A failed extract removes the partial tree so the next call tries again
        instead of treating an empty directory as a cached release.

        Requests for the same version share a lock. The cache is checked
        again after the lock is acquired, so the second request waits and
        then reuses the tree the first one wrote.
        """
        key = _cache_key(package_name, version)
        target = self.cache_dir / key
        cached = _source_root(target, package_name, version)
        if cached is not None:
            return cached

        with _version_lock(self.cache_dir, key):
            cached = _source_root(target, package_name, version)
            if cached is not None:
                return cached
            self._download_into(package_name, version, target)

        cached = _source_root(target, package_name, version)
        if cached is None:
            raise PyPIError(f"Extracted {package_name}=={version} produced no files")
        return cached

    def _download_into(self, package_name: str, version: str, target: Path) -> None:
        """Download and extract one release into ``target``.

        Extraction happens in a private directory and is moved into place
        only after it succeeds, so a reader never opens a half-written tree
        and a failure does not leave an empty directory that looks cached.
        """
        metadata = self.fetch_metadata(package_name, version)
        artifact = _select_artifact(metadata.get("urls", []))
        if artifact is None:
            raise PyPIError(f"No usable artifact for {package_name}=={version}")

        filename = artifact["filename"]
        staging = Path(tempfile.mkdtemp(prefix="ephemeral-scope-download-"))
        try:
            archive = staging / filename
            try:
                with urllib.request.urlopen(
                    artifact["url"], timeout=self.timeout, context=_ssl_context()
                ) as response, archive.open("wb") as handle:
                    shutil.copyfileobj(response, handle)
            except urllib.error.URLError as exc:
                raise PyPIError(f"Could not download {filename}: {exc}") from exc

            extracted = staging / "tree"
            extracted.mkdir()
            _extract(archive, extracted)
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            if target.exists():
                shutil.rmtree(target)
            shutil.move(extracted, target)
        finally:
            shutil.rmtree(staging, ignore_errors=True)


def _version_lock(cache_dir: Path, key: str) -> threading.Lock:
    """The lock for one cached release, shared by every client of that cache."""
    name = f"{cache_dir.expanduser().resolve()}:{key}"
    with _version_locks_guard:
        return _version_locks.setdefault(name, threading.Lock())


def _cache_key(package_name: str, version: str) -> str:
    """A single path component, so the cache cannot be pointed outside itself."""
    key = f"{package_name}-{version}"
    if "/" in key or "\\" in key or ".." in key or not key.strip("."):
        raise PyPIError(f"Refusing cache path for {package_name}=={version}")
    return key


def _source_root(target: Path, package_name: str, version: str) -> Path | None:
    """The directory that holds the package, or None when nothing is cached.

    Source distributions unpack into ``{name}-{version}/`` inside the cache
    directory. A cache hit has to apply the same rule as a fresh extract, or
    the second lookup returns the outer directory and the snapshot misses
    the package.
    """
    if not target.is_dir() or not any(target.iterdir()):
        return None
    entries = [entry for entry in target.iterdir() if entry.is_dir()]
    if len(entries) == 1 and entries[0].name == f"{package_name}-{version}":
        return entries[0]
    return target


def _select_artifact(urls: list[dict]) -> dict | None:
    for packagetype in ("bdist_wheel", "sdist"):
        for entry in urls:
            if entry.get("packagetype") == packagetype:
                return entry
    return urls[0] if urls else None


def _extract(archive: Path, target: Path) -> None:
    """Extract an archive refusing entries that escape the target directory"""
    target = target.resolve()

    if archive.suffix in {".whl", ".zip"}:
        with zipfile.ZipFile(archive) as zf:
            for member in zf.namelist():
                _ensure_contained(target, member)
            zf.extractall(target)
        return

    with tarfile.open(archive) as tf:
        for member in tf.getmembers():
            _ensure_contained(target, member.name)
        tf.extractall(target, filter="data")


def _ensure_contained(target: Path, member: str) -> None:
    resolved = (target / member).resolve()
    # Component-wise, so the check holds on Windows too, where a string
    # comparison against "/" would reject every entry.
    if not resolved.is_relative_to(target):
        raise PyPIError(f"Archive entry would escape target directory: {member}")
