"""PyPI metadata retrieval."""

from __future__ import annotations

import json
import shutil
import ssl
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from functools import cache
from pathlib import Path

import certifi

PYPI_BASE_URL = "https://pypi.org/pypi"


@cache
def _ssl_context() -> ssl.SSLContext:
    """Trust certifi's CA bundle needed for macOS"""
    return ssl.create_default_context(cafile=certifi.where())


class PyPIError(RuntimeError):
    """Raised when package metadata or artifacts cannot be retrieved"""


class PyPIClient:
    """Retrieves package metadata and the selected version artifacts"""

    def __init__(
        self,
        base_url: str = PYPI_BASE_URL,
        cache_dir: Path | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.cache_dir = Path(cache_dir) if cache_dir else None
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
        """Download and extract a release, returning the directory holding its code"""
        if self.cache_dir is not None:
            cached = self.cache_dir / f"{package_name}-{version}"
            if cached.is_dir():
                return cached

        metadata = self.fetch_metadata(package_name, version)
        artifact = _select_artifact(metadata.get("urls", []))
        if artifact is None:
            raise PyPIError(f"No usable artifact for {package_name}=={version}")

        if self.cache_dir is not None:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            target = self.cache_dir / f"{package_name}-{version}"
        else:
            target = Path(tempfile.mkdtemp(prefix="ephemeral_scope_pkg_"))
        target.mkdir(parents=True, exist_ok=True)

        filename = artifact["filename"]
        download_dir = Path(tempfile.mkdtemp(prefix="ephemeral_scope_dl_"))
        archive = download_dir / filename
        try:
            try:
                with urllib.request.urlopen(
                    artifact["url"], timeout=self.timeout, context=_ssl_context()
                ) as response, archive.open("wb") as handle:
                    shutil.copyfileobj(response, handle)
            except urllib.error.URLError as exc:
                raise PyPIError(f"Could not download {filename}: {exc}") from exc

            _extract(archive, target)
        finally:
            shutil.rmtree(download_dir, ignore_errors=True)

        # Source distributions nest everything under `<name>-<version>/`
        entries = [p for p in target.iterdir() if p.is_dir()]
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
    if resolved != target and not str(resolved).startswith(str(target) + "/"):
        raise PyPIError(f"Archive entry would escape target directory: {member}")
