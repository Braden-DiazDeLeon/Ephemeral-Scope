"""Released versions of a package, for the version pickers.

The analysis pipeline fetches one named version at a time. Choosing a version
needs the whole list, which is a different PyPI document, so it is read here
and kept for a few minutes.
"""

from __future__ import annotations

import json
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable

import certifi
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

PYPI_URL = "https://pypi.org/pypi/{name}/json"
DEFAULT_TTL_SECONDS = 10 * 60
DEFAULT_TIMEOUT_SECONDS = 15.0
_MAX_CACHED = 256


class PackageNotFound(LookupError):
    """PyPI has no project by that name."""


class PyPIUnavailable(RuntimeError):
    """PyPI could not be reached or answered with something unusable."""


def _fetch(name: str, timeout: float) -> dict:
    url = PYPI_URL.format(name=urllib.parse.quote(name, safe=""))
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": "ephemeral-scope"}
    )
    context = ssl.create_default_context(cafile=certifi.where())
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as reply:
            return json.load(reply)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise PackageNotFound(name) from error
        raise PyPIUnavailable(f"PyPI answered {error.code}") from error
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
        raise PyPIUnavailable(f"PyPI could not be reached: {error}") from error


class VersionLookup:
    def __init__(
        self,
        fetch: Callable[[str, float], dict] = _fetch,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._fetch = fetch
        self.ttl_seconds = ttl_seconds
        self.timeout = timeout
        self._cache: dict[str, tuple[float, dict]] = {}
        self._lock = threading.Lock()

    def versions(self, package_name: str) -> dict:
        """Newest first. Blocking; call it from a worker thread."""
        key = canonicalize_name(package_name)
        with self._lock:
            cached = self._cache.get(key)
            if cached is not None and time.time() - cached[0] < self.ttl_seconds:
                return cached[1]

        result = _summarize(key, self._fetch(key, self.timeout))
        with self._lock:
            if len(self._cache) >= _MAX_CACHED:
                self._cache.pop(next(iter(self._cache)))
            self._cache[key] = (time.time(), result)
        return result


def _summarize(name: str, document: dict) -> dict:
    releases = document.get("releases")
    if not isinstance(releases, dict):
        raise PyPIUnavailable("PyPI returned an unexpected document")

    versions: list[tuple[Version, dict]] = []
    for raw, files in releases.items():
        try:
            parsed = Version(raw)
        except InvalidVersion:
            continue
        files = [f for f in files or [] if isinstance(f, dict)]
        # A release with no files cannot be analyzed. A yanked one can, and a
        # project may well be pinned to it, so it is listed and marked.
        if not files:
            continue
        yanked = all(f.get("yanked") for f in files)
        uploaded = min(
            (f.get("upload_time_iso_8601") or "" for f in files), default=""
        )
        versions.append(
            (
                parsed,
                {
                    "version": raw,
                    "prerelease": parsed.is_prerelease or parsed.is_devrelease,
                    "yanked": yanked,
                    "released": uploaded[:10] or None,
                },
            )
        )
    versions.sort(key=lambda item: item[0], reverse=True)
    info = document.get("info") or {}
    return {
        "package_name": info.get("name") or name,
        "summary": info.get("summary"),
        "versions": [entry for _, entry in versions],
    }
