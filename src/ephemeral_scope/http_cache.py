"""Cached JSON over HTTP, shared by the evidence providers.

Responses are written to disk so repeated runs and the test suite do not
depend on network availability or on third-party rate limits.
"""

from __future__ import annotations

import hashlib
import json
import logging
import ssl
import urllib.error
import urllib.request
from functools import cache
from pathlib import Path
from typing import Any

import certifi

logger = logging.getLogger(__name__)

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "ephemeral-scope" / "http"


@cache
def ssl_context() -> ssl.SSLContext:
    """Trust certifi's CA bundle.

    Python installed from python.org on macOS ships without a usable system
    bundle, so the default context fails every request with a verification
    error.
    """
    return ssl.create_default_context(cafile=certifi.where())


class HttpCache:
    """Fetches JSON documents, reading from and writing to a disk cache.

    Every method returns ``None`` rather than raising when a document cannot
    be retrieved. Evidence gathering is best-effort a missing changelog or an
    unreachable advisory database should degrade the report, not fail it.
    """

    def __init__(
        self,
        cache_dir: Path | None = DEFAULT_CACHE_DIR,
        timeout: float = 30.0,
        offline: bool = False,
    ) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir is not None else None
        self.timeout = timeout
        self.offline = offline

    def get_json(self, url: str, headers: dict[str, str] | None = None) -> Any | None:
        return self._fetch("GET", url, None, headers)

    def post_json(
        self, url: str, payload: Any, headers: dict[str, str] | None = None
    ) -> Any | None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        return self._fetch("POST", url, body, headers)


    def _fetch(
        self,
        method: str,
        url: str,
        body: bytes | None,
        headers: dict[str, str] | None,
    ) -> Any | None:
        path = self._cache_path(method, url, body)

        if path is not None and path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                # A truncated cache entry should not be fatal; refetch it.
                path.unlink(missing_ok=True)

        if self.offline:
            return None

        document = self._request(method, url, body, headers)
        if document is not None and path is not None:
            self._store(path, document)
        return document

    def _request(
        self,
        method: str,
        url: str,
        body: bytes | None,
        headers: dict[str, str] | None,
    ) -> Any | None:
        request = urllib.request.Request(url, data=body, method=method)
        request.add_header("Accept", "application/json")
        if body is not None:
            request.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            request.add_header(key, value)

        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout, context=ssl_context()
            ) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
            logger.warning("Evidence lookup failed for %s: %s", url, exc)
            return None

    def _cache_path(self, method: str, url: str, body: bytes | None) -> Path | None:
        if self.cache_dir is None:
            return None
        digest = hashlib.sha256()
        digest.update(method.encode("utf-8"))
        digest.update(url.encode("utf-8"))
        if body is not None:
            digest.update(body)
        return self.cache_dir / f"{digest.hexdigest()}.json"

    def _store(self, path: Path, document: Any) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Write then rename so a crash cannot leave a half-written entry.
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(document), encoding="utf-8")
            temporary.replace(path)
        except OSError as exc:
            logger.warning("Could not cache %s: %s", path, exc)
