"""The web application.

Run it with::

    uvicorn ephemeral_scope.api.app:create_app --factory --port 8000

One process only. Jobs and uploads are held in memory, so several workers
would each see a different set.
"""

from __future__ import annotations

import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from ephemeral_scope.api.jobs import (
    DEFAULT_MAX_PENDING,
    DEFAULT_MAX_WORKERS,
    AnalysisService,
    JobManager,
)
from ephemeral_scope.api.projects import ProjectStore
from ephemeral_scope.api.pypi_versions import VersionLookup
from ephemeral_scope.api.router import router
from ephemeral_scope.domain.models import ApiSnapshot

#: ``npm run build`` writes here. When it exists the API serves it too, so
#: the whole app is one process on one port.
FRONTEND_DIST = Path(__file__).resolve().parents[3] / "frontend" / "dist"

_SNAPSHOT_CACHE_SIZE = 32


class CachedSnapshotBuilder:
    """Remembers API snapshots so a version is only parsed once.

    Building a snapshot means walking every module of a package, which is
    most of an analysis. Snapshots are immutable and depend only on the
    package and version, so they are safe to share between jobs. A per-key
    lock stops two jobs that start together from both doing the work.
    """

    def __init__(self, builder, max_entries: int = _SNAPSHOT_CACHE_SIZE) -> None:
        self._builder = builder
        self._max_entries = max_entries
        self._snapshots: dict[tuple[str, str], ApiSnapshot] = {}
        self._locks: dict[tuple[str, str], threading.Lock] = {}
        self._guard = threading.Lock()

    def build(self, package_name: str, version: str) -> ApiSnapshot:
        key = (package_name.lower(), version)
        with self._guard:
            cached = self._snapshots.get(key)
            if cached is not None:
                return cached
            lock = self._locks.setdefault(key, threading.Lock())
        with lock:
            with self._guard:
                cached = self._snapshots.get(key)
            if cached is not None:
                return cached
            snapshot = self._builder.build(package_name, version)
            # An empty snapshot is a failed read, not a package with no API.
            if getattr(snapshot, "symbols", ()):
                with self._guard:
                    if len(self._snapshots) >= self._max_entries:
                        self._snapshots.pop(next(iter(self._snapshots)))
                    self._snapshots[key] = snapshot
            return snapshot

    def __getattr__(self, name: str):
        return getattr(self._builder, name)


def _production_service() -> AnalysisService:
    from ephemeral_scope.main import create_service

    service = create_service()
    service.snapshot_builder = CachedSnapshotBuilder(service.snapshot_builder)
    return service


def _int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, ""))
    except ValueError:
        return default
    return value if value > 0 else default


def create_app(
    service: AnalysisService | None = None,
    *,
    projects: ProjectStore | None = None,
    versions: VersionLookup | None = None,
    max_workers: int | None = None,
    max_pending: int | None = None,
    frontend_dist: Path | None = FRONTEND_DIST,
) -> FastAPI:
    """Build the app. Tests pass a fake ``service``; production passes none."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        store = projects if projects is not None else ProjectStore()
        manager = JobManager(
            service if service is not None else _production_service(),
            store,
            max_workers=max_workers
            or _int_env("EPHEMERAL_SCOPE_WORKERS", DEFAULT_MAX_WORKERS),
            max_pending=max_pending
            or _int_env("EPHEMERAL_SCOPE_MAX_PENDING", DEFAULT_MAX_PENDING),
        )
        app.state.projects = store
        app.state.jobs = manager
        app.state.versions = versions if versions is not None else VersionLookup()
        try:
            yield
        finally:
            manager.shutdown()
            store.close()

    app = FastAPI(title="Ephemeral Scope", version="0.1.0", lifespan=lifespan)

    origins = [
        origin.strip()
        for origin in os.environ.get("EPHEMERAL_SCOPE_CORS_ORIGINS", "").split(",")
        if origin.strip()
    ]
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
        )

    app.include_router(router)

    if frontend_dist is not None and (frontend_dist / "index.html").is_file():
        _serve_frontend(app, frontend_dist)

    return app


def _serve_frontend(app: FastAPI, dist: Path) -> None:
    assets = dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    root = dist.resolve()

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not found.")
        candidate = (root / path).resolve()
        if path and candidate.is_relative_to(root) and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(root / "index.html")
