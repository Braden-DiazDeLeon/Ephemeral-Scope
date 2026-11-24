"""Background analysis jobs.

``UpgradeAnalysisService.analyze`` is a blocking call that downloads packages
and runs a subprocess, so it must not run on the event loop. Each request
becomes a job on a bounded thread pool: the POST returns at once with an id
and the browser polls for the result, which lets several analyses run side by
side.

Threads, not processes, and one manager per app. The job table is in memory
and the package cache serializes downloads with a ``threading.Lock``; a
second process would see neither.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Protocol

from packaging.utils import canonicalize_name

from ephemeral_scope.api.projects import ProjectStore, StoredProject
from ephemeral_scope.api.schemas import report_dict
from ephemeral_scope.domain.models import AnalysisRequest, UpgradeReport

logger = logging.getLogger(__name__)

DEFAULT_MAX_WORKERS = 4
DEFAULT_MAX_PENDING = 32
DEFAULT_MAX_JOBS = 200

QUEUED = "queued"
RUNNING = "running"
DONE = "done"
FAILED = "failed"


class AnalysisService(Protocol):
    def analyze(self, request: AnalysisRequest) -> UpgradeReport: ...


class QueueFull(RuntimeError):
    """Too many analyses are already waiting."""


class UnknownProject(LookupError):
    """The project id is unknown or its upload has expired."""


@dataclass(slots=True)
class Job:
    id: str
    key: tuple[str, str, str, str]
    project_id: str
    project_name: str
    package_name: str
    current_version: str
    target_version: str
    status: str = QUEUED
    created_at: float = 0.0
    started_at: float | None = None
    finished_at: float | None = None
    report: dict | None = None
    error: str | None = None

    def summary(self) -> dict:
        now = time.time()
        end = self.finished_at if self.finished_at is not None else now
        report = self.report or {}
        return {
            "id": self.id,
            "status": self.status,
            "project_id": self.project_id,
            "project_name": self.project_name,
            "package_name": self.package_name,
            "current_version": self.current_version,
            "target_version": self.target_version,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "queued_seconds": round(
                (self.started_at if self.started_at is not None else end)
                - self.created_at,
                3,
            ),
            "run_seconds": (
                None if self.started_at is None else round(end - self.started_at, 3)
            ),
            "migration_risk": report.get("migration_risk"),
            "upgrade_urgency": report.get("upgrade_urgency"),
            "error": self.error,
        }

    def detail(self) -> dict:
        return {**self.summary(), "report": self.report}


class JobManager:
    def __init__(
        self,
        service: AnalysisService,
        projects: ProjectStore,
        max_workers: int = DEFAULT_MAX_WORKERS,
        max_pending: int = DEFAULT_MAX_PENDING,
        max_jobs: int = DEFAULT_MAX_JOBS,
    ) -> None:
        self.service = service
        self.projects = projects
        self.max_workers = max_workers
        self.max_pending = max_pending
        self.max_jobs = max_jobs
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._by_key: dict[tuple[str, str, str, str], str] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="analysis"
        )

    def submit(
        self,
        project_id: str,
        package_name: str,
        current_version: str,
        target_version: str,
    ) -> tuple[Job, bool]:
        """Queue an analysis. Returns the job and whether it was reused.

        The same archive, package and versions always produce the same
        report, so a repeat request is answered with the job already queued,
        running or finished instead of doing the work twice.
        """
        project = self.projects.acquire(project_id)
        if project is None:
            raise UnknownProject(project_id)

        key = (
            project.sha256,
            canonicalize_name(package_name),
            current_version,
            target_version,
        )
        try:
            with self._lock:
                existing = self._jobs.get(self._by_key.get(key, ""))
                if existing is not None and existing.status != FAILED:
                    self.projects.release(project_id)
                    return existing, True

                pending = sum(1 for job in self._jobs.values() if job.status == QUEUED)
                if pending >= self.max_pending:
                    raise QueueFull(
                        f"{pending} analyses are already waiting; try again shortly."
                    )

                job = Job(
                    id=uuid.uuid4().hex,
                    key=key,
                    project_id=project.id,
                    project_name=project.name,
                    package_name=package_name,
                    current_version=current_version,
                    target_version=target_version,
                    created_at=time.time(),
                )
                self._jobs[job.id] = job
                self._by_key[key] = job.id
                self._trim()
            self._executor.submit(self._run, job, project)
        except BaseException:
            self.projects.release(project_id)
            raise
        return job, False

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def counts(self) -> dict[str, int]:
        with self._lock:
            counts = {QUEUED: 0, RUNNING: 0, DONE: 0, FAILED: 0}
            for job in self._jobs.values():
                counts[job.status] += 1
            return counts

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _run(self, job: Job, project: StoredProject) -> None:
        with self._lock:
            job.status = RUNNING
            job.started_at = time.time()
        try:
            report = self.service.analyze(
                AnalysisRequest(
                    project_path=project.root,
                    package_name=job.package_name,
                    current_version=job.current_version,
                    target_version=job.target_version,
                )
            )
            payload = report_dict(report, project.root)
        except Exception as error:
            logger.exception("analysis %s failed", job.id)
            with self._lock:
                job.status = FAILED
                job.error = _message(error)
                job.finished_at = time.time()
        else:
            with self._lock:
                job.report = payload
                job.status = DONE
                job.finished_at = time.time()
        finally:
            self.projects.release(project.id)

    def _trim(self) -> None:
        """Forget the oldest finished jobs once the table is full."""
        if len(self._jobs) <= self.max_jobs:
            return
        for job_id, job in list(self._jobs.items()):
            if len(self._jobs) <= self.max_jobs:
                break
            if job.status in (DONE, FAILED):
                del self._jobs[job_id]
                if self._by_key.get(job.key) == job_id:
                    del self._by_key[job.key]


def _message(error: Exception) -> str:
    text = str(error).strip() or type(error).__name__
    return text[:500]
