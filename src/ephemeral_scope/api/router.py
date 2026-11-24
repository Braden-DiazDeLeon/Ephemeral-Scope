"""FastAPI routing layer."""

from __future__ import annotations

import asyncio
import shutil

from fastapi import APIRouter, File, HTTPException, Query, Request, UploadFile

from ephemeral_scope.api.jobs import JobManager, QueueFull, UnknownProject
from ephemeral_scope.api.projects import (
    ProjectError,
    ProjectStore,
    ProjectTooLarge,
    StoredProject,
)
from ephemeral_scope.api.pypi_versions import (
    PackageNotFound,
    PyPIUnavailable,
    VersionLookup,
)
from ephemeral_scope.api.schemas import (
    AnalysisCreate,
    dependency_dict,
    valid_package_name,
)

router = APIRouter(prefix="/api")

_MAX_IDS = 50


def _projects(request: Request) -> ProjectStore:
    return request.app.state.projects


def _jobs(request: Request) -> JobManager:
    return request.app.state.jobs


def _versions(request: Request) -> VersionLookup:
    return request.app.state.versions


def project_dict(project: StoredProject) -> dict:
    return {
        "id": project.id,
        "name": project.name,
        "source_files": project.source_files,
        "test_files": project.test_files,
        "dependency_files": list(project.dependency_files),
        "dependencies": [
            dependency_dict(dependency, project.root)
            for dependency in project.dependencies
        ],
        "warnings": list(project.warnings),
        "created_at": project.created_at,
    }


@router.get("/health")
def health(request: Request) -> dict:
    jobs = _jobs(request)
    service = jobs.service
    engine = getattr(service, "risk_engine", None)
    swipl = getattr(engine, "_swipl", None) or "swipl"
    classifier = getattr(service, "release_note_classifier", None)
    return {
        "status": "ok",
        "prolog": shutil.which(str(swipl)) is not None,
        "classifier": (
            "hybrid" if getattr(classifier, "model", None) is not None else "rules"
        ),
        "max_concurrent": jobs.max_workers,
        "jobs": jobs.counts(),
    }


@router.post("/projects", status_code=201)
async def upload_project(request: Request, file: UploadFile = File(...)) -> dict:
    """Extract an uploaded ZIP and report the dependencies it declares."""
    store = _projects(request)
    try:
        project = await asyncio.to_thread(store.add, file.file, file.filename)
    except ProjectTooLarge as error:
        raise HTTPException(status_code=413, detail=str(error)) from error
    except ProjectError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    finally:
        await file.close()
    return project_dict(project)


@router.get("/projects/{project_id}")
def get_project(project_id: str, request: Request) -> dict:
    project = _projects(request).get(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found or expired.")
    return project_dict(project)


@router.post("/analyses", status_code=202)
def create_analysis(body: AnalysisCreate, request: Request) -> dict:
    """Queue an analysis and return immediately with its id."""
    try:
        job, reused = _jobs(request).submit(
            body.project_id,
            body.package_name,
            body.current_version,
            body.target_version,
        )
    except UnknownProject as error:
        raise HTTPException(
            status_code=404,
            detail="Project not found or expired. Upload the archive again.",
        ) from error
    except QueueFull as error:
        raise HTTPException(status_code=429, detail=str(error)) from error
    return {**job.summary(), "reused": reused}


@router.get("/analyses")
def list_analyses(
    request: Request,
    ids: str = Query("", description="Comma-separated job ids"),
) -> dict:
    """Status of the named jobs, without their reports.

    There is no "list everything" call: a browser only learns about the jobs
    it started, so one visitor cannot read another's results.
    """
    wanted = [part for part in (p.strip() for p in ids.split(",")) if part][:_MAX_IDS]
    manager = _jobs(request)
    found = []
    missing = []
    for job_id in wanted:
        job = manager.get(job_id)
        if job is None:
            missing.append(job_id)
        else:
            found.append(job.summary())
    return {"analyses": found, "missing": missing}


@router.get("/analyses/{job_id}")
def get_analysis(job_id: str, request: Request) -> dict:
    job = _jobs(request).get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return job.detail()


@router.get("/packages/{package_name}/versions")
async def package_versions(package_name: str, request: Request) -> dict:
    try:
        name = valid_package_name(package_name)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    try:
        return await asyncio.to_thread(_versions(request).versions, name)
    except PackageNotFound as error:
        raise HTTPException(
            status_code=404, detail=f"PyPI has no package named {name!r}."
        ) from error
    except PyPIUnavailable as error:
        raise HTTPException(status_code=502, detail=str(error)) from error
