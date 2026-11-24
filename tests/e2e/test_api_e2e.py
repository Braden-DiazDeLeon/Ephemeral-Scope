"""The two upgrade cases, driven through the HTTP API.

Same projects and the same expectations as the service-level cases beside
this file, but entered the way the browser enters them: upload a ZIP, queue
an analysis, poll until it finishes, read the JSON report.
"""

from __future__ import annotations

import io
import time
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("multipart")

from fastapi.testclient import TestClient  # noqa: E402

from ephemeral_scope.api.app import create_app  # noqa: E402
from ephemeral_scope.domain.models import EvidenceBundle  # noqa: E402
from tests.e2e.conftest import (  # noqa: E402
    PANDAS_PROJECT,
    REQUESTS_PROJECT,
    REQUIRES_PROLOG,
    RecordedEvidence,
    RecordedSnapshots,
    pandas_symbols,
    recorded_requests_evidence,
    recorded_service,
)
from tests.e2e.test_requests_upgrade import _unchanged_requests_api  # noqa: E402


def zipped(project: Path) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(project.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                archive.write(path, Path(project.name) / path.relative_to(project))
    return buffer.getvalue()


def run(client: TestClient, project: Path, package: str, current: str, target: str, timeout=180.0):
    uploaded = client.post(
        "/api/projects",
        files={"file": (f"{project.name}.zip", zipped(project), "application/zip")},
    )
    assert uploaded.status_code == 201, uploaded.text
    project_body = uploaded.json()

    queued = client.post(
        "/api/analyses",
        json={
            "project_id": project_body["id"],
            "package_name": package,
            "current_version": current,
            "target_version": target,
        },
    )
    assert queued.status_code == 202, queued.text

    deadline = time.time() + timeout
    while time.time() < deadline:
        detail = client.get(f"/api/analyses/{queued.json()['id']}").json()
        if detail["status"] in ("done", "failed"):
            break
        time.sleep(0.1)
    else:
        raise AssertionError("analysis did not finish in time")
    assert detail["status"] == "done", detail["error"]
    return project_body, detail["report"]


def assert_pandas(project: dict, report: dict) -> None:
    assert project["dependencies"][0]["name"] == "pandas"
    assert project["dependencies"][0]["pinned_version"] == "1.5.3"
    assert report["migration_risk"] == "high"
    assert report["declared_dependency"]["specifier"] == "==1.5.3"
    assert report["inference_engine"] == "prolog"

    affected = [
        item
        for item in report["affected_usages"]
        if item["symbol"] == "pandas.DataFrame.append"
    ]
    assert affected and affected[0]["change"]["change_type"] == "removed"
    assert affected[0]["file"] == "src/report.py"
    snippet = affected[0]["snippet"]
    hit = snippet["lines"][snippet["highlight_line"] - snippet["start_line"]]
    assert "frame.append" in hit

    assert "tests/test_report.py" in report["recommended_tests"]
    assert any("src/report.py" in action for action in report["migration_actions"])
    assert any(
        reason["rule"] == "removed_used_api" for reason in report["migration_reasons"]
    )
    assert not any(w["component"] == "api_snapshot" for w in report["warnings"])


def assert_requests(project: dict, report: dict) -> None:
    assert project["dependencies"][0]["pinned_version"] == "2.28.0"
    assert report["migration_risk"] == "low"
    assert report["upgrade_urgency"] == "high"
    assert report["affected_usages"] == []
    assert report["inference_engine"] == "prolog"

    fixed = {record["id"] for record in report["vulnerabilities"]["fixed"]}
    assert {"GHSA-9wx4-h78v-vm56", "GHSA-j8r2-6x86-q33q"} <= fixed
    still_open = {record["id"] for record in report["vulnerabilities"]["remaining"]}
    assert not fixed & still_open

    categories = {note["category"] for note in report["release_notes"]}
    assert "security_fix" in categories
    assert any(
        note["decision"] and note["decision"]["model_category"]
        for note in report["release_notes"]
    )
    assert any("2.32.0" in action for action in report["migration_actions"])


@REQUIRES_PROLOG
@pytest.mark.integration
def test_pandas_upgrade_through_the_api_from_recorded_snapshot():
    service = recorded_service(
        snapshot_builder=RecordedSnapshots(pandas_symbols()),
        evidence_collector=RecordedEvidence(EvidenceBundle()),
    )
    with TestClient(create_app(service, frontend_dist=None)) as client:
        assert_pandas(*run(client, PANDAS_PROJECT, "pandas", "1.5.3", "2.0.0"))


@REQUIRES_PROLOG
@pytest.mark.integration
def test_requests_upgrade_through_the_api_from_recorded_case_study():
    service = recorded_service(
        snapshot_builder=RecordedSnapshots(_unchanged_requests_api()),
        evidence_collector=RecordedEvidence(recorded_requests_evidence()),
    )
    with TestClient(create_app(service, frontend_dist=None)) as client:
        assert_requests(*run(client, REQUESTS_PROJECT, "requests", "2.28.0", "2.32.0"))


@REQUIRES_PROLOG
@pytest.mark.live
@pytest.mark.integration
def test_both_upgrades_through_the_api_against_live_providers():
    """The production app, unmodified: real PyPI, GitHub, OSV and SWI-Prolog."""
    with TestClient(create_app(frontend_dist=None)) as client:
        health = client.get("/api/health").json()
        assert health["prolog"] is True
        assert health["classifier"] == "hybrid"

        versions = client.get("/api/packages/pandas/versions").json()["versions"]
        listed = [entry["version"] for entry in versions]
        assert "1.5.3" in listed and "2.0.0" in listed
        assert listed.index("2.0.0") < listed.index("1.5.3")

        assert_pandas(*run(client, PANDAS_PROJECT, "pandas", "1.5.3", "2.0.0"))
        assert_requests(*run(client, REQUESTS_PROJECT, "requests", "2.28.0", "2.32.0"))
