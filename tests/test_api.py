"""Tests for API endpoints.

Everything here runs against a fake analysis service and a fake PyPI, so the
suite stays offline. The real pipeline is exercised through the same routes
in ``tests/e2e/test_api_e2e.py``.
"""

from __future__ import annotations

import io
import threading
import time
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("multipart")

from fastapi.testclient import TestClient  # noqa: E402

from ephemeral_scope.api.app import CachedSnapshotBuilder, create_app  # noqa: E402
from ephemeral_scope.api.projects import ProjectStore  # noqa: E402
from ephemeral_scope.api.pypi_versions import (  # noqa: E402
    PackageNotFound,
    PyPIUnavailable,
    VersionLookup,
)
from ephemeral_scope.api.schemas import pinned_version, source_snippet  # noqa: E402
from ephemeral_scope.domain.enums import (  # noqa: E402
    ApiSymbolKind,
    ChangeType,
    ReleaseNoteCategory,
    RiskLevel,
    SelectionReason,
    UsageKind,
)
from ephemeral_scope.domain.models import (  # noqa: E402
    AffectedUsage,
    AnalysisWarning,
    ApiChange,
    ApiSnapshot,
    ApiSymbol,
    ApiUsage,
    ClassificationDecision,
    ClassifiedChange,
    DependencyUpgrade,
    EvidenceBundle,
    ReleaseNoteItem,
    RiskAssessment,
    RiskFinding,
    RiskReason,
    UpgradeReport,
    VulnerabilityRecord,
)

SOURCE = "import pandas as pd\n\n\ndef build():\n    frame = pd.DataFrame()\n    return frame.append({})\n"


def make_zip(files: dict[str, str | bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def project_zip(prefix: str = "demo/") -> bytes:
    return make_zip(
        {
            f"{prefix}requirements.txt": "pandas==1.5.3\nrequests>=2.28\n",
            f"{prefix}src/report.py": SOURCE,
            f"{prefix}tests/test_report.py": "def test_ok():\n    assert True\n",
        }
    )


def fake_report(request) -> UpgradeReport:
    usage = ApiUsage(
        package_name=request.package_name,
        symbol="pandas.DataFrame.append",
        file=Path("src/report.py"),
        line=6,
        column=11,
        usage_kind=UsageKind.METHOD_CALL,
    )
    change = ApiChange(
        symbol="pandas.core.frame.DataFrame.append",
        change_type=ChangeType.REMOVED,
        old_signature="append(self, other)",
    )
    fixed = VulnerabilityRecord("GHSA-fixed", "closed by the target", fixed_versions=("2.0.0",))
    still_open = VulnerabilityRecord("GHSA-open", "still present")
    decision = ClassificationDecision(
        selected_category=ReleaseNoteCategory.BREAKING_CHANGE,
        rule_category=ReleaseNoteCategory.BREAKING_CHANGE,
        rule_confidence=0.7,
        model_category=ReleaseNoteCategory.BUG_FIX,
        model_confidence=0.4,
        agreement=False,
        selection_reason=SelectionReason.RULE_PREFERRED_OVER_MODEL,
    )
    note = ClassifiedChange(
        note=ReleaseNoteItem(
            text="Removed DataFrame.append",
            release_version=request.target_version,
            section="Removals",
        ),
        category=ReleaseNoteCategory.BREAKING_CHANGE,
        confidence=0.7,
        matched_project_symbols=("pandas.DataFrame.append",),
        relevance_score=0.9,
        decision=decision,
    )
    return UpgradeReport(
        upgrade=DependencyUpgrade(
            request.package_name, request.current_version, request.target_version
        ),
        overall_risk=RiskLevel.HIGH,
        assessment=RiskAssessment(
            migration_risk=RiskLevel.HIGH,
            upgrade_urgency=RiskLevel.MEDIUM,
            migration_reasons=(
                RiskReason(RiskLevel.HIGH, "removed_used_api", "pandas.DataFrame.append"),
            ),
            urgency_reasons=(
                RiskReason(RiskLevel.MEDIUM, "fixes_vulnerability", "GHSA-fixed"),
            ),
        ),
        usages=(usage,),
        api_changes=(change,),
        affected_usages=(AffectedUsage(usage, change),),
        classified_changes=(note,),
        evidence=EvidenceBundle(
            current_vulnerabilities=(fixed, still_open),
            target_vulnerabilities=(still_open,),
        ),
        findings=(
            RiskFinding(
                RiskLevel.HIGH,
                "The API was removed.",
                "removed_used_api",
                file=Path("src/report.py"),
                line=6,
                symbol="pandas.DataFrame.append",
                supporting_facts=("removed(x).",),
            ),
        ),
        recommended_tests=("tests/test_report.py",),
        migration_actions=("Replace pandas.DataFrame.append in src/report.py:6.",),
        inference_engine="prolog",
        warnings=(AnalysisWarning("osv", "OSV could not be reached"),),
    )


class FakeService:
    """Stands in for the pipeline. Can be held open to observe concurrency."""

    def __init__(self) -> None:
        self.calls: list = []
        self.gate = threading.Event()
        self.gate.set()
        self.fail_with: Exception | None = None
        self.running = 0
        self.peak = 0
        self._lock = threading.Lock()

    def analyze(self, request) -> UpgradeReport:
        with self._lock:
            self.calls.append(request)
            self.running += 1
            self.peak = max(self.peak, self.running)
        try:
            assert self.gate.wait(timeout=10), "test never released the gate"
            if self.fail_with is not None:
                raise self.fail_with
            return fake_report(request)
        finally:
            with self._lock:
                self.running -= 1


PYPI_DOCUMENT = {
    "info": {"name": "pandas", "summary": "Data analysis"},
    "releases": {
        "1.5.3": [{"yanked": False, "upload_time_iso_8601": "2023-01-19T00:00:00Z"}],
        "2.0.0": [{"yanked": False, "upload_time_iso_8601": "2023-04-03T00:00:00Z"}],
        "2.0.0rc1": [{"yanked": False, "upload_time_iso_8601": "2023-03-15T00:00:00Z"}],
        "10.0.0": [{"yanked": False, "upload_time_iso_8601": "2030-01-01T00:00:00Z"}],
        "1.9.9": [{"yanked": True}],
        "0.0.1": [],
        "not-a-version": [{"yanked": False}],
    },
}


class FakePyPI:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.error: Exception | None = None

    def __call__(self, name: str, timeout: float) -> dict:
        self.calls.append(name)
        if self.error is not None:
            raise self.error
        return PYPI_DOCUMENT


@pytest.fixture
def service() -> FakeService:
    return FakeService()


@pytest.fixture
def pypi() -> FakePyPI:
    return FakePyPI()


def build_client(service, pypi, tmp_path, **options) -> TestClient:
    store = options.pop("projects", None)
    if store is None:
        store = ProjectStore(base_dir=tmp_path / "projects")
    app = create_app(
        service,
        projects=store,
        versions=VersionLookup(fetch=pypi),
        frontend_dist=options.pop("frontend_dist", None),
        **options,
    )
    return TestClient(app)


@pytest.fixture
def client(service, pypi, tmp_path):
    with build_client(service, pypi, tmp_path) as test_client:
        yield test_client


def upload(client: TestClient, content: bytes | None = None, name: str = "demo.zip"):
    return client.post(
        "/api/projects",
        files={"file": (name, content if content is not None else project_zip(), "application/zip")},
    )


def queue(client: TestClient, project_id: str, **overrides):
    body = {
        "project_id": project_id,
        "package_name": "pandas",
        "current_version": "1.5.3",
        "target_version": "2.0.0",
        **overrides,
    }
    return client.post("/api/analyses", json=body)


def wait_for(client: TestClient, job_id: str, statuses=("done", "failed"), timeout=10.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        detail = client.get(f"/api/analyses/{job_id}").json()
        if detail["status"] in statuses:
            return detail
        time.sleep(0.01)
    raise AssertionError(f"job {job_id} never reached {statuses}")


def wait_until(predicate, timeout=10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition never became true")


class TestHealth:
    def test_reports_capacity_and_engine(self, client):
        body = client.get("/api/health").json()
        assert body["status"] == "ok"
        assert body["max_concurrent"] == 4
        assert body["classifier"] == "rules"
        assert body["jobs"] == {"queued": 0, "running": 0, "done": 0, "failed": 0}
        assert isinstance(body["prolog"], bool)


class TestProjectUpload:
    def test_returns_declared_dependencies(self, client):
        response = upload(client)
        assert response.status_code == 201
        body = response.json()
        assert body["name"] == "demo"
        assert body["source_files"] == 1
        assert body["test_files"] == 1
        assert body["dependency_files"] == ["requirements.txt"]
        by_name = {dep["name"]: dep for dep in body["dependencies"]}
        assert by_name["pandas"]["pinned_version"] == "1.5.3"
        assert by_name["pandas"]["source_file"] == "requirements.txt"
        assert by_name["requests"]["pinned_version"] is None
        assert by_name["requests"]["specifier"] == ">=2.28"
        assert body["warnings"] == []

    def test_can_be_fetched_again(self, client):
        project_id = upload(client).json()["id"]
        assert client.get(f"/api/projects/{project_id}").json()["id"] == project_id
        assert client.get("/api/projects/nope").status_code == 404

    def test_flat_archive_is_named_after_the_file(self, client):
        body = upload(client, project_zip(prefix=""), name="my-app.zip").json()
        assert body["name"] == "my-app"
        assert body["dependency_files"] == ["requirements.txt"]

    def test_finder_metadata_does_not_hide_the_project_folder(self, client):
        content = make_zip(
            {
                "demo/requirements.txt": "pandas==1.5.3\n",
                "demo/app.py": "import pandas\n",
                "demo/.DS_Store": b"\x00\x01",
                "__MACOSX/demo/._app.py": b"\x00\x01",
            }
        )
        body = upload(client, content).json()
        assert body["name"] == "demo"
        assert body["dependencies"][0]["name"] == "pandas"

    def test_missing_dependency_file_is_a_warning(self, client):
        body = upload(client, make_zip({"app.py": "import pandas\n"})).json()
        assert body["dependencies"] == []
        assert "enter the package" in body["warnings"][0]

    def test_malformed_dependency_file_is_a_warning(self, client):
        content = make_zip({"pyproject.toml": "not [valid toml", "app.py": "x = 1\n"})
        response = upload(client, content)
        assert response.status_code == 201
        assert "could not be parsed" in response.json()["warnings"][0]

    @pytest.mark.parametrize(
        "content,expected",
        [
            (b"this is not a zip", "not a valid ZIP"),
            (b"", "empty"),
            (make_zip({"README.md": "hello"}), "no Python files"),
            (make_zip({"../escape.py": "x = 1"}), "escape"),
        ],
        ids=["not-a-zip", "empty", "no-python", "path-traversal"],
    )
    def test_rejects_unusable_archives(self, client, content, expected):
        response = upload(client, content)
        assert response.status_code == 400
        assert expected in response.json()["detail"]

    def test_rejects_an_oversized_upload(self, service, pypi, tmp_path):
        store = ProjectStore(base_dir=tmp_path / "small", max_zip_bytes=64)
        with build_client(service, pypi, tmp_path, projects=store) as client:
            response = upload(client)
            assert response.status_code == 413
            assert "larger than" in response.json()["detail"]

    def test_a_rejected_upload_leaves_nothing_on_disk(self, client, tmp_path):
        upload(client, b"this is not a zip")
        assert list((tmp_path / "projects").iterdir()) == []

    def test_requires_a_file(self, client):
        assert client.post("/api/projects").status_code == 422


class TestAnalysisValidation:
    @pytest.mark.parametrize(
        "overrides",
        [
            {"package_name": "../etc/passwd"},
            {"package_name": ""},
            {"package_name": "has space"},
            {"current_version": "banana"},
            {"target_version": ""},
            {"current_version": "2.0.0", "target_version": "2.0.0"},
            {"current_version": "2.0.0", "target_version": "1.5.3"},
        ],
        ids=["traversal", "empty", "space", "bad-version", "no-target", "same", "downgrade"],
    )
    def test_rejects_bad_requests_before_queueing(self, client, service, overrides):
        project_id = upload(client).json()["id"]
        response = queue(client, project_id, **overrides)
        assert response.status_code == 422
        assert service.calls == []

    def test_unknown_project(self, client):
        response = queue(client, "missing")
        assert response.status_code == 404
        assert "Upload the archive again" in response.json()["detail"]

    def test_unknown_job(self, client):
        assert client.get("/api/analyses/missing").status_code == 404


class TestAnalysis:
    def test_returns_immediately_then_completes(self, client, service):
        service.gate.clear()
        project_id = upload(client).json()["id"]
        response = queue(client, project_id)
        assert response.status_code == 202
        job = response.json()
        assert job["status"] in ("queued", "running")
        assert job["reused"] is False
        assert "report" not in job

        running = wait_for(client, job["id"], statuses=("running",))
        assert running["report"] is None

        service.gate.set()
        done = wait_for(client, job["id"])
        assert done["status"] == "done"
        assert done["error"] is None
        assert done["run_seconds"] >= 0
        assert done["migration_risk"] == "high"
        assert done["upgrade_urgency"] == "medium"

    def test_report_shape(self, client):
        project_id = upload(client).json()["id"]
        report = wait_for(client, queue(client, project_id).json()["id"])["report"]

        assert report["upgrade"] == {
            "package_name": "pandas",
            "current_version": "1.5.3",
            "target_version": "2.0.0",
        }
        assert report["migration_risk"] == "high"
        assert report["upgrade_urgency"] == "medium"
        assert report["migration_reasons"] == [
            {"level": "high", "rule": "removed_used_api", "subject": "pandas.DataFrame.append"}
        ]
        assert report["inference_engine"] == "prolog"
        assert report["recommended_tests"] == ["tests/test_report.py"]
        assert report["migration_actions"][0].startswith("Replace pandas.DataFrame.append")
        assert report["warnings"] == [
            {"component": "osv", "message": "OSV could not be reached"}
        ]
        assert report["usage_count"] == 1
        assert report["usages"][0]["affected"] is True
        assert report["api_change_count"] == 1
        assert report["classifier_disagreement_count"] == 1

        note = report["release_notes"][0]
        assert note["category"] == "breaking_change"
        assert note["matched_project_symbols"] == ["pandas.DataFrame.append"]
        assert note["decision"]["selection_reason"] == "rule_preferred_over_model"
        assert note["decision"]["model_category"] == "bug_fix"

        finding = report["findings"][0]
        assert finding["file"] == "src/report.py"
        assert finding["supporting_facts"] == ["removed(x)."]

    def test_separates_fixed_from_still_open_advisories(self, client):
        project_id = upload(client).json()["id"]
        vulnerabilities = wait_for(client, queue(client, project_id).json()["id"])[
            "report"
        ]["vulnerabilities"]
        assert [v["id"] for v in vulnerabilities["fixed"]] == ["GHSA-fixed"]
        assert [v["id"] for v in vulnerabilities["remaining"]] == ["GHSA-open"]
        assert vulnerabilities["introduced"] == []

    def test_affected_usage_carries_the_source_lines(self, client):
        project_id = upload(client).json()["id"]
        affected = wait_for(client, queue(client, project_id).json()["id"])["report"][
            "affected_usages"
        ][0]
        assert affected["file"] == "src/report.py"
        assert affected["line"] == 6
        assert affected["change"]["change_type"] == "removed"
        snippet = affected["snippet"]
        assert snippet["highlight_line"] == 6
        assert snippet["start_line"] == 3
        hit = snippet["lines"][snippet["highlight_line"] - snippet["start_line"]]
        assert hit.strip() == "return frame.append({})"

    def test_service_receives_the_extracted_directory(self, client, service):
        project_id = upload(client).json()["id"]
        wait_for(client, queue(client, project_id).json()["id"])
        request = service.calls[0]
        assert request.project_path.is_dir()
        assert (request.project_path / "requirements.txt").is_file()
        assert (request.package_name, request.current_version, request.target_version) == (
            "pandas",
            "1.5.3",
            "2.0.0",
        )

    def test_no_absolute_paths_leak_into_the_report(self, client, tmp_path):
        project_id = upload(client).json()["id"]
        detail = wait_for(client, queue(client, project_id).json()["id"])
        assert str(tmp_path) not in str(detail)

    def test_failure_is_reported_and_can_be_retried(self, client, service):
        service.fail_with = RuntimeError("PyPI has no such release")
        project_id = upload(client).json()["id"]
        first = queue(client, project_id).json()
        failed = wait_for(client, first["id"])
        assert failed["status"] == "failed"
        assert failed["error"] == "PyPI has no such release"
        assert failed["report"] is None

        service.fail_with = None
        retry = queue(client, project_id).json()
        assert retry["reused"] is False
        assert retry["id"] != first["id"]
        assert wait_for(client, retry["id"])["status"] == "done"


class TestReuse:
    def test_identical_request_returns_the_same_job(self, client, service):
        project_id = upload(client).json()["id"]
        first = queue(client, project_id).json()
        wait_for(client, first["id"])
        again = queue(client, project_id).json()
        assert again["id"] == first["id"]
        assert again["reused"] is True
        assert again["status"] == "done"
        assert len(service.calls) == 1

    def test_same_archive_uploaded_twice_is_still_reused(self, client, service):
        first = queue(client, upload(client).json()["id"]).json()
        wait_for(client, first["id"])
        again = queue(client, upload(client).json()["id"]).json()
        assert again["id"] == first["id"]
        assert len(service.calls) == 1

    def test_in_flight_request_is_not_duplicated(self, client, service):
        service.gate.clear()
        project_id = upload(client).json()["id"]
        first = queue(client, project_id).json()
        again = queue(client, project_id).json()
        assert again["id"] == first["id"] and again["reused"] is True
        service.gate.set()
        wait_for(client, first["id"])
        assert len(service.calls) == 1

    def test_different_versions_are_different_jobs(self, client, service):
        project_id = upload(client).json()["id"]
        one = queue(client, project_id).json()
        two = queue(client, project_id, target_version="10.0.0").json()
        assert one["id"] != two["id"]
        wait_for(client, one["id"])
        wait_for(client, two["id"])
        assert len(service.calls) == 2

    def test_package_name_is_compared_canonically(self, client, service):
        project_id = upload(client).json()["id"]
        one = queue(client, project_id, package_name="Typing_Extensions").json()
        two = queue(client, project_id, package_name="typing-extensions").json()
        assert one["id"] == two["id"]


class TestConcurrency:
    def test_jobs_run_side_by_side_up_to_the_worker_limit(self, service, pypi, tmp_path):
        service.gate.clear()
        with build_client(service, pypi, tmp_path, max_workers=2) as client:
            project_id = upload(client).json()["id"]
            ids = [
                queue(client, project_id, target_version=version).json()["id"]
                for version in ("2.0.0", "2.0.1", "2.0.2")
            ]
            wait_until(lambda: client.get("/api/health").json()["jobs"]["running"] == 2)
            counts = client.get("/api/health").json()["jobs"]
            assert counts == {"queued": 1, "running": 2, "done": 0, "failed": 0}
            statuses = sorted(
                job["status"]
                for job in client.get(f"/api/analyses?ids={','.join(ids)}").json()["analyses"]
            )
            assert statuses == ["queued", "running", "running"]

            service.gate.set()
            for job_id in ids:
                assert wait_for(client, job_id)["status"] == "done"
            assert service.peak == 2

    def test_requests_stay_responsive_while_jobs_run(self, client, service):
        service.gate.clear()
        project_id = upload(client).json()["id"]
        job_id = queue(client, project_id).json()["id"]
        wait_for(client, job_id, statuses=("running",))
        started = time.time()
        assert client.get("/api/health").status_code == 200
        assert upload(client).status_code == 201
        assert time.time() - started < 2
        service.gate.set()
        wait_for(client, job_id)

    def test_a_full_queue_is_refused(self, service, pypi, tmp_path):
        service.gate.clear()
        with build_client(service, pypi, tmp_path, max_workers=1, max_pending=1) as client:
            project_id = upload(client).json()["id"]
            first = queue(client, project_id, target_version="2.0.0").json()["id"]
            wait_for(client, first, statuses=("running",))
            assert queue(client, project_id, target_version="2.0.1").status_code == 202
            refused = queue(client, project_id, target_version="2.0.2")
            assert refused.status_code == 429
            assert "waiting" in refused.json()["detail"]
            service.gate.set()
            wait_for(client, first)

    def test_many_simultaneous_submissions_all_finish(self, client, service):
        project_id = upload(client).json()["id"]
        results: list[dict] = []

        def submit(index: int) -> None:
            results.append(queue(client, project_id, target_version=f"2.0.{index}").json())

        threads = [threading.Thread(target=submit, args=(i,)) for i in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len({job["id"] for job in results}) == 12
        for job in results:
            assert wait_for(client, job["id"])["status"] == "done"
        assert len(service.calls) == 12
        assert service.peak <= 4


class TestListing:
    def test_only_named_jobs_are_returned(self, client):
        project_id = upload(client).json()["id"]
        one = queue(client, project_id).json()["id"]
        two = queue(client, project_id, target_version="10.0.0").json()["id"]
        wait_for(client, one)
        wait_for(client, two)

        body = client.get(f"/api/analyses?ids={one},ghost").json()
        assert [job["id"] for job in body["analyses"]] == [one]
        assert body["missing"] == ["ghost"]
        assert "report" not in body["analyses"][0]

    def test_no_ids_lists_nothing(self, client):
        project_id = upload(client).json()["id"]
        wait_for(client, queue(client, project_id).json()["id"])
        assert client.get("/api/analyses").json() == {"analyses": [], "missing": []}


class TestVersions:
    def test_newest_first_without_unusable_releases(self, client):
        body = client.get("/api/packages/pandas/versions").json()
        assert body["package_name"] == "pandas"
        assert [v["version"] for v in body["versions"]] == [
            "10.0.0",
            "2.0.0",
            "2.0.0rc1",
            "1.9.9",
            "1.5.3",
        ]
        # A yanked release stays selectable: a project may be pinned to it.
        assert [v["version"] for v in body["versions"] if v["yanked"]] == ["1.9.9"]
        flags = {v["version"]: v["prerelease"] for v in body["versions"]}
        assert flags == {
            "10.0.0": False,
            "2.0.0": False,
            "2.0.0rc1": True,
            "1.9.9": False,
            "1.5.3": False,
        }
        assert body["versions"][1]["released"] == "2023-04-03"

    def test_lookup_is_cached(self, client, pypi):
        client.get("/api/packages/pandas/versions")
        client.get("/api/packages/Pandas/versions")
        assert pypi.calls == ["pandas"]

    def test_unknown_package(self, client, pypi):
        pypi.error = PackageNotFound("nope")
        response = client.get("/api/packages/nope/versions")
        assert response.status_code == 404
        assert "no package named" in response.json()["detail"]

    def test_pypi_outage(self, client, pypi):
        pypi.error = PyPIUnavailable("PyPI could not be reached: timeout")
        assert client.get("/api/packages/pandas/versions").status_code == 502

    def test_invalid_name_never_reaches_pypi(self, client, pypi):
        assert client.get("/api/packages/bad name/versions").status_code == 422
        assert pypi.calls == []


class TestProjectStore:
    def test_expired_uploads_are_deleted(self, tmp_path):
        store = ProjectStore(base_dir=tmp_path, ttl_seconds=0)
        project = store.add(io.BytesIO(project_zip()), "demo.zip")
        assert project.container.is_dir()
        time.sleep(0.01)
        assert store.get(project.id) is None
        assert not project.container.exists()

    def test_oldest_idle_upload_makes_room(self, tmp_path):
        store = ProjectStore(base_dir=tmp_path, max_projects=2)
        first = store.add(io.BytesIO(project_zip()), "a.zip")
        second = store.add(io.BytesIO(project_zip()), "b.zip")
        third = store.add(io.BytesIO(project_zip()), "c.zip")
        assert store.get(first.id) is None
        assert store.get(second.id) is not None and store.get(third.id) is not None
        assert len(store) == 2

    def test_an_upload_being_analyzed_is_kept(self, tmp_path):
        store = ProjectStore(base_dir=tmp_path, ttl_seconds=0.2, max_projects=1)
        busy = store.add(io.BytesIO(project_zip()), "a.zip")
        assert store.acquire(busy.id) is not None
        time.sleep(0.25)
        store.add(io.BytesIO(project_zip()), "b.zip")
        assert busy.container.is_dir()
        store.release(busy.id)
        assert store.get(busy.id) is None
        assert not busy.container.exists()

    def test_close_removes_everything(self, tmp_path):
        store = ProjectStore(base_dir=tmp_path)
        project = store.add(io.BytesIO(project_zip()), "demo.zip")
        store.close()
        assert not project.container.exists()


class TestSchemas:
    @pytest.mark.parametrize(
        "specifier,expected",
        [
            ("==1.5.3", "1.5.3"),
            ("== 2.0", "2.0"),
            (">=1.0", None),
            ("==1.*", None),
            (">=1.0,<2", None),
            ("===1.0", None),
            (None, None),
            ("", None),
        ],
    )
    def test_pinned_version(self, specifier, expected):
        assert pinned_version(specifier) == expected

    def test_snippet_never_reads_outside_the_project(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        (project / "a.py").write_text("one\ntwo\nthree\n")
        (tmp_path / "secret.py").write_text("password = 1\n")

        assert source_snippet(project, Path("a.py"), 2, context=1) == {
            "start_line": 1,
            "highlight_line": 2,
            "lines": ["one", "two", "three"],
        }
        assert source_snippet(project, Path("../secret.py"), 1) is None
        assert source_snippet(project, tmp_path / "secret.py", 1) is None
        assert source_snippet(project, Path("missing.py"), 1) is None
        assert source_snippet(project, Path("a.py"), 99) is None
        assert source_snippet(project, Path("a.py"), 0) is None
        assert source_snippet(None, Path("a.py"), 1) is None


class TestSnapshotCache:
    def test_each_version_is_built_once_across_threads(self):
        class SlowBuilder:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str]] = []

            def build(self, package_name: str, version: str) -> ApiSnapshot:
                self.calls.append((package_name, version))
                time.sleep(0.05)
                return ApiSnapshot(
                    package_name,
                    version,
                    (ApiSymbol(f"{package_name}.f", ApiSymbolKind.FUNCTION),),
                )

        inner = SlowBuilder()
        cached = CachedSnapshotBuilder(inner)
        results: list[ApiSnapshot] = []
        threads = [
            threading.Thread(target=lambda: results.append(cached.build("pandas", "2.0.0")))
            for _ in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert inner.calls == [("pandas", "2.0.0")]
        assert all(result is results[0] for result in results)
        cached.build("pandas", "1.5.3")
        assert len(inner.calls) == 2

    def test_failed_snapshot_is_not_remembered(self):
        class EmptyBuilder:
            calls = 0

            def build(self, package_name: str, version: str) -> ApiSnapshot:
                self.calls += 1
                return ApiSnapshot(package_name, version, ())

        inner = EmptyBuilder()
        cached = CachedSnapshotBuilder(inner)
        cached.build("pandas", "2.0.0")
        cached.build("pandas", "2.0.0")
        assert inner.calls == 2

    def test_errors_propagate_and_are_retried(self):
        class BrokenBuilder:
            calls = 0

            def build(self, package_name: str, version: str) -> ApiSnapshot:
                self.calls += 1
                raise RuntimeError("download failed")

        inner = BrokenBuilder()
        cached = CachedSnapshotBuilder(inner)
        for _ in range(2):
            with pytest.raises(RuntimeError):
                cached.build("pandas", "2.0.0")
        assert inner.calls == 2


class TestFrontendServing:
    def test_built_frontend_is_served_beside_the_api(self, service, pypi, tmp_path):
        dist = tmp_path / "dist"
        (dist / "assets").mkdir(parents=True)
        (dist / "index.html").write_text("<html>app</html>")
        (dist / "assets" / "app.js").write_text("console.log(1)")
        (dist / "logo.svg").write_text("<svg/>")
        (tmp_path / "secret.txt").write_text("no")

        with build_client(service, pypi, tmp_path, frontend_dist=dist) as client:
            assert client.get("/").text == "<html>app</html>"
            assert client.get("/some/client/route").text == "<html>app</html>"
            assert client.get("/assets/app.js").text == "console.log(1)"
            assert client.get("/logo.svg").text == "<svg/>"
            assert client.get("/api/health").json()["status"] == "ok"
            assert client.get("/api/nope").status_code == 404
            assert client.get("/%2e%2e/secret.txt").text == "<html>app</html>"

    def test_api_works_without_a_built_frontend(self, client):
        assert client.get("/").status_code == 404
        assert client.get("/api/health").status_code == 200
