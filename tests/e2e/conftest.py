"""Shared pieces for the end-to-end upgrade cases.

The recorded tests inject release notes and API snapshots so `pytest -q`
does not call PyPI, GitHub, or OSV. The live tests use `create_service()`
unchanged and are selected with `-m "live and integration"`.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from ephemeral_scope.domain.enums import ApiSymbolKind
from ephemeral_scope.domain.models import (
    AnalysisRequest,
    ApiSnapshot,
    ApiSymbol,
    DependencyUpgrade,
    EvidenceBundle,
    ReleaseNoteItem,
    VulnerabilityRecord,
)
from ephemeral_scope.main import create_service

ROOT = Path(__file__).resolve().parents[2]
PANDAS_PROJECT = ROOT / "examples" / "pandas_append_project"
REQUESTS_PROJECT = ROOT / "examples" / "requests_security_project"
REQUESTS_CASE_STUDY = ROOT / "data" / "case_studies" / "requests.jsonl"

REQUIRES_PROLOG = pytest.mark.skipif(
    shutil.which("swipl") is None, reason="SWI-Prolog is not installed"
)

# Versions strictly after 2.28.0 and up to 2.32.0. The live test checks
# this as an upper bound; the recorded case study is exactly this set.
REQUESTS_VERSIONS = {
    "2.28.1",
    "2.28.2",
    "2.29.0",
    "2.30.0",
    "2.31.0",
    "2.32.0",
}


class RecordedSnapshots:
    """Serves symbols captured from a real Griffe run, without downloading."""

    def __init__(self, by_version: dict[str, tuple[ApiSymbol, ...]]) -> None:
        self.by_version = by_version

    def build(self, package_name: str, version: str) -> ApiSnapshot:
        return ApiSnapshot(
            package_name=package_name,
            version=version,
            symbols=self.by_version[version],
        )


class RecordedEvidence:
    def __init__(self, bundle: EvidenceBundle) -> None:
        self.bundle = bundle

    def collect(self, upgrade: DependencyUpgrade) -> EvidenceBundle:
        return self.bundle


def pandas_request() -> AnalysisRequest:
    return AnalysisRequest(
        project_path=PANDAS_PROJECT,
        package_name="pandas",
        current_version="1.5.3",
        target_version="2.0.0",
    )


def requests_request() -> AnalysisRequest:
    return AnalysisRequest(
        project_path=REQUESTS_PROJECT,
        package_name="requests",
        current_version="2.28.0",
        target_version="2.32.0",
    )


def recorded_requests_notes() -> tuple[ReleaseNoteItem, ...]:
    notes = []
    for line in REQUESTS_CASE_STUDY.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        notes.append(
            ReleaseNoteItem(
                text=row["text"],
                release_version=row["release_version"],
                source_url=row.get("source_url"),
                package_name=row.get("package_name"),
                section=row.get("section"),
            )
        )
    return tuple(notes)


def recorded_requests_evidence() -> EvidenceBundle:
    """The two advisories 2.32.0 closes, taken from the cached OSV answers.

    Both affect 2.28.0 and neither affects 2.32.0, so the upgrade fixes them.
    """
    fixed = (
        VulnerabilityRecord(
            vulnerability_id="GHSA-j8r2-6x86-q33q",
            summary="Proxy-Authorization header leak",
            fixed_versions=("2.31.0",),
        ),
        VulnerabilityRecord(
            vulnerability_id="GHSA-9wx4-h78v-vm56",
            summary="Session with verify=False leaks that setting to later requests",
            fixed_versions=("2.32.0",),
        ),
    )
    return EvidenceBundle(
        release_notes=recorded_requests_notes(),
        current_vulnerabilities=fixed,
    )


def pandas_symbols() -> dict[str, tuple[ApiSymbol, ...]]:
    """The symbols this project uses, under the names Griffe assigned them.

    A full pandas snapshot is about 26,000 symbols. The recorded test keeps
    the two that decide the case. The live test builds both snapshots from
    the PyPI wheels.
    """
    frame = ApiSymbol(
        qualified_name="pandas.core.frame.DataFrame",
        symbol_kind=ApiSymbolKind.CLASS,
    )
    append = ApiSymbol(
        qualified_name="pandas.core.frame.DataFrame.append",
        symbol_kind=ApiSymbolKind.METHOD,
        signature="append(self, other, ignore_index=False, verify_integrity=False, sort=False)",
    )
    return {"1.5.3": (frame, append), "2.0.0": (frame,)}


def recorded_service(**replacements):
    service = create_service()
    for name, value in replacements.items():
        setattr(service, name, value)
    return service
