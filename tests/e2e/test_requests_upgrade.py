"""Requests 2.28.0 to 2.32.0: the upgrade closes two published advisories.

The recorded test replays data/case_studies/requests.jsonl, whose 29
statements are the frozen corpus. The live test reads GitHub and OSV again
and only checks that every statement falls inside the upgrade window.
"""

from __future__ import annotations

import pytest

from ephemeral_scope.domain.enums import ApiSymbolKind, ReleaseNoteCategory, RiskLevel
from ephemeral_scope.domain.models import ApiSymbol
from ephemeral_scope.main import create_service
from tests.e2e.conftest import (
    REQUESTS_VERSIONS,
    REQUIRES_PROLOG,
    RecordedEvidence,
    RecordedSnapshots,
    recorded_requests_evidence,
    recorded_service,
    requests_request,
)


def _unchanged_requests_api() -> dict[str, tuple[ApiSymbol, ...]]:
    """One symbol present in both versions, so the snapshot is not incomplete.

    The case is about advisories. A real diff of the two releases is what
    the live test builds.
    """
    get = (
        ApiSymbol(
            qualified_name="requests.sessions.Session.get",
            symbol_kind=ApiSymbolKind.METHOD,
            signature="get(self, url, **kwargs)",
        ),
    )
    return {"2.28.0": get, "2.32.0": get}


def assert_requests_report(report, *, exact_versions: set[str] | None = None) -> None:
    assert report.declared_dependency is not None
    assert report.declared_dependency.specifier == "==2.28.0"
    assert any(
        vulnerability.vulnerability_id == "GHSA-j8r2-6x86-q33q"
        for vulnerability in report.fixed_vulnerabilities
    )
    assert any(
        vulnerability.vulnerability_id == "GHSA-9wx4-h78v-vm56"
        for vulnerability in report.fixed_vulnerabilities
    )
    assert report.assessment.upgrade_urgency is RiskLevel.HIGH
    assert report.overall_risk == report.assessment.migration_risk
    assert report.inference_engine == "prolog"
    assert any(
        change.category is ReleaseNoteCategory.SECURITY_FIX
        for change in report.classified_changes
    )
    assert any(
        change.decision is not None and change.decision.model_category is not None
        for change in report.classified_changes
    )
    versions = {change.note.release_version for change in report.classified_changes}
    assert versions <= REQUESTS_VERSIONS
    if exact_versions is not None:
        assert versions == exact_versions


@REQUIRES_PROLOG
@pytest.mark.integration
def test_requests_upgrade_from_recorded_case_study():
    evidence = recorded_requests_evidence()
    service = recorded_service(
        snapshot_builder=RecordedSnapshots(_unchanged_requests_api()),
        evidence_collector=RecordedEvidence(evidence),
    )

    assert_requests_report(
        service.analyze(requests_request()),
        exact_versions=REQUESTS_VERSIONS,
    )


@REQUIRES_PROLOG
@pytest.mark.live
@pytest.mark.integration
def test_requests_upgrade_against_live_providers():
    assert_requests_report(create_service().analyze(requests_request()))
