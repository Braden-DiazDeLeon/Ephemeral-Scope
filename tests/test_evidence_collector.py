"""Tests for EvidenceCollector coordination."""

import pytest

from ephemeral_scope.domain.models import (
    DependencyUpgrade,
    ReleaseNoteItem,
    VulnerabilityRecord,
)
from ephemeral_scope.evidence.evidence_collector import EvidenceCollector

UPGRADE = DependencyUpgrade("requests", "2.28.0", "2.32.0")


class FakeNotes:
    def __init__(self, items=(), error: Exception | None = None):
        self.items = list(items)
        self.error = error

    def get_notes(self, upgrade):
        if self.error:
            raise self.error
        return self.items


class FakeOsv:
    def __init__(self, by_version=None, error: Exception | None = None):
        self.by_version = by_version or {}
        self.error = error
        self.queried: list[tuple[str, str]] = []

    def get_vulnerabilities(self, package, version):
        self.queried.append((package, version))
        if self.error:
            raise self.error
        return list(self.by_version.get(version, []))


def record(identifier: str) -> VulnerabilityRecord:
    return VulnerabilityRecord(vulnerability_id=identifier, summary=identifier)


def note(text: str) -> ReleaseNoteItem:
    return ReleaseNoteItem(text=text, release_version="2.32.0")


def test_bundles_both_sources():
    collector = EvidenceCollector(
        FakeNotes([note("Removed the old API.")]),
        FakeOsv({"2.28.0": [record("GHSA-1")]}),
    )
    bundle = collector.collect(UPGRADE)

    assert [n.text for n in bundle.release_notes] == ["Removed the old API."]
    assert [v.vulnerability_id for v in bundle.vulnerabilities] == ["GHSA-1"]


def test_queries_both_versions():
    osv = FakeOsv()
    EvidenceCollector(FakeNotes(), osv).collect(UPGRADE)
    assert osv.queried == [("requests", "2.28.0"), ("requests", "2.32.0")]


def test_vulnerabilities_are_deduplicated_across_versions():
    osv = FakeOsv({"2.28.0": [record("GHSA-1")], "2.32.0": [record("GHSA-1")]})
    bundle = EvidenceCollector(FakeNotes(), osv).collect(UPGRADE)
    assert [v.vulnerability_id for v in bundle.vulnerabilities] == ["GHSA-1"]


def test_merges_distinct_vulnerabilities():
    osv = FakeOsv({"2.28.0": [record("GHSA-1")], "2.32.0": [record("GHSA-2")]})
    bundle = EvidenceCollector(FakeNotes(), osv).collect(UPGRADE)
    assert [v.vulnerability_id for v in bundle.vulnerabilities] == ["GHSA-1", "GHSA-2"]


def test_failing_notes_do_not_lose_vulnerabilities():
    collector = EvidenceCollector(
        FakeNotes(error=RuntimeError("github down")),
        FakeOsv({"2.28.0": [record("GHSA-1")]}),
    )
    bundle = collector.collect(UPGRADE)
    assert bundle.release_notes == ()
    assert [v.vulnerability_id for v in bundle.vulnerabilities] == ["GHSA-1"]


def test_failing_osv_does_not_lose_notes():
    collector = EvidenceCollector(
        FakeNotes([note("Removed the old API.")]),
        FakeOsv(error=RuntimeError("osv down")),
    )
    bundle = collector.collect(UPGRADE)
    assert bundle.vulnerabilities == ()
    assert len(bundle.release_notes) == 1


def test_everything_down_yields_an_empty_bundle():
    collector = EvidenceCollector(
        FakeNotes(error=RuntimeError("x")), FakeOsv(error=RuntimeError("y"))
    )
    bundle = collector.collect(UPGRADE)
    assert bundle.release_notes == ()
    assert bundle.vulnerabilities == ()


def test_a_failed_lookup_is_a_warning_and_an_empty_answer_is_not():
    """No advisories and an OSV outage must not look the same."""
    quiet = EvidenceCollector(FakeNotes(), FakeOsv()).collect(UPGRADE)
    down = EvidenceCollector(
        FakeNotes(error=RuntimeError("github down")),
        FakeOsv(error=RuntimeError("osv down")),
    ).collect(UPGRADE)

    assert quiet.vulnerabilities == ()
    assert quiet.release_notes == ()
    assert quiet.warnings == ()

    assert down.vulnerabilities == ()
    assert down.release_notes == ()
    messages = [warning.message for warning in down.warnings]
    assert any(message.startswith("Release notes unavailable") for message in messages)
    assert any("OSV current-version query failed" in message for message in messages)
    assert any("OSV target-version query failed" in message for message in messages)


def test_one_failed_source_does_not_warn_about_the_other():
    bundle = EvidenceCollector(
        FakeNotes([note("Removed the old API.")]),
        FakeOsv(error=RuntimeError("osv down")),
    ).collect(UPGRADE)

    assert [warning.component for warning in bundle.warnings] == ["osv", "osv"]
    assert bundle.release_notes
