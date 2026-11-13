"""Tests for OSVClient (offline, with a stubbed transport)."""

import pytest

from ephemeral_scope.evidence.osv_client import OSVClient

ADVISORY = {
    "id": "GHSA-j8r2-6x86-q33q",
    "summary": "Unintended leak of Proxy-Authorization header in requests",
    "affected": [
        {
            "versions": ["2.28.0", "2.28.1"],
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.31.0"}],
                }
            ],
        }
    ],
    "references": [
        {"type": "WEB", "url": "https://example.test/blog"},
        {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-32681"},
    ],
}


class FakeHttp:
    def __init__(self, document):
        self.document = document
        self.payloads: list = []

    def post_json(self, url, payload, headers=None):
        self.payloads.append(payload)
        return self.document


def client(document) -> tuple[OSVClient, FakeHttp]:
    http = FakeHttp(document)
    return OSVClient(http=http), http


def test_parses_an_advisory():
    osv, _ = client({"vulns": [ADVISORY]})
    record = osv.get_vulnerabilities("requests", "2.28.0")[0]

    assert record.vulnerability_id == "GHSA-j8r2-6x86-q33q"
    assert record.summary.startswith("Unintended leak")
    assert record.affected_versions == ("2.28.0", "2.28.1")
    assert record.fixed_versions == ("2.31.0",)


def test_prefers_the_advisory_reference():
    osv, _ = client({"vulns": [ADVISORY]})
    record = osv.get_vulnerabilities("requests", "2.28.0")[0]
    assert record.source_url == "https://nvd.nist.gov/vuln/detail/CVE-2023-32681"


def test_falls_back_to_an_osv_permalink():
    osv, _ = client({"vulns": [{"id": "PYSEC-1", "summary": "x"}]})
    record = osv.get_vulnerabilities("requests", "2.28.0")[0]
    assert record.source_url == "https://osv.dev/vulnerability/PYSEC-1"


def test_summary_falls_back_to_first_line_of_details():
    osv, _ = client({"vulns": [{"id": "PYSEC-1", "details": "First line.\nSecond."}]})
    assert osv.get_vulnerabilities("requests", "1.0")[0].summary == "First line."


def test_sends_the_expected_query():
    osv, http = client({"vulns": []})
    osv.get_vulnerabilities("requests", "2.28.0")
    assert http.payloads == [
        {"version": "2.28.0", "package": {"name": "requests", "ecosystem": "PyPI"}}
    ]


def test_clean_version_returns_nothing():
    osv, _ = client({"vulns": []})
    assert osv.get_vulnerabilities("requests", "2.32.0") == []


def test_unreachable_service_returns_nothing():
    osv, _ = client(None)
    assert osv.get_vulnerabilities("requests", "2.28.0") == []


def test_entries_without_an_id_are_skipped():
    osv, _ = client({"vulns": [{"summary": "no id"}, ADVISORY]})
    assert len(osv.get_vulnerabilities("requests", "2.28.0")) == 1


def test_results_are_sorted_by_id():
    osv, _ = client({"vulns": [{"id": "PYSEC-9"}, {"id": "GHSA-1"}]})
    ids = [r.vulnerability_id for r in osv.get_vulnerabilities("requests", "1.0")]
    assert ids == ["GHSA-1", "PYSEC-9"]
