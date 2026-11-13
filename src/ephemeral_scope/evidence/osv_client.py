"""OSV vulnerability retrieval."""

from __future__ import annotations

from ephemeral_scope.domain.models import VulnerabilityRecord
from ephemeral_scope.http_cache import HttpCache

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULNERABILITY_URL = "https://osv.dev/vulnerability"


class OSVClient:
    """Retrieves vulnerability records for the old and target versions."""

    def __init__(
        self,
        http: HttpCache | None = None,
        query_url: str = OSV_QUERY_URL,
        ecosystem: str = "PyPI",
    ) -> None:
        self.http = http or HttpCache()
        self.query_url = query_url
        self.ecosystem = ecosystem

    def get_vulnerabilities(
        self, package: str, version: str
    ) -> list[VulnerabilityRecord]:
        """Return advisories affecting one released version of a package."""
        payload = {
            "version": version,
            "package": {"name": package, "ecosystem": self.ecosystem},
        }
        document = self.http.post_json(self.query_url, payload)
        if not isinstance(document, dict):
            return []

        records = [
            _to_record(vuln)
            for vuln in document.get("vulns", [])
            if isinstance(vuln, dict) and vuln.get("id")
        ]
        return sorted(records, key=lambda r: r.vulnerability_id)


def _to_record(vuln: dict) -> VulnerabilityRecord:
    identifier = vuln["id"]
    affected_versions: list[str] = []
    fixed_versions: list[str] = []

    for entry in vuln.get("affected", []):
        if not isinstance(entry, dict):
            continue
        affected_versions.extend(
            v for v in entry.get("versions", []) if isinstance(v, str)
        )
        for range_entry in entry.get("ranges", []):
            if not isinstance(range_entry, dict):
                continue
            for event in range_entry.get("events", []):
                if isinstance(event, dict) and event.get("fixed"):
                    fixed_versions.append(event["fixed"])

    return VulnerabilityRecord(
        vulnerability_id=identifier,
        summary=_summary(vuln),
        affected_versions=tuple(dict.fromkeys(affected_versions)),
        fixed_versions=tuple(dict.fromkeys(fixed_versions)),
        source_url=_source_url(vuln, identifier),
    )


def _summary(vuln: dict) -> str:
    summary = (vuln.get("summary") or "").strip()
    if summary:
        return summary
    # Not every advisory carries a summary; fall back to the first line of
    # the long-form details.
    details = (vuln.get("details") or "").strip()
    return details.splitlines()[0].strip() if details else ""


def _source_url(vuln: dict, identifier: str) -> str:
    references = [r for r in vuln.get("references", []) if isinstance(r, dict)]
    for reference in references:
        if reference.get("type") == "ADVISORY" and reference.get("url"):
            return reference["url"]
    for reference in references:
        if reference.get("url"):
            return reference["url"]
    return f"{OSV_VULNERABILITY_URL}/{identifier}"
