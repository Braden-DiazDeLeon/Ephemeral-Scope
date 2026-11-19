"""Evidence coordination."""

from __future__ import annotations

import logging

from ephemeral_scope.domain.models import (
    DependencyUpgrade,
    EvidenceBundle,
    ReleaseNoteItem,
    VulnerabilityRecord,
)
from ephemeral_scope.evidence.osv_client import OSVClient
from ephemeral_scope.evidence.release_notes_client import ReleaseNotesClient

logger = logging.getLogger(__name__)


class EvidenceCollector:
    """Coordinates release-note and vulnerability providers."""

    def __init__(
        self,
        release_notes_client: ReleaseNotesClient | None = None,
        osv_client: OSVClient | None = None,
    ) -> None:
        self.release_notes_client = release_notes_client or ReleaseNotesClient()
        self.osv_client = osv_client or OSVClient()

    def collect(self, upgrade: DependencyUpgrade) -> EvidenceBundle:
        """Gather everything known about the gap between the two versions.

        Each provider is isolated so that one failing source still leaves the
        rest of the evidence usable.
        """
        current = self._for_version(upgrade.package_name, upgrade.current_version)
        target = self._for_version(upgrade.package_name, upgrade.target_version)

        merged: dict[str, VulnerabilityRecord] = {}
        for record in (*current, *target):
            merged.setdefault(record.vulnerability_id, record)

        return EvidenceBundle(
            release_notes=tuple(self._release_notes(upgrade)),
            vulnerabilities=tuple(
                sorted(merged.values(), key=lambda r: r.vulnerability_id)
            ),
            current_vulnerabilities=tuple(current),
            target_vulnerabilities=tuple(target),
        )

    def _release_notes(self, upgrade: DependencyUpgrade) -> list[ReleaseNoteItem]:
        try:
            return self.release_notes_client.get_notes(upgrade)
        except Exception:
            logger.exception("Release notes unavailable for %s", upgrade.package_name)
            return []

    def _for_version(self, package: str, version: str) -> list[VulnerabilityRecord]:
        """Advisories affecting one version.

        Kept per version rather than merged: an advisory that affects the
        current version but not the target is fixed *by* the upgrade, and
        collapsing the two sets would make that indistinguishable from one
        the upgrade leaves open.
        """
        try:
            records = self.osv_client.get_vulnerabilities(package, version)
        except Exception:
            logger.exception("Vulnerability lookup failed for %s==%s", package, version)
            return []
        return sorted(records, key=lambda r: r.vulnerability_id)
