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
        return EvidenceBundle(
            release_notes=tuple(self._release_notes(upgrade)),
            vulnerabilities=tuple(self._vulnerabilities(upgrade)),
        )

    def _release_notes(self, upgrade: DependencyUpgrade) -> list[ReleaseNoteItem]:
        try:
            return self.release_notes_client.get_notes(upgrade)
        except Exception:
            logger.exception("Release notes unavailable for %s", upgrade.package_name)
            return []

    def _vulnerabilities(
        self, upgrade: DependencyUpgrade
    ) -> list[VulnerabilityRecord]:
        """Query both versions: the current one to show what the upgrade
        fixes, the target to show what it would introduce."""
        found: dict[str, VulnerabilityRecord] = {}
        for version in (upgrade.current_version, upgrade.target_version):
            try:
                records = self.osv_client.get_vulnerabilities(
                    upgrade.package_name, version
                )
            except Exception:
                logger.exception(
                    "Vulnerability lookup failed for %s==%s",
                    upgrade.package_name,
                    version,
                )
                continue
            for record in records:
                found.setdefault(record.vulnerability_id, record)
        return sorted(found.values(), key=lambda r: r.vulnerability_id)
