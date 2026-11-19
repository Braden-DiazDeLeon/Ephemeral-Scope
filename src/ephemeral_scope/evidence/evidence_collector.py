"""Evidence coordination."""

from __future__ import annotations

import logging

from ephemeral_scope.domain.models import (
    AnalysisWarning,
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
        current, current_warning = self._for_version(
            upgrade.package_name, upgrade.current_version, "current"
        )
        target, target_warning = self._for_version(
            upgrade.package_name, upgrade.target_version, "target"
        )
        notes, notes_warning = self._release_notes(upgrade)

        merged: dict[str, VulnerabilityRecord] = {}
        for record in (*current, *target):
            merged.setdefault(record.vulnerability_id, record)

        warnings = tuple(
            warning
            for warning in (notes_warning, current_warning, target_warning)
            if warning is not None
        )
        return EvidenceBundle(
            release_notes=tuple(notes),
            vulnerabilities=tuple(
                sorted(merged.values(), key=lambda r: r.vulnerability_id)
            ),
            current_vulnerabilities=tuple(current),
            target_vulnerabilities=tuple(target),
            warnings=warnings,
        )

    def _release_notes(
        self, upgrade: DependencyUpgrade
    ) -> tuple[list[ReleaseNoteItem], AnalysisWarning | None]:
        try:
            return self.release_notes_client.get_notes(upgrade), None
        except Exception as exc:
            logger.exception("Release notes unavailable for %s", upgrade.package_name)
            return [], AnalysisWarning(
                "release_notes", f"Release notes unavailable: {exc}"
            )

    def _for_version(
        self, package: str, version: str, role: str
    ) -> tuple[list[VulnerabilityRecord], AnalysisWarning | None]:
        """Advisories affecting one version.

        Kept per version rather than merged: an advisory that affects the
        current version but not the target is fixed *by* the upgrade, and
        collapsing the two sets would make that indistinguishable from one
        the upgrade leaves open.
        """
        try:
            records = self.osv_client.get_vulnerabilities(package, version)
        except Exception as exc:
            logger.exception("Vulnerability lookup failed for %s==%s", package, version)
            return [], AnalysisWarning(
                "osv", f"OSV {role}-version query failed: {exc}"
            )
        return sorted(records, key=lambda r: r.vulnerability_id), None
