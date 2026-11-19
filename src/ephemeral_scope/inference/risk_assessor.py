"""Scoring an upgrade along two independent dimensions.

A Python implementation of the policy in ``rules.pl``. The two exist for
different reasons: the Prolog rules are the readable, auditable statement of
the policy and the thing a reader of the report should be pointed at, while
this module runs without a Prolog interpreter installed, which the web
application cannot assume. ``tests/test_risk_assessor.py`` runs both over
the same facts and fails if they ever disagree.

The split that matters:

    migration risk     will this upgrade break the project?
    upgrade urgency    how badly does the project need it regardless?

Vulnerabilities only ever move urgency. An advisory the target version
fixes is a reason to upgrade, and letting it raise migration risk would
report a security fix as an incompatibility.
"""

from __future__ import annotations

from collections.abc import Sequence

from ephemeral_scope.domain.enums import ChangeType, ReleaseNoteCategory, RiskLevel
from ephemeral_scope.domain.models import (
    AffectedUsage,
    ClassifiedChange,
    DependencyUpgrade,
    EvidenceBundle,
    RiskAssessment,
    RiskReason,
)
from ephemeral_scope.ml.relevance_matcher import RELEVANCE_THRESHOLD

_RANK = {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3}

#: Change types that break a call site outright when the project uses it.
BREAKING_IN_USE = {
    ChangeType.REMOVED: "removed_symbol_in_use",
    ChangeType.PARAMETER_ADDED_REQUIRED: "incompatible_signature_in_use",
    ChangeType.PARAMETER_REMOVED: "incompatible_signature_in_use",
    ChangeType.PARAMETER_RENAMED: "incompatible_signature_in_use",
}

#: Change types that alter a used call site without necessarily breaking it.
BEHAVIOURAL_IN_USE = {
    ChangeType.SIGNATURE_CHANGED: "signature_changed_in_use",
    ChangeType.MOVED: "moved_symbol_in_use",
}


def _highest(reasons: Sequence[RiskReason]) -> RiskLevel:
    if not reasons:
        return RiskLevel.LOW
    return max((reason.level for reason in reasons), key=lambda level: _RANK[level])


def _at_level(reasons: Sequence[RiskReason], level: RiskLevel) -> tuple[RiskReason, ...]:
    return tuple(reason for reason in reasons if reason.level is level)


class RiskAssessor:
    """Derives migration risk and upgrade urgency from analysis results."""

    def __init__(self, relevance_threshold: float = RELEVANCE_THRESHOLD) -> None:
        self.relevance_threshold = relevance_threshold

    def assess(
        self,
        upgrade: DependencyUpgrade,
        affected: Sequence[AffectedUsage] = (),
        classified_changes: Sequence[ClassifiedChange] = (),
        evidence: EvidenceBundle | None = None,
    ) -> RiskAssessment:
        migration = self._migration_reasons(affected, classified_changes)
        urgency = self._urgency_reasons(upgrade, classified_changes, evidence)

        migration_level = _highest(migration)
        urgency_level = _highest(urgency)

        return RiskAssessment(
            migration_risk=migration_level,
            upgrade_urgency=urgency_level,
            migration_reasons=_at_level(migration, migration_level),
            urgency_reasons=_at_level(urgency, urgency_level),
        )

    def _migration_reasons(
        self,
        affected: Sequence[AffectedUsage],
        classified_changes: Sequence[ClassifiedChange],
    ) -> list[RiskReason]:
        reasons: list[RiskReason] = []

        for item in affected:
            change_type = item.change.change_type
            symbol = item.usage.symbol
            if change_type in BREAKING_IN_USE:
                reasons.append(
                    RiskReason(RiskLevel.HIGH, BREAKING_IN_USE[change_type], symbol)
                )
            elif change_type in BEHAVIOURAL_IN_USE:
                reasons.append(
                    RiskReason(
                        RiskLevel.MEDIUM, BEHAVIOURAL_IN_USE[change_type], symbol
                    )
                )
            elif change_type is ChangeType.DEFAULT_CHANGED:
                reasons.append(
                    RiskReason(RiskLevel.LOW, "default_changed_in_use", symbol)
                )

        for index, change in enumerate(classified_changes, start=1):
            identifier = f"change_{index}"
            relevant = change.relevance_score >= self.relevance_threshold
            corroborated = not (
                change.decision is not None and change.decision.is_model_only
            )

            if change.category is ReleaseNoteCategory.BREAKING_CHANGE:
                if relevant and corroborated:
                    reasons.append(
                        RiskReason(
                            RiskLevel.MEDIUM, "breaking_change_reported", identifier
                        )
                    )
            elif change.category is ReleaseNoteCategory.BEHAVIORAL_CHANGE:
                if relevant and corroborated:
                    reasons.append(
                        RiskReason(
                            RiskLevel.MEDIUM, "behavioral_change_relevant", identifier
                        )
                    )
            elif change.category is ReleaseNoteCategory.DEPRECATION:
                if relevant:
                    reasons.append(
                        RiskReason(RiskLevel.LOW, "deprecation_relevant", identifier)
                    )
            elif change.category is ReleaseNoteCategory.BUG_FIX:
                reasons.append(
                    RiskReason(RiskLevel.LOW, "bug_fixes_only", identifier)
                )

        return reasons

    def _urgency_reasons(
        self,
        upgrade: DependencyUpgrade,
        classified_changes: Sequence[ClassifiedChange],
        evidence: EvidenceBundle | None,
    ) -> list[RiskReason]:
        reasons: list[RiskReason] = []

        if evidence is not None:
            for record in evidence.target_vulnerabilities:
                reasons.append(
                    RiskReason(
                        RiskLevel.HIGH,
                        "target_still_vulnerable",
                        record.vulnerability_id,
                    )
                )
            for record in evidence.fixed_by_upgrade:
                reasons.append(
                    RiskReason(
                        RiskLevel.HIGH,
                        "fixes_known_vulnerability",
                        record.vulnerability_id,
                    )
                )

        for index, change in enumerate(classified_changes, start=1):
            identifier = f"change_{index}"
            corroborated = not (
                change.decision is not None and change.decision.is_model_only
            )
            if change.category is ReleaseNoteCategory.SECURITY_FIX and corroborated:
                reasons.append(
                    RiskReason(RiskLevel.MEDIUM, "security_fix_reported", identifier)
                )
            elif change.category is ReleaseNoteCategory.BUG_FIX:
                reasons.append(
                    RiskReason(RiskLevel.LOW, "bug_fixes_available", identifier)
                )

        return reasons
