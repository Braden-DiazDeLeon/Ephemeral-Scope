"""Scoring an upgrade along two independent dimensions.

A Python implementation of the policy in ``rules.pl``. The two exist for
different reasons: the Prolog rules are the readable, auditable statement of
the policy and the thing a reader of the report should be pointed at, while
this module runs without a Prolog interpreter installed, which the web
application cannot assume. ``tests/test_risk_assessor.py`` runs both over
the same facts and fails if they ever disagree.


Only high- and medium-risk rules exist so far, matching ``rules.pl``. An
analysis where nothing fires reports ``low``, so the missing low-risk rules
cost explanations rather than correctness.
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

#: Stable rule names shared with rules.pl, mapped to user-facing prose.
#: A test asserts this covers exactly the rules the Prolog file defines, so
#: renaming a rule in one place fails the build rather than silently
#: producing a finding the report cannot explain.
RULE_EXPLANATIONS: dict[str, str] = {
    "removed_used_api": (
        "Your project calls an API that no longer exists in the target "
        "version. This will raise AttributeError or ImportError at runtime."
    ),
    "changed_used_signature": (
        "Your project calls an API whose signature changed incompatibly. "
        "Existing call sites may raise TypeError."
    ),
    "relevant_breaking_note": (
        "The release notes announce a breaking change that mentions code "
        "your project uses, though no specific call site was identified."
    ),
    "relevant_behavior_change": (
        "The release notes describe a behavioural change closely matching "
        "code your project uses. The call still works but may do something "
        "different."
    ),
    "fixes_known_vulnerability": (
        "The version you are on has a published advisory that the target "
        "version resolves. This is a reason to upgrade, not a risk of "
        "upgrading."
    ),
    "target_remains_vulnerable": (
        "A published advisory still affects the target version. Upgrading "
        "does not resolve it; a later version may be required."
    ),
    "reported_security_fix": (
        "The release notes describe a security fix between these versions."
    ),
}

#: Thresholds mirroring breaking_note_threshold/1 and
#: behavior_note_threshold/1 in rules.pl.
BREAKING_NOTE_THRESHOLD = 0.5
BEHAVIOR_NOTE_THRESHOLD = 0.7

_RANK = {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3}

#: Change types that break a call site the project actually uses. Grouped
#: under one rule name because from a caller's point of view they are the
#: same failure.
INCOMPATIBLE_SIGNATURE_CHANGES = frozenset(
    {
        ChangeType.SIGNATURE_CHANGED,
        ChangeType.PARAMETER_ADDED_REQUIRED,
        ChangeType.PARAMETER_REMOVED,
        ChangeType.PARAMETER_RENAMED,
    }
)


def explain(rule_name: str) -> str:
    """User-facing prose for a rule name, or the name itself if unmapped."""
    return RULE_EXPLANATIONS.get(rule_name, rule_name)


def _highest(reasons: Sequence[RiskReason]) -> RiskLevel:
    if not reasons:
        return RiskLevel.LOW
    return max((reason.level for reason in reasons), key=lambda level: _RANK[level])


def _at_level(reasons: Sequence[RiskReason], level: RiskLevel) -> tuple[RiskReason, ...]:
    seen: dict[tuple[str, str], RiskReason] = {}
    for reason in reasons:
        if reason.level is level:
            seen.setdefault((reason.rule_name, reason.subject), reason)
    return tuple(seen.values())


def _corroborated(change: ClassifiedChange) -> bool:
    return not (change.decision is not None and change.decision.is_model_only)


class RiskAssessor:
    """Derives migration risk and upgrade urgency from analysis results."""

    def assess(
        self,
        upgrade: DependencyUpgrade,
        affected: Sequence[AffectedUsage] = (),
        classified_changes: Sequence[ClassifiedChange] = (),
        evidence: EvidenceBundle | None = None,
    ) -> RiskAssessment:
        migration = self._migration_reasons(affected, classified_changes)
        urgency = self._urgency_reasons(classified_changes, evidence)

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
            if change_type is ChangeType.REMOVED:
                reasons.append(
                    RiskReason(RiskLevel.HIGH, "removed_used_api", symbol)
                )
            elif change_type in INCOMPATIBLE_SIGNATURE_CHANGES:
                reasons.append(
                    RiskReason(RiskLevel.HIGH, "changed_used_signature", symbol)
                )

        for identifier, change in _identified(classified_changes):
            if not _corroborated(change):
                continue
            if (
                change.category is ReleaseNoteCategory.BREAKING_CHANGE
                and change.relevance_score >= BREAKING_NOTE_THRESHOLD
            ):
                reasons.append(
                    RiskReason(RiskLevel.MEDIUM, "relevant_breaking_note", identifier)
                )
            elif (
                change.category is ReleaseNoteCategory.BEHAVIORAL_CHANGE
                and change.relevance_score >= BEHAVIOR_NOTE_THRESHOLD
            ):
                reasons.append(
                    RiskReason(
                        RiskLevel.MEDIUM, "relevant_behavior_change", identifier
                    )
                )

        return reasons

    def _urgency_reasons(
        self,
        classified_changes: Sequence[ClassifiedChange],
        evidence: EvidenceBundle | None,
    ) -> list[RiskReason]:
        reasons: list[RiskReason] = []

        if evidence is not None:
            for record in evidence.fixed_by_upgrade:
                reasons.append(
                    RiskReason(
                        RiskLevel.HIGH,
                        "fixes_known_vulnerability",
                        record.vulnerability_id,
                    )
                )
            for record in evidence.target_vulnerabilities:
                reasons.append(
                    RiskReason(
                        RiskLevel.HIGH,
                        "target_remains_vulnerable",
                        record.vulnerability_id,
                    )
                )

        for identifier, change in _identified(classified_changes):
            if (
                change.category is ReleaseNoteCategory.SECURITY_FIX
                and _corroborated(change)
            ):
                reasons.append(
                    RiskReason(RiskLevel.MEDIUM, "reported_security_fix", identifier)
                )

        return reasons


def _identified(
    changes: Sequence[ClassifiedChange],
) -> list[tuple[str, ClassifiedChange]]:
    """Pair each change with the identifier fact_builder would give it."""
    return [(f"change_{index}", change) for index, change in enumerate(changes, 1)]
