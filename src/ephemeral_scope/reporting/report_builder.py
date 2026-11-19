"""Assembling the final UpgradeReport.

Every earlier stage answers one narrow question: which symbols does the
project use, what changed between the two versions, what do the release
notes say, which advisories apply, what do the rules conclude. 

The builder runs standalone.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from packaging.version import InvalidVersion, Version

from ephemeral_scope.domain.enums import ChangeType, ReleaseNoteCategory, RiskLevel
from ephemeral_scope.domain.models import (
    AffectedUsage,
    ApiChange,
    ApiUsage,
    ClassifiedChange,
    DependencyUpgrade,
    EvidenceBundle,
    RiskFinding,
    TestReference,
    UpgradeReport,
    VulnerabilityRecord,
)
from ephemeral_scope.inference.prolog_risk_engine import (
    InferenceResult,
    PrologRiskEngine,
    infer,
)

#: Change types that mean "this call site will not work as written".
BREAKING_CHANGES = frozenset(
    {
        ChangeType.REMOVED,
        ChangeType.SIGNATURE_CHANGED,
        ChangeType.PARAMETER_ADDED_REQUIRED,
        ChangeType.PARAMETER_REMOVED,
        ChangeType.PARAMETER_RENAMED,
    }
)

#: Phrasings release notes use to name a replacement. Only a backticked or
#: dotted name is accepted as the answer, so a sentence such as "use the new
#: API instead" yields nothing rather than the word "the".
_REPLACEMENT_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"use\s+`([\w.]+)`\s*(?:\(\))?\s*instead",
        r"replaced\s+(?:by|with)\s+`([\w.]+)`",
        r"in\s+fav(?:our|or)\s+of\s+`([\w.]+)`",
        r"switch\s+to\s+`([\w.]+)`",
        r"migrate\s+to\s+`([\w.]+)`",
    )
)

#: api_comparator writes the parameter name into ApiChange.details, e.g.
#: "'verify' default False -> True". Parsed rather than re-derived from the
#: signatures; if the wording ever changes these simply find nothing and the
#: action falls back to its generic form.
_DEFAULT_CHANGE = re.compile(r"'(\w+)'\s+default\s+(.+?)\s*->\s*(.+)$")
_NAMED_PARAMETER = re.compile(r"'(\w+)'")


class ReportBuilder:
    """Combines every analysis stage into one UpgradeReport."""

    def __init__(self, engine: PrologRiskEngine | None = None) -> None:
        self.engine = engine

    def build(
        self,
        upgrade: DependencyUpgrade,
        usages: Sequence[ApiUsage] = (),
        api_changes: Sequence[ApiChange] = (),
        affected: Sequence[AffectedUsage] = (),
        classified_changes: Sequence[ClassifiedChange] = (),
        evidence: EvidenceBundle | None = None,
        test_references: Sequence[TestReference] = (),
        inference: InferenceResult | None = None,
    ) -> UpgradeReport:
        """Produce the report.

        ``inference`` lets a caller supply findings it already computed;
        otherwise the rules are run here.
        """
        evidence = evidence or EvidenceBundle()

        if inference is None:
            inference = infer(
                upgrade,
                usages=usages,
                api_changes=api_changes,
                affected=affected,
                classified_changes=classified_changes,
                evidence=evidence,
                test_references=test_references,
                engine=self.engine,
            )

        overall = overall_risk(
            inference.findings,
            analysed=_analysis_had_input(api_changes, classified_changes, evidence),
        )

        return UpgradeReport(
            upgrade=upgrade,
            overall_risk=overall,
            assessment=inference.assessment,
            usages=tuple(usages),
            api_changes=tuple(api_changes),
            affected_usages=tuple(affected),
            classified_changes=tuple(classified_changes),
            vulnerabilities=_all_vulnerabilities(evidence),
            evidence=evidence,
            findings=inference.findings,
            recommended_tests=inference.recommended_tests,
            migration_actions=migration_actions(
                upgrade,
                affected=affected,
                classified_changes=classified_changes,
                evidence=evidence,
                test_references=test_references,
            ),
            inference_engine=inference.engine,
        )


def overall_risk(findings: Iterable[RiskFinding], analysed: bool = True) -> RiskLevel:
    """The most severe migration finding: HIGH > MEDIUM > LOW > UNKNOWN.

    Only migration findings count. Urgency findings describe why the
    upgrade is worth doing, and letting them raise the overall risk would
    report a security fix as a hazard.

    ``analysed`` is False when no stage produced anything to reason over --
    no API comparison, no release notes, no advisories. That is reported as
    UNKNOWN rather than LOW, because "we found no problems" and "we were
    unable to look" are different claims and only one of them is reassuring.
    """
    levels = [
        finding.risk_level
        for finding in findings
        if finding.rule_name in _MIGRATION_RULES
    ]
    if levels:
        return RiskLevel.highest(levels)
    return RiskLevel.LOW if analysed else RiskLevel.UNKNOWN


_MIGRATION_RULES = frozenset(
    {
        "removed_used_api",
        "changed_used_signature",
        "relevant_breaking_note",
        "relevant_behavior_change",
    }
)


def _analysis_had_input(
    api_changes: Sequence[ApiChange],
    classified_changes: Sequence[ClassifiedChange],
    evidence: EvidenceBundle,
) -> bool:
    return bool(
        api_changes
        or classified_changes
        or evidence.release_notes
        or evidence.current_vulnerabilities
        or evidence.target_vulnerabilities
        or evidence.vulnerabilities
    )


def _all_vulnerabilities(evidence: EvidenceBundle) -> tuple[VulnerabilityRecord, ...]:
    seen: dict[str, VulnerabilityRecord] = {}
    for record in (
        *evidence.vulnerabilities,
        *evidence.current_vulnerabilities,
        *evidence.target_vulnerabilities,
    ):
        seen.setdefault(record.vulnerability_id, record)
    return tuple(seen.values())


def migration_actions(
    upgrade: DependencyUpgrade,
    affected: Sequence[AffectedUsage] = (),
    classified_changes: Sequence[ClassifiedChange] = (),
    evidence: EvidenceBundle | None = None,
    test_references: Sequence[TestReference] = (),
) -> tuple[str, ...]:
    """Turn findings into instructions, most urgent first.

    Ordered breakage, then review, then security, then tests: the first two
    are work the upgrade forces, the third is the argument for doing it,
    and the last is how to check. Deduplicated while preserving that order,
    since one symbol used twice produces the same sentence twice.
    """
    evidence = evidence or EvidenceBundle()
    replacements = _replacements_from(classified_changes)

    actions: list[str] = []
    actions += _breaking_actions(affected, replacements, upgrade)
    actions += _review_actions(affected)
    actions += _security_actions(upgrade, evidence)
    actions += _test_actions(affected, test_references)
    return _dedupe(actions)


def _breaking_actions(
    affected: Sequence[AffectedUsage],
    replacements: dict[str, str],
    upgrade: DependencyUpgrade,
) -> list[str]:
    actions = []
    for item in affected:
        change_type = item.change.change_type
        if change_type not in BREAKING_CHANGES:
            continue

        symbol = item.usage.symbol
        location = _location(item)

        if change_type is ChangeType.REMOVED:
            replacement = _replacement_for(symbol, replacements)
            if replacement:
                actions.append(f"Replace {symbol} with {replacement}.")
            else:
                actions.append(
                    f"Replace {symbol} in {location}; it no longer exists in "
                    f"{upgrade.package_name} {upgrade.target_version}."
                )
        elif change_type is ChangeType.PARAMETER_RENAMED:
            detail = item.change.details
            renamed = f" ({detail})" if detail else ""
            actions.append(
                f"Update the call to {symbol} in {location}; "
                f"a parameter was renamed{renamed}."
            )
        else:
            parameter = _named_parameter(item.change)
            if parameter:
                actions.append(
                    f"Update the call to {symbol} in {location}; "
                    f"the {parameter} parameter changed."
                )
            else:
                actions.append(
                    f"Update the call to {symbol} in {location}; "
                    f"its signature is no longer compatible."
                )
    return actions


def _review_actions(affected: Sequence[AffectedUsage]) -> list[str]:
    """Changes that still run but may behave differently."""
    actions = []
    for item in affected:
        change = item.change
        location = _location(item, line=False)

        if change.change_type is ChangeType.DEFAULT_CHANGED:
            match = _DEFAULT_CHANGE.search(change.details or "")
            if match:
                name, old, new = match.groups()
                actions.append(
                    f"Review {name}={old} usage in {location}; "
                    f"the default is now {new}."
                )
            else:
                actions.append(
                    f"Review calls to {item.usage.symbol} in {location}; "
                    f"a parameter default changed."
                )
        elif change.change_type is ChangeType.MOVED:
            actions.append(
                f"Update the import of {item.usage.symbol} in {location}"
                + (f"; {change.details}." if change.details else ".")
            )
        elif change.change_type is ChangeType.RETURN_TYPE_CHANGED:
            actions.append(
                f"Review how the result of {item.usage.symbol} is used in "
                f"{location}; its return type changed"
                + (f" ({change.details})." if change.details else ".")
            )
    return actions


def _security_actions(
    upgrade: DependencyUpgrade, evidence: EvidenceBundle
) -> list[str]:
    actions = []

    fixed = [record.vulnerability_id for record in evidence.fixed_by_upgrade]
    if fixed:
        actions.append(
            f"Upgrade to {upgrade.package_name} {upgrade.target_version} "
            f"to address {_join(fixed)}."
        )

    for record in evidence.target_vulnerabilities:
        later = _later_fix(record, upgrade.target_version)
        suffix = f" Upgrade to {later} or later." if later else ""
        actions.append(
            f"{upgrade.package_name} {upgrade.target_version} is still affected "
            f"by {record.vulnerability_id}.{suffix}"
        )
    return actions


def _test_actions(
    affected: Sequence[AffectedUsage], references: Sequence[TestReference]
) -> list[str]:
    touched = {item.usage.file.as_posix() for item in affected}
    actions = []
    for reference in sorted(references, key=lambda r: r.test_file.as_posix()):
        source = reference.source_file.as_posix()
        if source in touched:
            actions.append(
                f"Run {reference.test_file.as_posix()} because it exercises "
                f"{source}."
            )
    return actions


def _replacements_from(changes: Sequence[ClassifiedChange]) -> dict[str, str]:
    """Replacement symbols named by release notes, keyed by what they replace.

    Only statements the classifiers treated as breaking changes or
    deprecations are read, and only when the note also names a project
    symbol; a general note saying "use `concat`" should not rewrite an
    unrelated call site.
    """
    suggestions: dict[str, str] = {}
    interesting = {
        ReleaseNoteCategory.BREAKING_CHANGE,
        ReleaseNoteCategory.DEPRECATION,
    }

    for change in changes:
        if change.category not in interesting:
            continue
        replacement = _replacement_in(change.note.text)
        if not replacement:
            continue
        for symbol in change.matched_project_symbols:
            suggestions.setdefault(symbol, replacement)
    return suggestions


def _replacement_in(text: str) -> str | None:
    for pattern in _REPLACEMENT_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return None


def _replacement_for(symbol: str, replacements: dict[str, str]) -> str | None:
    if symbol in replacements:
        return replacements[symbol]
    # The note may name the symbol as the comparator knows it
    # (pandas.core.frame.DataFrame.append) rather than as the project
    # writes it (pandas.DataFrame.append).
    tail = symbol.split(".")[-1]
    for known, replacement in replacements.items():
        if known.split(".")[-1] == tail:
            return replacement
    return None


def _named_parameter(change: ApiChange) -> str | None:
    match = _NAMED_PARAMETER.search(change.details or "")
    return match.group(1) if match else None


def _location(item: AffectedUsage, line: bool = True) -> str:
    path = item.usage.file.as_posix()
    return f"{path}:{item.usage.line}" if line else path


def _later_fix(record: VulnerabilityRecord, target: str) -> str | None:
    """The earliest fixed version above the target, if the advisory names one."""
    try:
        current = Version(target)
    except InvalidVersion:
        return None

    candidates = []
    for version in record.fixed_versions:
        try:
            parsed = Version(version)
        except InvalidVersion:
            continue
        if parsed > current:
            candidates.append(parsed)
    return str(min(candidates)) if candidates else None


def _join(items: Sequence[str]) -> str:
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + f" and {items[-1]}"


def _dedupe(actions: Iterable[str]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for action in actions:
        seen.setdefault(action, None)
    return tuple(seen)


__all__ = ["BREAKING_CHANGES", "ReportBuilder", "migration_actions", "overall_risk"]
