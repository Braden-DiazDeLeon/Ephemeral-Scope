"""Tests for the migration-risk / upgrade-urgency split.

The headline property is the last class: a vulnerability the upgrade fixes
must never make the upgrade look dangerous.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from ephemeral_scope.domain.enums import (
    ChangeType,
    ReleaseNoteCategory,
    RiskLevel,
    SelectionReason,
    UsageKind,
)
from ephemeral_scope.domain.models import (
    AffectedUsage,
    ApiChange,
    ApiUsage,
    ClassificationDecision,
    ClassifiedChange,
    DependencyUpgrade,
    EvidenceBundle,
    ReleaseNoteItem,
    VulnerabilityRecord,
)
from ephemeral_scope.inference.fact_builder import build_facts
from ephemeral_scope.inference.risk_assessor import RiskAssessor

RULES = Path(__file__).resolve().parents[1] / "src/ephemeral_scope/inference/rules.pl"
SWIPL = shutil.which("swipl")
requires_prolog = pytest.mark.skipif(SWIPL is None, reason="swipl not installed")

UPGRADE = DependencyUpgrade("requests", "2.28.0", "2.32.0")


def affected(symbol: str, change_type: ChangeType) -> AffectedUsage:
    return AffectedUsage(
        usage=ApiUsage(
            package_name=symbol.split(".")[0],
            symbol=symbol,
            file=Path("src/report.py"),
            line=4,
            column=0,
            usage_kind=UsageKind.METHOD_CALL,
        ),
        change=ApiChange(symbol=symbol, change_type=change_type),
    )


def note(
    category: ReleaseNoteCategory | None,
    relevance: float = 0.85,
    model_only: bool = False,
) -> ClassifiedChange:
    reason = (
        SelectionReason.MODEL_SUGGESTION_ONLY
        if model_only
        else SelectionReason.RULE_MODEL_AGREEMENT
    )
    return ClassifiedChange(
        note=ReleaseNoteItem(text="statement", release_version="2.32.0"),
        category=category,
        confidence=0.8,
        relevance_score=relevance,
        decision=ClassificationDecision(
            selected_category=category,
            rule_category=None if model_only else category,
            rule_confidence=0.0 if model_only else 0.5,
            model_category=category,
            model_confidence=0.6,
            agreement=not model_only,
            selection_reason=reason,
        ),
    )


def advisory(identifier: str) -> VulnerabilityRecord:
    return VulnerabilityRecord(vulnerability_id=identifier, summary="x")


@pytest.fixture()
def assessor() -> RiskAssessor:
    return RiskAssessor()


class TestTheDocumentedTable:
    """One test per row of the evidence table in the brief."""

    def test_used_method_removed_is_high_risk_neutral_urgency(self, assessor):
        result = assessor.assess(
            UPGRADE, affected=[affected("requests.get", ChangeType.REMOVED)]
        )

        assert result.migration_risk is RiskLevel.HIGH
        assert result.upgrade_urgency is RiskLevel.LOW

    def test_target_still_vulnerable_is_high_urgency_neutral_risk(self, assessor):
        evidence = EvidenceBundle(
            current_vulnerabilities=(advisory("GHSA-open"),),
            target_vulnerabilities=(advisory("GHSA-open"),),
        )

        result = assessor.assess(UPGRADE, evidence=evidence)

        assert result.upgrade_urgency is RiskLevel.HIGH
        assert result.migration_risk is RiskLevel.LOW

    def test_current_vulnerable_target_fixed_is_high_urgency_neutral_risk(
        self, assessor
    ):
        evidence = EvidenceBundle(current_vulnerabilities=(advisory("GHSA-fixed"),))

        result = assessor.assess(UPGRADE, evidence=evidence)

        assert result.upgrade_urgency is RiskLevel.HIGH
        assert result.migration_risk is RiskLevel.LOW

    def test_relevant_behaviour_change_is_medium_risk(self, assessor):
        result = assessor.assess(
            UPGRADE,
            classified_changes=[note(ReleaseNoteCategory.BEHAVIORAL_CHANGE)],
        )

        assert result.migration_risk is RiskLevel.MEDIUM
        assert result.upgrade_urgency is RiskLevel.LOW

    def test_only_bug_fixes_is_low_risk_and_low_urgency(self, assessor):
        result = assessor.assess(
            UPGRADE, classified_changes=[note(ReleaseNoteCategory.BUG_FIX)]
        )

        assert result.migration_risk is RiskLevel.LOW
        assert result.upgrade_urgency is RiskLevel.LOW


class TestSecurityDoesNotInflateMigrationRisk:
    """The property the whole split exists to guarantee."""

    def test_a_fixed_vulnerability_leaves_a_safe_upgrade_safe(self, assessor):
        evidence = EvidenceBundle(current_vulnerabilities=(advisory("GHSA-fixed"),))

        without = assessor.assess(UPGRADE)
        with_fix = assessor.assess(UPGRADE, evidence=evidence)

        assert with_fix.migration_risk == without.migration_risk
        assert with_fix.upgrade_urgency is RiskLevel.HIGH

    def test_many_advisories_never_raise_migration_risk(self, assessor):
        evidence = EvidenceBundle(
            current_vulnerabilities=tuple(advisory(f"GHSA-{i}") for i in range(20))
        )

        result = assessor.assess(UPGRADE, evidence=evidence)

        assert result.migration_risk is RiskLevel.LOW

    def test_a_security_fix_note_does_not_raise_migration_risk(self, assessor):
        result = assessor.assess(
            UPGRADE, classified_changes=[note(ReleaseNoteCategory.SECURITY_FIX)]
        )

        assert result.migration_risk is RiskLevel.LOW
        assert result.upgrade_urgency is RiskLevel.MEDIUM

    def test_risk_and_urgency_can_both_be_high_independently(self, assessor):
        evidence = EvidenceBundle(current_vulnerabilities=(advisory("GHSA-fixed"),))

        result = assessor.assess(
            UPGRADE,
            affected=[affected("requests.get", ChangeType.REMOVED)],
            evidence=evidence,
        )

        assert result.migration_risk is RiskLevel.HIGH
        assert result.upgrade_urgency is RiskLevel.HIGH


class TestRelevanceAndCorroboration:
    def test_an_irrelevant_breaking_change_does_not_raise_risk(self, assessor):
        result = assessor.assess(
            UPGRADE,
            classified_changes=[
                note(ReleaseNoteCategory.BREAKING_CHANGE, relevance=0.2)
            ],
        )

        assert result.migration_risk is RiskLevel.LOW

    def test_a_model_only_breaking_change_does_not_raise_risk(self, assessor):
        """TF-IDF alone must not create a high-risk finding."""
        result = assessor.assess(
            UPGRADE,
            classified_changes=[
                note(ReleaseNoteCategory.BREAKING_CHANGE, model_only=True)
            ],
        )

        assert result.migration_risk is RiskLevel.LOW

    def test_an_unclassified_note_contributes_nothing(self, assessor):
        result = assessor.assess(UPGRADE, classified_changes=[note(None)])

        assert result.migration_risk is RiskLevel.LOW
        assert result.upgrade_urgency is RiskLevel.LOW


class TestReasons:
    def test_reasons_name_the_rule_and_subject(self, assessor):
        result = assessor.assess(
            UPGRADE, affected=[affected("requests.get", ChangeType.REMOVED)]
        )

        assert result.migration_reasons[0].rule_name == "removed_symbol_in_use"
        assert result.migration_reasons[0].subject == "requests.get"

    def test_only_reasons_at_the_reported_level_are_kept(self, assessor):
        result = assessor.assess(
            UPGRADE,
            affected=[
                affected("requests.get", ChangeType.REMOVED),
                affected("requests.post", ChangeType.DEFAULT_CHANGED),
            ],
        )

        assert result.migration_risk is RiskLevel.HIGH
        assert all(r.level is RiskLevel.HIGH for r in result.migration_reasons)

    def test_no_evidence_yields_low_with_no_reasons(self, assessor):
        result = assessor.assess(UPGRADE)

        assert result.migration_risk is RiskLevel.LOW
        assert result.migration_reasons == ()

    def test_serializes_both_dimensions(self, assessor):
        document = assessor.assess(
            UPGRADE, affected=[affected("requests.get", ChangeType.REMOVED)]
        ).to_dict()

        assert document["migration_risk"] == "high"
        assert document["upgrade_urgency"] == "low"
        assert document["migration_reasons"][0]["rule"] == "removed_symbol_in_use"


@requires_prolog
class TestPythonAndPrologAgree:
    """Two implementations of one policy drift unless something checks."""

    SCENARIOS = [
        ("removed symbol in use", {"affected": [("requests.get", ChangeType.REMOVED)]}),
        (
            "default changed in use",
            {"affected": [("requests.get", ChangeType.DEFAULT_CHANGED)]},
        ),
        (
            "signature changed in use",
            {"affected": [("requests.get", ChangeType.SIGNATURE_CHANGED)]},
        ),
        ("fixed vulnerability", {"fixed": ["GHSA-fixed"]}),
        ("target still vulnerable", {"open": ["GHSA-open"]}),
        ("behavioural change", {"notes": [ReleaseNoteCategory.BEHAVIORAL_CHANGE]}),
        ("bug fixes only", {"notes": [ReleaseNoteCategory.BUG_FIX]}),
        ("security fix note", {"notes": [ReleaseNoteCategory.SECURITY_FIX]}),
        ("nothing at all", {}),
        (
            "breakage and a fix together",
            {
                "affected": [("requests.get", ChangeType.REMOVED)],
                "fixed": ["GHSA-fixed"],
            },
        ),
    ]

    def ask_prolog(self, tmp_path: Path, base, name: str) -> tuple[str, str]:
        path = base.write(tmp_path / f"{abs(hash(name))}.pl")
        goal = (
            "migration_risk(M, _), upgrade_urgency(U, _), "
            "format('~w ~w', [M, U])"
        )
        result = subprocess.run(
            [SWIPL, "-q", "-g", f"consult('{RULES}'), consult('{path}'), {goal}",
             "-t", "halt"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        migration, urgency = result.stdout.strip().split()
        return migration, urgency

    @pytest.mark.parametrize("name,spec", SCENARIOS, ids=[s[0] for s in SCENARIOS])
    def test_same_conclusion(self, tmp_path, name, spec):
        affected_usages = [affected(s, c) for s, c in spec.get("affected", [])]
        notes = [note(category) for category in spec.get("notes", [])]
        evidence = EvidenceBundle(
            current_vulnerabilities=tuple(
                advisory(i) for i in (*spec.get("fixed", []), *spec.get("open", []))
            ),
            target_vulnerabilities=tuple(advisory(i) for i in spec.get("open", [])),
        )

        python = RiskAssessor().assess(
            UPGRADE,
            affected=affected_usages,
            classified_changes=notes,
            evidence=evidence,
        )
        base = build_facts(
            UPGRADE,
            affected=affected_usages,
            classified_changes=notes,
            evidence=evidence,
        )
        migration, urgency = self.ask_prolog(tmp_path, base, name)

        assert str(python.migration_risk) == migration
        assert str(python.upgrade_urgency) == urgency
