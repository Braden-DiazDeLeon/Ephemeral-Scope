"""Tests for the final report assembly.

Two things here are worth more than the rest: that overall risk is the
maximum migration finding and nothing else, and that the migration actions
say something true and specific rather than restating the finding.
"""

from __future__ import annotations

import shutil
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

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
    RiskFinding,
    UpgradeReport,
    VulnerabilityRecord,
)
from ephemeral_scope.domain.models import TestReference as CoveringTest
from ephemeral_scope.reporting.report_builder import (
    ReportBuilder,
    migration_actions,
    overall_risk,
)

requires_prolog = pytest.mark.skipif(
    shutil.which("swipl") is None, reason="SWI-Prolog not installed"
)

UPGRADE = DependencyUpgrade("requests", "2.28.0", "2.32.0")
PANDAS = DependencyUpgrade("pandas", "1.5.3", "2.0.0")


def usage(symbol: str, file: str = "src/client.py", line: int = 12) -> ApiUsage:
    return ApiUsage(
        package_name=symbol.split(".")[0],
        symbol=symbol,
        file=Path(file),
        line=line,
        column=0,
        usage_kind=UsageKind.METHOD_CALL,
    )


def affected(
    symbol: str,
    change_type: ChangeType = ChangeType.REMOVED,
    file: str = "src/client.py",
    line: int = 12,
    details: str | None = None,
) -> AffectedUsage:
    return AffectedUsage(
        usage=usage(symbol, file, line),
        change=ApiChange(symbol=symbol, change_type=change_type, details=details),
    )


def note(
    text: str,
    category: ReleaseNoteCategory = ReleaseNoteCategory.BREAKING_CHANGE,
    matched: tuple[str, ...] = (),
    relevance: float = 0.85,
    agreement: bool = True,
    model_category: ReleaseNoteCategory | None = None,
) -> ClassifiedChange:
    model = model_category if model_category is not None else category
    return ClassifiedChange(
        note=ReleaseNoteItem(text=text, release_version="2.0.0"),
        category=category,
        confidence=0.8,
        matched_project_symbols=matched,
        relevance_score=relevance,
        decision=ClassificationDecision(
            selected_category=category,
            rule_category=category,
            rule_confidence=0.5,
            model_category=model,
            model_confidence=0.6,
            agreement=agreement,
            selection_reason=(
                SelectionReason.RULE_MODEL_AGREEMENT
                if agreement
                else SelectionReason.RULE_PREFERRED_OVER_MODEL
            ),
        ),
    )


def advisory(
    identifier: str, fixed: tuple[str, ...] = ()
) -> VulnerabilityRecord:
    return VulnerabilityRecord(
        vulnerability_id=identifier, summary="x", fixed_versions=fixed
    )


def finding(rule: str, level: RiskLevel) -> RiskFinding:
    return RiskFinding(risk_level=level, reason="because", rule_name=rule)


@pytest.fixture()
def builder() -> ReportBuilder:
    return ReportBuilder()


class TestOverallRisk:
    """HIGH > MEDIUM > LOW > UNKNOWN, over migration findings only."""

    def test_the_maximum_finding_wins(self):
        level = overall_risk(
            [
                finding("relevant_behavior_change", RiskLevel.MEDIUM),
                finding("removed_used_api", RiskLevel.HIGH),
                finding("relevant_breaking_note", RiskLevel.MEDIUM),
            ]
        )

        assert level is RiskLevel.HIGH

    def test_medium_beats_low(self):
        level = overall_risk(
            [
                finding("relevant_breaking_note", RiskLevel.LOW),
                finding("relevant_behavior_change", RiskLevel.MEDIUM),
            ]
        )

        assert level is RiskLevel.MEDIUM

    def test_unknown_never_outranks_a_derived_level(self):
        level = overall_risk(
            [
                finding("removed_used_api", RiskLevel.UNKNOWN),
                finding("relevant_breaking_note", RiskLevel.LOW),
            ]
        )

        assert level is RiskLevel.LOW

    def test_an_analysis_that_found_nothing_is_low(self):
        assert overall_risk([], analysed=True) is RiskLevel.LOW

    def test_an_analysis_that_could_not_look_is_unknown(self):
        """"Nothing found" and "nothing checked" are different claims."""
        assert overall_risk([], analysed=False) is RiskLevel.UNKNOWN

    def test_urgency_findings_do_not_raise_migration_risk(self):
        """The headline property: a security fix is not an incompatibility."""
        level = overall_risk(
            [
                finding("fixes_known_vulnerability", RiskLevel.HIGH),
                finding("target_remains_vulnerable", RiskLevel.HIGH),
            ]
        )

        assert level is RiskLevel.LOW


class TestMigrationActions:
    """The examples from the brief, each produced from real evidence."""

    def test_a_removed_symbol_names_its_replacement(self):
        actions = migration_actions(
            PANDAS,
            affected=[affected("pandas.DataFrame.append")],
            classified_changes=[
                note(
                    "Removed `DataFrame.append`; use `pandas.concat` instead.",
                    matched=("pandas.DataFrame.append",),
                )
            ],
        )

        assert "Replace pandas.DataFrame.append with pandas.concat." in actions

    def test_a_removed_symbol_without_a_named_replacement_names_the_site(self):
        actions = migration_actions(
            PANDAS, affected=[affected("pandas.DataFrame.append", line=4)]
        )

        assert actions == (
            "Replace pandas.DataFrame.append in src/client.py:4; it no longer "
            "exists in pandas 2.0.0.",
        )

    def test_a_vague_replacement_phrase_is_not_mistaken_for_a_symbol(self):
        """"use the new API instead" must not yield "Replace X with the"."""
        actions = migration_actions(
            PANDAS,
            affected=[affected("pandas.DataFrame.append")],
            classified_changes=[
                note(
                    "Removed DataFrame.append; use the new API instead.",
                    matched=("pandas.DataFrame.append",),
                )
            ],
        )

        assert all("with the" not in action for action in actions)
        assert any("no longer exists" in action for action in actions)

    def test_a_changed_default_is_quoted_back_with_its_old_value(self):
        actions = migration_actions(
            UPGRADE,
            affected=[
                affected(
                    "requests.request",
                    ChangeType.DEFAULT_CHANGED,
                    details="'verify' default False -> True",
                )
            ],
        )

        assert actions == (
            "Review verify=False usage in src/client.py; the default is now True.",
        )

    def test_a_test_is_recommended_with_its_reason(self):
        actions = migration_actions(
            UPGRADE,
            affected=[affected("requests.get", file="src/client.py")],
            test_references=[
                CoveringTest(
                    test_file=Path("tests/test_client.py"),
                    source_file=Path("src/client.py"),
                )
            ],
        )

        assert (
            "Run tests/test_client.py because it exercises src/client.py."
            in actions
        )

    def test_a_fixed_advisory_becomes_a_reason_to_upgrade(self):
        actions = migration_actions(
            UPGRADE,
            evidence=EvidenceBundle(
                current_vulnerabilities=(advisory("GHSA-9wx4-h78v-vm56"),)
            ),
        )

        assert actions == (
            "Upgrade to requests 2.32.0 to address GHSA-9wx4-h78v-vm56.",
        )

    def test_several_fixed_advisories_read_as_a_sentence(self):
        actions = migration_actions(
            UPGRADE,
            evidence=EvidenceBundle(
                current_vulnerabilities=(
                    advisory("GHSA-a"),
                    advisory("GHSA-b"),
                    advisory("GHSA-c"),
                )
            ),
        )

        assert "address GHSA-a, GHSA-b and GHSA-c." in actions[0]

    def test_an_unfixed_advisory_says_so_rather_than_claiming_a_fix(self):
        actions = migration_actions(
            UPGRADE,
            evidence=EvidenceBundle(
                current_vulnerabilities=(advisory("GHSA-open"),),
                target_vulnerabilities=(advisory("GHSA-open", fixed=("2.33.0",)),),
            ),
        )

        assert actions == (
            "requests 2.32.0 is still affected by GHSA-open. "
            "Upgrade to 2.33.0 or later.",
        )

    def test_a_test_for_an_untouched_file_is_not_recommended(self):
        actions = migration_actions(
            UPGRADE,
            affected=[affected("requests.get", file="src/client.py")],
            test_references=[
                CoveringTest(
                    test_file=Path("tests/test_other.py"),
                    source_file=Path("src/other.py"),
                )
            ],
        )

        assert actions == (
            "Replace requests.get in src/client.py:12; it no longer exists "
            "in requests 2.32.0.",
        )

    def test_the_same_symbol_twice_yields_one_action(self):
        actions = migration_actions(
            PANDAS,
            affected=[
                affected("pandas.DataFrame.append"),
                affected("pandas.DataFrame.append"),
            ],
        )

        assert len(actions) == 1

    def test_breakage_is_listed_before_security_and_tests(self):
        actions = migration_actions(
            UPGRADE,
            affected=[affected("requests.get", file="src/client.py")],
            evidence=EvidenceBundle(current_vulnerabilities=(advisory("GHSA-1"),)),
            test_references=[
                CoveringTest(
                    test_file=Path("tests/test_client.py"),
                    source_file=Path("src/client.py"),
                )
            ],
        )

        assert actions[0].startswith("Replace")
        assert actions[1].startswith("Upgrade to")
        assert actions[2].startswith("Run")

    def test_an_unrelated_note_does_not_rewrite_a_call_site(self):
        """A replacement is only applied to the symbol the note matched."""
        actions = migration_actions(
            PANDAS,
            affected=[affected("pandas.read_csv")],
            classified_changes=[
                note(
                    "Removed `DataFrame.append`; use `pandas.concat` instead.",
                    matched=("pandas.DataFrame.append",),
                )
            ],
        )

        assert all("pandas.concat" not in action for action in actions)

    def test_a_bug_fix_note_is_not_read_for_replacements(self):
        actions = migration_actions(
            PANDAS,
            affected=[affected("pandas.DataFrame.append")],
            classified_changes=[
                note(
                    "Fixed a typo; use `pandas.concat` instead.",
                    category=ReleaseNoteCategory.BUG_FIX,
                    matched=("pandas.DataFrame.append",),
                )
            ],
        )

        assert all("with pandas.concat" not in action for action in actions)

    def test_nothing_to_do_produces_no_actions(self):
        assert migration_actions(UPGRADE) == ()


class TestBuiltReport:
    """Requirement: one complete UpgradeReport, no web API involved."""

    def report(self, builder, **kwargs) -> UpgradeReport:
        with patch("shutil.which", return_value=None):
            return builder.build(UPGRADE, **kwargs)

    def test_every_section_is_carried_through(self, builder):
        report = self.report(
            builder,
            usages=[usage("requests.get")],
            api_changes=[ApiChange(symbol="requests.get", change_type=ChangeType.REMOVED)],
            affected=[affected("requests.get")],
            classified_changes=[note("Removed `get`.")],
            evidence=EvidenceBundle(current_vulnerabilities=(advisory("GHSA-1"),)),
            test_references=[
                CoveringTest(
                    test_file=Path("tests/test_client.py"),
                    source_file=Path("src/client.py"),
                )
            ],
        )

        assert report.upgrade == UPGRADE
        assert len(report.usages) == 1
        assert len(report.api_changes) == 1
        assert len(report.affected_usages) == 1
        assert len(report.classified_changes) == 1
        assert len(report.vulnerabilities) == 1
        assert report.findings
        assert report.recommended_tests == ("tests/test_client.py",)
        assert report.migration_actions

    def test_overall_risk_matches_the_assessment(self, builder):
        report = self.report(builder, affected=[affected("requests.get")])

        assert report.overall_risk is RiskLevel.HIGH
        assert report.overall_risk == report.assessment.migration_risk

    def test_the_two_dimensions_stay_separate(self, builder):
        report = self.report(
            builder,
            evidence=EvidenceBundle(current_vulnerabilities=(advisory("GHSA-1"),)),
        )

        assert report.overall_risk is RiskLevel.LOW
        assert report.assessment.upgrade_urgency is RiskLevel.HIGH

    def test_an_empty_analysis_is_unknown_not_low(self, builder):
        report = self.report(builder)

        assert report.overall_risk is RiskLevel.UNKNOWN

    def test_affected_files_are_listed(self, builder):
        report = self.report(
            builder,
            affected=[
                affected("requests.get", file="src/b.py"),
                affected("requests.post", file="src/a.py"),
            ],
        )

        assert report.affected_files == (Path("src/a.py"), Path("src/b.py"))

    def test_classifier_disagreements_are_visible(self, builder):
        report = self.report(
            builder,
            classified_changes=[
                note("Removed `get`.", agreement=True),
                note(
                    "Changed the retry behaviour.",
                    category=ReleaseNoteCategory.BEHAVIORAL_CHANGE,
                    model_category=ReleaseNoteCategory.BUG_FIX,
                    agreement=False,
                ),
            ],
        )

        assert len(report.classifier_disagreements) == 1
        decision = report.classifier_disagreements[0].decision
        assert decision.rule_category is ReleaseNoteCategory.BEHAVIORAL_CHANGE
        assert decision.model_category is ReleaseNoteCategory.BUG_FIX

    def test_a_statement_only_one_classifier_labelled_is_not_a_disagreement(
        self, builder
    ):
        """Silence is not dissent."""
        only_model = ClassifiedChange(
            note=ReleaseNoteItem(text="x", release_version="2.0.0"),
            category=ReleaseNoteCategory.BUG_FIX,
            confidence=0.6,
            decision=ClassificationDecision(
                selected_category=ReleaseNoteCategory.BUG_FIX,
                rule_category=None,
                rule_confidence=0.0,
                model_category=ReleaseNoteCategory.BUG_FIX,
                model_confidence=0.6,
                agreement=False,
                selection_reason=SelectionReason.MODEL_SUGGESTION_ONLY,
            ),
        )
        report = self.report(builder, classified_changes=[only_model])

        assert report.classifier_disagreements == ()

    def test_fixed_and_remaining_advisories_are_distinguishable(self, builder):
        report = self.report(
            builder,
            evidence=EvidenceBundle(
                current_vulnerabilities=(advisory("GHSA-fixed"), advisory("GHSA-open")),
                target_vulnerabilities=(advisory("GHSA-open"),),
            ),
        )

        assert [v.vulnerability_id for v in report.fixed_vulnerabilities] == [
            "GHSA-fixed"
        ]
        assert [v.vulnerability_id for v in report.remaining_vulnerabilities] == [
            "GHSA-open"
        ]
        assert len(report.vulnerabilities) == 2

    def test_the_engine_is_disclosed(self, builder):
        assert self.report(builder).inference_engine == "python"

    def test_the_report_is_serializable(self, builder):
        report = self.report(
            builder,
            affected=[affected("requests.get")],
            evidence=EvidenceBundle(current_vulnerabilities=(advisory("GHSA-1"),)),
        )
        document = asdict(report)

        assert document["overall_risk"] == RiskLevel.HIGH
        assert document["upgrade"]["package_name"] == "requests"
        assert document["migration_actions"]

    def test_no_network_or_web_layer_is_touched(self, builder):
        """The acceptance criterion, asserted rather than assumed."""
        import socket

        with patch.object(
            socket.socket, "connect", side_effect=AssertionError("network used")
        ):
            report = self.report(builder, affected=[affected("requests.get")])

        assert report.overall_risk is RiskLevel.HIGH


@requires_prolog
@pytest.mark.integration
class TestThroughProlog:
    def test_the_report_records_that_prolog_ran(self):
        report = ReportBuilder().build(UPGRADE, affected=[affected("requests.get")])

        assert report.inference_engine == "prolog"
        assert report.overall_risk is RiskLevel.HIGH

    def test_both_engines_produce_the_same_report(self):
        arguments = {
            "affected": [affected("requests.get")],
            "classified_changes": [note("Removed `get`.")],
            "evidence": EvidenceBundle(
                current_vulnerabilities=(advisory("GHSA-1"),)
            ),
            "test_references": [
                CoveringTest(
                    test_file=Path("tests/test_client.py"),
                    source_file=Path("src/client.py"),
                )
            ],
        }
        through_prolog = ReportBuilder().build(UPGRADE, **arguments)
        with patch("shutil.which", return_value=None):
            through_python = ReportBuilder().build(UPGRADE, **arguments)

        assert through_prolog.overall_risk == through_python.overall_risk
        assert (
            through_prolog.assessment.upgrade_urgency
            == through_python.assessment.upgrade_urgency
        )
        assert through_prolog.migration_actions == through_python.migration_actions
        assert through_prolog.recommended_tests == through_python.recommended_tests
