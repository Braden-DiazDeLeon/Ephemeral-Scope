"""Tests for Prolog fact generation."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from ephemeral_scope.domain.enums import (
    ChangeType,
    ReleaseNoteCategory,
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
    # Aliased: pytest tries to collect any module-level name matching Test*.
    TestReference as CoveringTest,
    VulnerabilityRecord,
)
from ephemeral_scope.inference.fact_builder import (
    FactBuilder,
    atom,
    build_facts,
    fact,
)

RULES = Path(__file__).resolve().parents[1] / "src/ephemeral_scope/inference/rules.pl"
SWIPL = shutil.which("swipl")
requires_prolog = pytest.mark.skipif(SWIPL is None, reason="swipl not installed")


def usage(symbol: str, file: str = "src/report.py", line: int = 4) -> ApiUsage:
    return ApiUsage(
        package_name=symbol.split(".")[0],
        symbol=symbol,
        file=Path(file),
        line=line,
        column=0,
        usage_kind=UsageKind.METHOD_CALL,
    )


def change(symbol: str, change_type: ChangeType = ChangeType.REMOVED) -> ApiChange:
    return ApiChange(symbol=symbol, change_type=change_type)


def classified(
    text: str,
    category: ReleaseNoteCategory | None = ReleaseNoteCategory.BREAKING_CHANGE,
    relevance: float = 0.85,
    agreement: bool = True,
    reason: SelectionReason = SelectionReason.RULE_MODEL_AGREEMENT,
) -> ClassifiedChange:
    return ClassifiedChange(
        note=ReleaseNoteItem(text=text, release_version="2.0.0"),
        category=category,
        confidence=0.8,
        relevance_score=relevance,
        decision=ClassificationDecision(
            selected_category=category,
            rule_category=category,
            rule_confidence=0.5,
            model_category=category if agreement else None,
            model_confidence=0.6,
            agreement=agreement,
            selection_reason=reason,
        ),
    )


UPGRADE = DependencyUpgrade("requests", "2.28.0", "2.32.0")


class TestAtomQuoting:
    def test_lowercase_identifier_needs_no_quotes(self):
        assert atom("removed") == "removed"
        assert atom("breaking_change") == "breaking_change"

    def test_dotted_symbol_is_quoted(self):
        assert atom("pandas.DataFrame.append") == "'pandas.DataFrame.append'"

    def test_leading_capital_is_quoted_so_it_is_not_a_variable(self):
        """Unquoted `Session` would be a Prolog variable, not an atom."""
        assert atom("Session") == "'Session'"

    def test_single_quote_is_escaped(self):
        assert atom("don't") == r"'don\'t'"

    def test_backslash_is_escaped(self):
        assert atom("C:\\path") == r"'C:\\path'"

    def test_backslash_before_quote_does_not_break_out(self):
        """A naive escaper turns `\\'` into an unterminated atom."""
        assert atom("a\\'b") == r"'a\\\'b'"

    def test_newline_and_tab_become_escapes(self):
        assert atom("a\nb\tc") == r"'a\nb\tc'"

    def test_control_characters_use_hex_escapes(self):
        assert atom("a\x01b") == r"'a\x1\b'"

    def test_empty_string_is_the_empty_atom(self):
        assert atom("") == "''"

    def test_none_is_the_empty_atom(self):
        assert atom(None) == "''"

    def test_unicode_survives(self):
        assert atom("café") == "'café'"


class TestFactRendering:
    def test_zero_arity(self):
        assert fact("done") == "done."

    def test_arguments_are_comma_separated(self):
        assert fact("api_change", "'a.b'", "removed") == "api_change('a.b', removed)."


class TestStaticFacts:
    def test_uses_symbol_and_api_change(self):
        base = build_facts(
            DependencyUpgrade("pandas", "1.5.3", "2.0.0"),
            usages=[usage("pandas.DataFrame.append")],
            api_changes=[change("pandas.DataFrame.append")],
        )

        assert "uses_symbol(project, 'pandas.DataFrame.append')." in base.facts
        assert "api_change('pandas.DataFrame.append', removed)." in base.facts

    def test_affected_usage_matches_the_documented_shape(self):
        affected = AffectedUsage(
            usage=usage("pandas.DataFrame.append"),
            change=change("pandas.DataFrame.append"),
        )

        base = build_facts(UPGRADE, affected=[affected])

        assert (
            "affected_usage('src/report.py', 4, 'pandas.DataFrame.append', removed)."
            in base.facts
        )

    def test_test_covers(self):
        reference = CoveringTest(
            test_file=Path("tests/test_report.py"), source_file=Path("src/report.py")
        )

        base = build_facts(UPGRADE, test_references=[reference])

        assert "test_covers('tests/test_report.py', 'src/report.py')." in base.facts

    def test_facts_are_deduplicated(self):
        base = build_facts(
            UPGRADE, usages=[usage("requests.get"), usage("requests.get")]
        )

        assert base.facts.count("uses_symbol(project, 'requests.get').") == 1


class TestClassifiedChangeFacts:
    def test_prose_never_reaches_prolog(self):
        """The whole reason identifiers exist."""
        text = "Removed `DataFrame.append`; use pd.concat -- it's faster.\nSee docs."

        base = build_facts(UPGRADE, classified_changes=[classified(text)])

        assert all("pd.concat" not in clause for clause in base.facts)
        assert base.notes["change_1"] == text

    def test_identified_facts_match_the_documented_shape(self):
        base = build_facts(UPGRADE, classified_changes=[classified("x")])

        assert "release_change(change_1, breaking_change)." in base.facts
        assert "release_relevance(change_1, 0.8500)." in base.facts
        assert "classifier_agreement(change_1)." in base.facts

    def test_identifiers_increment(self):
        base = build_facts(
            UPGRADE, classified_changes=[classified("a"), classified("b")]
        )

        assert "release_change(change_1, breaking_change)." in base.facts
        assert "release_change(change_2, breaking_change)." in base.facts
        assert set(base.notes) == {"change_1", "change_2"}

    def test_disagreement_emits_no_agreement_fact(self):
        base = build_facts(
            UPGRADE,
            classified_changes=[
                classified(
                    "x",
                    agreement=False,
                    reason=SelectionReason.RULE_PREFERRED_OVER_MODEL,
                )
            ],
        )

        assert "classifier_agreement(change_1)." not in base.facts
        assert (
            "classification_source(change_1, rule_preferred_over_model)." in base.facts
        )

    def test_model_only_is_flagged_so_rules_can_discount_it(self):
        base = build_facts(
            UPGRADE,
            classified_changes=[
                classified(
                    "x",
                    agreement=False,
                    reason=SelectionReason.MODEL_SUGGESTION_ONLY,
                )
            ],
        )

        assert "model_only(change_1)." in base.facts

    def test_unclassified_is_not_recorded_as_irrelevant(self):
        base = build_facts(
            UPGRADE,
            classified_changes=[
                classified("x", category=None, reason=SelectionReason.NO_EVIDENCE)
            ],
        )

        assert "release_unclassified(change_1)." in base.facts
        assert "release_change(change_1, irrelevant)." not in base.facts


class TestVulnerabilityStatus:
    def advisory(self, identifier: str) -> VulnerabilityRecord:
        return VulnerabilityRecord(vulnerability_id=identifier, summary="x")

    def test_fixed_by_upgrade_emits_both_predicates(self):
        evidence = EvidenceBundle(
            current_vulnerabilities=(self.advisory("GHSA-j8r2-6x86-q33q"),),
            target_vulnerabilities=(),
        )

        base = build_facts(UPGRADE, evidence=evidence)

        assert (
            "vulnerable_version(requests, '2.28.0', 'GHSA-j8r2-6x86-q33q')."
            in base.facts
        )
        assert (
            "fixed_version(requests, '2.32.0', 'GHSA-j8r2-6x86-q33q')." in base.facts
        )

    def test_target_still_vulnerable_is_not_reported_as_fixed(self):
        advisory = self.advisory("GHSA-still-open")
        evidence = EvidenceBundle(
            current_vulnerabilities=(advisory,), target_vulnerabilities=(advisory,)
        )

        base = build_facts(UPGRADE, evidence=evidence)

        assert "vulnerable_version(requests, '2.32.0', 'GHSA-still-open')." in base.facts
        assert not any(clause.startswith("fixed_version") for clause in base.facts)

    def test_the_two_versions_stay_distinguishable(self):
        evidence = EvidenceBundle(
            current_vulnerabilities=(self.advisory("GHSA-old"),),
            target_vulnerabilities=(self.advisory("GHSA-new"),),
        )

        base = build_facts(UPGRADE, evidence=evidence)

        assert "vulnerable_version(requests, '2.28.0', 'GHSA-old')." in base.facts
        assert "vulnerable_version(requests, '2.32.0', 'GHSA-new')." in base.facts
        assert "fixed_version(requests, '2.32.0', 'GHSA-old')." in base.facts


class TestEmptyEvidence:
    def test_empty_analysis_still_produces_a_valid_file(self):
        base = build_facts(UPGRADE)

        text = base.to_prolog()

        assert text.endswith("\n")
        assert "upgrade(requests, '2.28.0', '2.32.0')." in text

    def test_no_facts_at_all(self):
        text = FactBuilder().build().to_prolog()

        assert text.strip().startswith("%%")

    def test_empty_evidence_bundle_adds_nothing(self):
        base = build_facts(UPGRADE, evidence=EvidenceBundle())

        assert not any(clause.startswith("vulnerable_version") for clause in base.facts)


class TestPrologOutput:
    def test_dynamic_declarations_cover_every_predicate(self):
        base = build_facts(UPGRADE, usages=[usage("requests.get")])

        text = base.to_prolog()

        assert ":- dynamic uses_symbol/2." in text
        assert ":- dynamic upgrade/3." in text

    def test_arity_counts_ignore_commas_inside_atoms(self):
        """`atom('a, b')` is one argument, not two."""
        builder = FactBuilder()
        builder._emit(fact("note", atom("a, b"), atom("c")))

        assert ":- dynamic note/2." in builder.build().to_prolog()

    def test_write_creates_parent_directories(self, tmp_path):
        destination = tmp_path / "nested" / "facts.pl"

        build_facts(UPGRADE).write(destination)

        assert destination.exists()


@requires_prolog
class TestGeneratedFileLoadsInProlog:
    """The claim "a valid .pl fact file" checked against a real interpreter."""

    def consult(self, tmp_path: Path, base, goal: str = "true") -> str:
        path = base.write(tmp_path / "facts.pl")
        result = subprocess.run(
            [
                SWIPL,
                "-q",
                "-g",
                f"consult('{RULES}'), consult('{path}'), ({goal})",
                "-t",
                "halt",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        assert "ERROR" not in result.stderr, result.stderr
        return result.stdout

    def test_a_full_fact_base_loads(self, tmp_path):
        affected = AffectedUsage(
            usage=usage("pandas.DataFrame.append"),
            change=change("pandas.DataFrame.append"),
        )
        evidence = EvidenceBundle(
            current_vulnerabilities=(
                VulnerabilityRecord(vulnerability_id="GHSA-abc", summary="x"),
            )
        )
        base = build_facts(
            UPGRADE,
            usages=[usage("requests.get")],
            api_changes=[change("requests.get")],
            affected=[affected],
            classified_changes=[classified("Removed it; use `pd.concat`.")],
            evidence=evidence,
            test_references=[
                CoveringTest(Path("tests/test_report.py"), Path("src/report.py"))
            ],
        )

        self.consult(tmp_path, base)

    def test_empty_fact_base_loads(self, tmp_path):
        self.consult(tmp_path, build_facts(UPGRADE))

    def test_hostile_strings_do_not_break_the_file(self, tmp_path):
        """Quotes, backslashes and newlines in a path or symbol."""
        base = build_facts(
            DependencyUpgrade("pkg", "1.0", "2.0"),
            usages=[usage("pkg.don't", file="src/it's a \\ dir/x.py")],
        )

        self.consult(tmp_path, base)

    def test_a_removed_symbol_in_use_infers_high_migration_risk(self, tmp_path):
        affected = AffectedUsage(
            usage=usage("pandas.DataFrame.append"),
            change=change("pandas.DataFrame.append"),
        )
        base = build_facts(UPGRADE, affected=[affected])

        output = self.consult(
            tmp_path, base, "migration_risk_level(L), format('~w', [L])"
        )

        assert output.strip() == "high"

    def test_the_rule_name_reaches_the_terminal(self, tmp_path):
        affected = AffectedUsage(
            usage=usage("pandas.DataFrame.append"),
            change=change("pandas.DataFrame.append"),
        )
        base = build_facts(UPGRADE, affected=[affected])

        output = self.consult(
            tmp_path,
            base,
            "forall(migration_risk(L, R, S), format('~w ~w ~w~n', [L, R, S]))",
        )

        assert output.strip() == "high removed_used_api pandas.DataFrame.append"

    def test_report_runs_against_an_empty_analysis(self, tmp_path):
        output = self.consult(tmp_path, build_facts(UPGRADE), "report")

        assert "migration risk:  low" in output
        assert "upgrade urgency: low" in output
