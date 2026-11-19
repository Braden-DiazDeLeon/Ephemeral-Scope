"""Tests for the Python/Prolog boundary.

Split deliberately in two. The mocked tests pin down how the engine
behaves when the subprocess misbehaves -- missing binary, timeout, crash,
garbage on stdout -- which is awkward to provoke with a real interpreter.
The integration tests run actual SWI-Prolog and are skipped when it is
absent, because they are the only ones that prove the rules say what this
module thinks they say.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
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
    VulnerabilityRecord,
)

# Aliased: pytest tries to collect anything named Test* as a test class.
from ephemeral_scope.domain.models import TestReference as CoveringTest
from ephemeral_scope.inference.fact_builder import build_facts
from ephemeral_scope.inference.prolog_risk_engine import (
    RULE_EXPLANATIONS,
    SUBJECT_KINDS,
    InferenceResult,
    PrologQueryError,
    PrologRiskEngine,
    PrologUnavailableError,
    infer,
)

SWIPL = shutil.which("swipl")
requires_prolog = pytest.mark.skipif(SWIPL is None, reason="SWI-Prolog not installed")
integration = pytest.mark.integration

RULES = Path(__file__).resolve().parents[1] / "src/ephemeral_scope/inference/rules.pl"

UPGRADE = DependencyUpgrade(
    package_name="requests", current_version="2.28.0", target_version="2.32.0"
)


def usage(symbol: str, file: str = "src/report.py", line: int = 4) -> ApiUsage:
    return ApiUsage(
        package_name="requests",
        symbol=symbol,
        file=Path(file),
        line=line,
        column=0,
        usage_kind=UsageKind.METHOD_CALL,
    )


def change(symbol: str, change_type: ChangeType = ChangeType.REMOVED) -> ApiChange:
    return ApiChange(symbol=symbol, change_type=change_type)


def affected(
    symbol: str,
    change_type: ChangeType = ChangeType.REMOVED,
    file: str = "src/report.py",
    line: int = 4,
) -> AffectedUsage:
    return AffectedUsage(
        usage=usage(symbol, file, line), change=change(symbol, change_type)
    )


def note(
    category: ReleaseNoteCategory,
    relevance: float = 0.85,
    text: str = "Removed the deprecated `send` helper.",
    model_only: bool = False,
) -> ClassifiedChange:
    decision = ClassificationDecision(
        selected_category=category,
        rule_category=None if model_only else category,
        rule_confidence=0.0 if model_only else 0.8,
        model_category=category,
        model_confidence=0.6,
        agreement=not model_only,
        selection_reason=(
            SelectionReason.MODEL_SUGGESTION_ONLY
            if model_only
            else SelectionReason.RULE_MODEL_AGREEMENT
        ),
    )
    return ClassifiedChange(
        note=ReleaseNoteItem(text=text, release_version="2.32.0"),
        category=category,
        confidence=0.8,
        relevance_score=relevance,
        decision=decision,
    )


def advisory(identifier: str) -> VulnerabilityRecord:
    return VulnerabilityRecord(vulnerability_id=identifier, summary="x")


def fake_completed(stdout: str = "", returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess(
        args=["swipl"], returncode=returncode, stdout=stdout, stderr=stderr
    )


ANSWER = {
    "migration_risk": "high",
    "upgrade_urgency": "low",
    "recommended_tests": ["tests/test_report.py"],
    "findings": [
        {
            "dimension": "migration",
            "level": "high",
            "rule": "removed_used_api",
            "subject": "requests.Session.send",
            "sites": [{"file": "src/report.py", "line": 4, "change": "removed"}],
            "support": [],
        }
    ],
}


class TestAvailability:
    """Requirement 1: confirm swipl is installed."""

    def test_reports_unavailable_when_swipl_is_missing(self):
        with patch("shutil.which", return_value=None):
            assert PrologRiskEngine().available() is False

    def test_infer_raises_a_named_error_when_swipl_is_missing(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(PrologUnavailableError):
                PrologRiskEngine().infer(build_facts(UPGRADE))

    def test_the_error_says_how_to_fix_it(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(PrologUnavailableError, match="install"):
                PrologRiskEngine().executable()

    def test_an_explicit_binary_that_does_not_exist_is_rejected(self):
        engine = PrologRiskEngine(swipl="/nonexistent/swipl")

        assert engine.available() is False
        with pytest.raises(PrologUnavailableError, match="not an executable"):
            engine.executable()

    def test_a_missing_query_file_counts_as_unavailable(self, tmp_path):
        engine = PrologRiskEngine(query_file=tmp_path / "absent.pl")

        assert engine.available() is False


class TestSubprocessFailures:
    """Requirement 7: fail gracefully, and never silently."""

    def test_a_nonzero_exit_becomes_a_query_error(self):
        with patch("shutil.which", return_value="/usr/bin/swipl"), patch(
            "subprocess.run", return_value=fake_completed(returncode=2, stderr="boom")
        ):
            with pytest.raises(PrologQueryError, match="boom"):
                PrologRiskEngine().infer(build_facts(UPGRADE))

    def test_a_failed_goal_is_reported_rather_than_read_as_no_findings(self):
        """Exit 1 means the goal failed. That is not an empty answer."""
        with patch("shutil.which", return_value="/usr/bin/swipl"), patch(
            "subprocess.run", return_value=fake_completed(returncode=1)
        ):
            with pytest.raises(PrologQueryError, match="exited 1"):
                PrologRiskEngine().infer(build_facts(UPGRADE))

    def test_non_json_output_is_reported_with_a_sample(self):
        with patch("shutil.which", return_value="/usr/bin/swipl"), patch(
            "subprocess.run", return_value=fake_completed(stdout="Welcome to SWI")
        ):
            with pytest.raises(PrologQueryError, match="Welcome to SWI"):
                PrologRiskEngine().infer(build_facts(UPGRADE))

    def test_a_timeout_becomes_a_query_error(self):
        with patch("shutil.which", return_value="/usr/bin/swipl"), patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="swipl", timeout=30),
        ):
            with pytest.raises(PrologQueryError, match="did not finish"):
                PrologRiskEngine().infer(build_facts(UPGRADE))

    def test_an_unlaunchable_binary_is_unavailable_not_a_query_error(self):
        with patch("shutil.which", return_value="/usr/bin/swipl"), patch(
            "subprocess.run", side_effect=OSError("exec format error")
        ):
            with pytest.raises(PrologUnavailableError):
                PrologRiskEngine().infer(build_facts(UPGRADE))

    def test_an_unparseable_level_is_reported(self):
        answer = dict(ANSWER, migration_risk="catastrophic")
        with patch("shutil.which", return_value="/usr/bin/swipl"), patch(
            "subprocess.run", return_value=fake_completed(stdout=json.dumps(answer))
        ):
            with pytest.raises(PrologQueryError, match="unexpected answer"):
                PrologRiskEngine().infer(build_facts(UPGRADE))

    def test_a_missing_key_is_reported(self):
        answer = {"migration_risk": "low"}
        with patch("shutil.which", return_value="/usr/bin/swipl"), patch(
            "subprocess.run", return_value=fake_completed(stdout=json.dumps(answer))
        ):
            with pytest.raises(PrologQueryError, match="unexpected answer"):
                PrologRiskEngine().infer(build_facts(UPGRADE))


class TestSubprocessInvocation:
    """Requirements 2-4: write facts, load the rules, run the query."""

    def run_with(self, facts, stdout=json.dumps(ANSWER)):
        with patch("shutil.which", return_value="/usr/bin/swipl"), patch(
            "subprocess.run", return_value=fake_completed(stdout=stdout)
        ) as runner:
            result = PrologRiskEngine().infer(facts)
        return result, runner.call_args[0][0]

    def test_the_command_loads_the_query_file_and_the_facts(self):
        _, command = self.run_with(build_facts(UPGRADE))
        goal = command[command.index("-g") + 1]

        assert "query.pl" in goal
        assert "facts.pl" in goal
        assert "emit_findings" in goal

    def test_the_command_halts_so_swipl_never_waits_for_input(self):
        _, command = self.run_with(build_facts(UPGRADE))

        assert command[-2:] == ["-t", "halt"]
        assert "-q" in command

    def test_no_shell_is_involved(self):
        """Arguments go to execve directly, so paths need no shell quoting."""
        with patch("shutil.which", return_value="/usr/bin/swipl"), patch(
            "subprocess.run", return_value=fake_completed(stdout=json.dumps(ANSWER))
        ) as runner:
            PrologRiskEngine().infer(build_facts(UPGRADE))

        assert runner.call_args.kwargs.get("shell") in (None, False)
        assert isinstance(runner.call_args[0][0], list)

    def test_the_fact_file_holds_the_generated_facts(self):
        """Requirement 2, checked by reading the file while swipl 'runs'."""
        seen = {}

        def capture(command, **kwargs):
            goal = command[command.index("-g") + 1]
            path = re.search(r"'([^']*facts\.pl)'", goal).group(1)
            seen["text"] = Path(path).read_text(encoding="utf-8")
            seen["existed"] = Path(path).is_file()
            seen["path"] = path
            return fake_completed(stdout=json.dumps(ANSWER))

        facts = build_facts(UPGRADE, affected=[affected("requests.Session.send")])
        with patch("shutil.which", return_value="/usr/bin/swipl"), patch(
            "subprocess.run", side_effect=capture
        ):
            PrologRiskEngine().infer(facts)

        assert seen["existed"] is True
        assert "affected_usage('src/report.py', 4," in seen["text"]

    def test_the_temporary_file_is_deleted_afterwards(self):
        """Requirement 6."""
        seen = {}

        def capture(command, **kwargs):
            goal = command[command.index("-g") + 1]
            seen["path"] = re.search(r"'([^']*facts\.pl)'", goal).group(1)
            return fake_completed(stdout=json.dumps(ANSWER))

        with patch("shutil.which", return_value="/usr/bin/swipl"), patch(
            "subprocess.run", side_effect=capture
        ):
            PrologRiskEngine().infer(build_facts(UPGRADE))

        assert not Path(seen["path"]).exists()
        assert not Path(seen["path"]).parent.exists()

    def test_the_temporary_file_is_deleted_even_when_swipl_fails(self):
        seen = {}

        def capture(command, **kwargs):
            goal = command[command.index("-g") + 1]
            seen["path"] = re.search(r"'([^']*facts\.pl)'", goal).group(1)
            return fake_completed(returncode=2, stderr="boom")

        with patch("shutil.which", return_value="/usr/bin/swipl"), patch(
            "subprocess.run", side_effect=capture
        ):
            with pytest.raises(PrologQueryError):
                PrologRiskEngine().infer(build_facts(UPGRADE))

        assert not Path(seen["path"]).exists()


class TestFindingConversion:
    """Requirement 5: rule names become RiskFinding objects."""

    def result_for(self, answer, facts=None):
        with patch("shutil.which", return_value="/usr/bin/swipl"), patch(
            "subprocess.run", return_value=fake_completed(stdout=json.dumps(answer))
        ):
            return PrologRiskEngine().infer(facts or build_facts(UPGRADE))

    def test_a_removed_used_api_becomes_a_risk_finding(self):
        result = self.result_for(ANSWER)

        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.rule_name == "removed_used_api"
        assert finding.risk_level is RiskLevel.HIGH
        assert finding.symbol == "requests.Session.send"
        assert finding.file == Path("src/report.py")
        assert finding.line == 4

    def test_the_rule_name_is_translated_into_prose(self):
        finding = self.result_for(ANSWER).findings[0]

        assert finding.reason == RULE_EXPLANATIONS["removed_used_api"]
        assert finding.reason != finding.rule_name

    def test_the_supporting_fact_is_the_prolog_clause_behind_it(self):
        finding = self.result_for(ANSWER).findings[0]

        assert (
            "affected_usage('src/report.py', 4, 'requests.Session.send', removed)."
            in finding.supporting_facts
        )

    def test_one_symbol_at_several_sites_becomes_one_finding_per_site(self):
        answer = dict(ANSWER)
        answer["findings"] = [
            dict(
                ANSWER["findings"][0],
                sites=[
                    {"file": "src/a.py", "line": 1, "change": "removed"},
                    {"file": "src/b.py", "line": 9, "change": "removed"},
                ],
            )
        ]
        result = self.result_for(answer)

        assert [(f.file, f.line) for f in result.findings] == [
            (Path("src/a.py"), 1),
            (Path("src/b.py"), 9),
        ]

    def test_an_advisory_finding_has_no_file_or_symbol(self):
        answer = {
            "migration_risk": "low",
            "upgrade_urgency": "high",
            "recommended_tests": [],
            "findings": [
                {
                    "dimension": "urgency",
                    "level": "high",
                    "rule": "fixes_known_vulnerability",
                    "subject": "GHSA-j8r2-6x86-q33q",
                    "sites": [],
                    "support": [],
                }
            ],
        }
        finding = self.result_for(answer).findings[0]

        assert finding.symbol is None
        assert finding.file is None
        assert finding.risk_level is RiskLevel.HIGH

    def test_release_note_prose_rejoins_its_finding(self):
        """The text never entered Prolog; it comes back from FactBase.notes."""
        facts = build_facts(
            UPGRADE,
            classified_changes=[
                note(ReleaseNoteCategory.BREAKING_CHANGE, text="Dropped `send`.")
            ],
        )
        answer = {
            "migration_risk": "medium",
            "upgrade_urgency": "low",
            "recommended_tests": [],
            "findings": [
                {
                    "dimension": "migration",
                    "level": "medium",
                    "rule": "relevant_breaking_note",
                    "subject": "change_1",
                    "sites": [],
                    "support": ["classifier_agreement"],
                }
            ],
        }
        finding = self.result_for(answer, facts).findings[0]

        assert "Dropped `send`." in finding.supporting_facts
        assert (
            "confidence_support(change_1, classifier_agreement)."
            in finding.supporting_facts
        )

    def test_the_assessment_keeps_the_two_dimensions_apart(self):
        result = self.result_for(ANSWER)

        assert result.assessment.migration_risk is RiskLevel.HIGH
        assert result.assessment.upgrade_urgency is RiskLevel.LOW

    def test_the_engine_that_ran_is_recorded(self):
        assert self.result_for(ANSWER).engine == "prolog"

    def test_recommended_tests_are_carried_through(self):
        assert self.result_for(ANSWER).recommended_tests == ("tests/test_report.py",)


class TestSubjectKinds:
    """Every rule must say what its subject denotes, or findings lose fields."""

    def prolog_rule_names(self) -> set[str]:
        text = RULES.read_text(encoding="utf-8")
        pattern = re.compile(
            r"^(?:migration_risk|upgrade_urgency)\(\s*\w+\s*,\s*(\w+)\s*,",
            re.MULTILINE,
        )
        return set(pattern.findall(text))

    def test_every_rule_has_a_subject_kind(self):
        missing = self.prolog_rule_names() - set(SUBJECT_KINDS)

        assert not missing, f"rules without a declared subject: {sorted(missing)}"

    def test_no_subject_kind_describes_an_absent_rule(self):
        extra = set(SUBJECT_KINDS) - self.prolog_rule_names()

        assert not extra, f"subject kinds for absent rules: {sorted(extra)}"

    def test_the_kinds_are_ones_the_converter_understands(self):
        assert set(SUBJECT_KINDS.values()) <= {"symbol", "change", "advisory"}


class TestFallback:
    """Requirement 7: a missing interpreter degrades, a broken rule does not."""

    def test_infer_falls_back_to_python_when_prolog_is_absent(self):
        with patch("shutil.which", return_value=None):
            result = infer(UPGRADE, affected=[affected("requests.Session.send")])

        assert result.engine == "python"
        assert result.assessment.migration_risk is RiskLevel.HIGH
        assert result.findings[0].rule_name == "removed_used_api"

    def test_the_fallback_still_explains_itself(self):
        with patch("shutil.which", return_value=None):
            result = infer(UPGRADE, affected=[affected("requests.Session.send")])

        assert result.findings[0].reason == RULE_EXPLANATIONS["removed_used_api"]

    def test_require_prolog_refuses_to_fall_back(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(PrologUnavailableError):
                infer(UPGRADE, require_prolog=True)

    def test_a_broken_rule_is_not_hidden_by_the_fallback(self):
        """A query error means the rules are wrong. Falling back would mask it."""
        with patch("shutil.which", return_value="/usr/bin/swipl"), patch(
            "subprocess.run", return_value=fake_completed(returncode=2, stderr="boom")
        ):
            with pytest.raises(PrologQueryError):
                infer(UPGRADE)

    def test_the_fallback_recommends_the_same_tests(self):
        with patch("shutil.which", return_value=None):
            result = infer(
                UPGRADE,
                affected=[affected("requests.Session.send")],
                test_references=[
                    CoveringTest(
                        test_file=Path("tests/test_report.py"),
                        source_file=Path("src/report.py"),
                    )
                ],
            )

        assert result.recommended_tests == ("tests/test_report.py",)


@requires_prolog
@integration
class TestAgainstRealProlog:
    """The only tests that prove the rules say what the engine assumes."""

    def test_a_removed_used_api_becomes_a_finding_through_prolog(self):
        """The acceptance criterion for this phase."""
        result = infer(
            UPGRADE,
            affected=[affected("requests.Session.send")],
            require_prolog=True,
        )

        assert result.engine == "prolog"
        assert result.assessment.migration_risk is RiskLevel.HIGH
        finding = result.findings[0]
        assert finding.rule_name == "removed_used_api"
        assert finding.symbol == "requests.Session.send"
        assert finding.file == Path("src/report.py")
        assert finding.line == 4
        assert finding.reason == RULE_EXPLANATIONS["removed_used_api"]

    def test_an_empty_analysis_is_low_risk_rather_than_an_error(self):
        result = infer(UPGRADE, require_prolog=True)

        assert result.assessment.migration_risk is RiskLevel.LOW
        assert result.assessment.upgrade_urgency is RiskLevel.LOW
        assert result.findings == ()

    def test_a_security_fix_does_not_make_the_upgrade_look_incompatible(self):
        result = infer(
            UPGRADE,
            evidence=EvidenceBundle(
                current_vulnerabilities=(advisory("GHSA-j8r2-6x86-q33q"),)
            ),
            require_prolog=True,
        )

        assert result.assessment.migration_risk is RiskLevel.LOW
        assert result.assessment.upgrade_urgency is RiskLevel.HIGH
        assert result.findings[0].rule_name == "fixes_known_vulnerability"

    def test_quotes_and_newlines_in_a_symbol_survive_the_round_trip(self):
        """The whole point of generated ids and quoted atoms."""
        awkward = "pkg.weird'name\nwith breaks"
        result = infer(
            UPGRADE, affected=[affected(awkward)], require_prolog=True
        )

        assert result.findings[0].symbol == awkward

    def test_a_unicode_path_survives_the_round_trip(self):
        result = infer(
            UPGRADE,
            affected=[affected("requests.get", file="src/rapport_été.py")],
            require_prolog=True,
        )

        assert result.findings[0].file == Path("src/rapport_été.py")

    def test_several_call_sites_each_get_a_finding(self):
        result = infer(
            UPGRADE,
            affected=[
                affected("requests.Session.send", file="src/a.py", line=1),
                affected("requests.Session.send", file="src/b.py", line=9),
            ],
            require_prolog=True,
        )

        assert {(str(f.file), f.line) for f in result.findings} == {
            ("src/a.py", 1),
            ("src/b.py", 9),
        }

    def test_a_model_only_note_raises_no_finding(self):
        """TF-IDF alone must not create a finding."""
        result = infer(
            UPGRADE,
            classified_changes=[
                note(ReleaseNoteCategory.BREAKING_CHANGE, model_only=True)
            ],
            require_prolog=True,
        )

        assert result.assessment.migration_risk is RiskLevel.LOW
        assert result.findings == ()

    def test_prose_never_reaches_prolog_but_reaches_the_finding(self):
        result = infer(
            UPGRADE,
            classified_changes=[
                note(
                    ReleaseNoteCategory.BREAKING_CHANGE,
                    text="Removed `Session.send`; use `request` instead.",
                )
            ],
            require_prolog=True,
        )

        finding = result.findings[0]
        assert finding.rule_name == "relevant_breaking_note"
        assert "Removed `Session.send`; use `request` instead." in (
            finding.supporting_facts
        )

    def test_recommended_tests_come_back_from_prolog(self):
        result = infer(
            UPGRADE,
            affected=[affected("requests.Session.send")],
            test_references=[
                CoveringTest(
                    test_file=Path("tests/test_report.py"),
                    source_file=Path("src/report.py"),
                )
            ],
            require_prolog=True,
        )

        assert result.recommended_tests == ("tests/test_report.py",)

    @pytest.mark.parametrize(
        "scenario",
        [
            {"affected": [affected("requests.get", ChangeType.REMOVED)]},
            {"affected": [affected("requests.get", ChangeType.SIGNATURE_CHANGED)]},
            {"affected": [affected("requests.get", ChangeType.DEFAULT_CHANGED)]},
            {"classified_changes": [note(ReleaseNoteCategory.BREAKING_CHANGE)]},
            {"classified_changes": [note(ReleaseNoteCategory.BUG_FIX)]},
            {
                "evidence": EvidenceBundle(
                    current_vulnerabilities=(advisory("GHSA-1"),),
                    target_vulnerabilities=(advisory("GHSA-1"),),
                )
            },
            {},
        ],
    )
    def test_both_engines_reach_the_same_conclusion(self, scenario):
        """The fallback is only honest if it agrees with the rules."""
        through_prolog = infer(UPGRADE, require_prolog=True, **scenario)
        with patch("shutil.which", return_value=None):
            through_python = infer(UPGRADE, **scenario)

        assert (
            through_prolog.assessment.migration_risk
            == through_python.assessment.migration_risk
        )
        assert (
            through_prolog.assessment.upgrade_urgency
            == through_python.assessment.upgrade_urgency
        )
        assert {f.rule_name for f in through_prolog.findings} == {
            f.rule_name for f in through_python.findings
        }


@requires_prolog
@integration
class TestResultShape:
    def test_the_result_separates_the_two_dimensions(self):
        result = infer(
            UPGRADE,
            affected=[affected("requests.Session.send")],
            evidence=EvidenceBundle(
                current_vulnerabilities=(advisory("GHSA-j8r2-6x86-q33q"),)
            ),
            require_prolog=True,
        )

        assert isinstance(result, InferenceResult)
        assert [f.rule_name for f in result.migration_findings] == ["removed_used_api"]
        assert [f.rule_name for f in result.urgency_findings] == [
            "fixes_known_vulnerability"
        ]
