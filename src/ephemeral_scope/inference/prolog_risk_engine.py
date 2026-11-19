"""Running the Prolog rules from Python.

SWI-Prolog is invoked as a subprocess.
A subprocess has no native extension to build against the running
interpreter, survives Python upgrades, and cannot take the process down
with it; the cost is one fork and a JSON parse per analysis, which is
nothing beside the network calls the rest of the pipeline makes. It also
leaves the logic-programming boundary visible -- the exact command this
module runs can be retyped at a terminal, which is how the rules were
developed.

If SWI-Prolog is missing the engine says so through
:class:`PrologUnavailableError`, and :func:`infer` falls back to the pure
Python :class:`~ephemeral_scope.inference.risk_assessor.RiskAssessor`,
which implements the same policy and is tested against the Prolog for
agreement. Installing Prolog therefore changes which engine produced a
report.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ephemeral_scope.domain.enums import RiskLevel
from ephemeral_scope.domain.models import (
    AffectedUsage,
    AnalysisWarning,
    ApiChange,
    ApiUsage,
    ClassifiedChange,
    DependencyUpgrade,
    EvidenceBundle,
    RiskAssessment,
    RiskFinding,
    RiskReason,
    TestReference,
)
from ephemeral_scope.inference.fact_builder import FactBase, atom, build_facts, fact
from ephemeral_scope.inference.risk_assessor import (
    RULE_EXPLANATIONS,
    RiskAssessor,
    explain,
)

#: Where rules.pl and query.pl live. Shipped as package data.
RULES_DIRECTORY = Path(__file__).parent
QUERY_FILE = RULES_DIRECTORY / "query.pl"

DEFAULT_TIMEOUT_SECONDS = 30.0

#: What the third argument of each rule denotes. Needed because a rule name
#: is all the engine gets back, and a symbol, a release-note identifier and
#: an advisory id are populated into different RiskFinding fields. A test
#: asserts this covers exactly the rules rules.pl defines, so adding a rule
#: without deciding what its subject means fails the build.
SUBJECT_KINDS: dict[str, str] = {
    "removed_used_api": "symbol",
    "changed_used_signature": "symbol",
    "relevant_breaking_note": "change",
    "relevant_behavior_change": "change",
    "fixes_known_vulnerability": "advisory",
    "target_remains_vulnerable": "advisory",
    "reported_security_fix": "change",
}


class PrologError(RuntimeError):
    """Base class for every failure of the Prolog subprocess."""


class PrologUnavailableError(PrologError):
    """SWI-Prolog is not installed, or the named binary is not executable."""


class PrologQueryError(PrologError):
    """swipl ran but did not return a usable answer."""


@dataclass(frozen=True, slots=True)
class InferenceResult:
    """The outcome of one inference run, whichever engine produced it."""

    assessment: RiskAssessment
    findings: tuple[RiskFinding, ...] = ()
    recommended_tests: tuple[str, ...] = ()
    #: "prolog" or "python". Recorded so a report can disclose how it was
    #: derived rather than implying Prolog ran when it did not.
    engine: str = "prolog"
    #: Why this result is not the Prolog one, when it is not. Empty when
    #: Prolog ran, or when the caller asked for the Python assessor directly.
    warnings: tuple[AnalysisWarning, ...] = ()

    @property
    def migration_findings(self) -> tuple[RiskFinding, ...]:
        return tuple(f for f in self.findings if f.rule_name in _MIGRATION_RULES)

    @property
    def urgency_findings(self) -> tuple[RiskFinding, ...]:
        return tuple(f for f in self.findings if f.rule_name not in _MIGRATION_RULES)


_MIGRATION_RULES = frozenset(
    {
        "removed_used_api",
        "changed_used_signature",
        "relevant_breaking_note",
        "relevant_behavior_change",
    }
)


class PrologRiskEngine:
    """Derives findings by running rules.pl over generated facts."""

    def __init__(
        self,
        swipl: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        query_file: Path = QUERY_FILE,
    ) -> None:
        self._swipl = swipl
        self._timeout = timeout
        self._query_file = query_file

    def executable(self) -> str:
        """The swipl binary to run, or raise if there is not one."""
        if self._swipl is not None:
            if Path(self._swipl).is_file() or shutil.which(self._swipl):
                return self._swipl
            raise PrologUnavailableError(f"{self._swipl} is not an executable")

        found = shutil.which("swipl")
        if found is None:
            raise PrologUnavailableError(
                "SWI-Prolog is not installed. Install it (brew install swi-prolog, "
                "apt install swi-prolog) or use the Python RiskAssessor instead."
            )
        return found

    def available(self) -> bool:
        """Whether an inference run could be attempted at all."""
        try:
            self.executable()
        except PrologUnavailableError:
            return False
        return self._query_file.is_file()

    def infer(self, facts: FactBase) -> InferenceResult:
        """Run the rules over ``facts`` and return the findings.

        Raises :class:`PrologUnavailableError` if SWI-Prolog is missing and
        :class:`PrologQueryError` if it ran but failed.
        """
        executable = self.executable()
        if not self._query_file.is_file():
            raise PrologUnavailableError(f"missing query file: {self._query_file}")

        payload = self._run(executable, facts)
        return self._to_result(payload, facts)

    def _run(self, executable: str, facts: FactBase) -> dict:
        # A directory rather than a bare file so cleanup is guaranteed by
        # the context manager even if swipl is killed mid-run.
        with tempfile.TemporaryDirectory(prefix="ephemeral-scope-") as directory:
            fact_file = Path(directory) / "facts.pl"
            facts.write(fact_file, header="Temporary; written by PrologRiskEngine.")

            goal = (
                f"consult({atom(str(self._query_file))}), "
                f"consult({atom(str(fact_file))}), "
                "emit_findings"
            )
            command = [executable, "-q", "-g", goal, "-t", "halt"]

            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                )
            except subprocess.TimeoutExpired as error:
                raise PrologQueryError(
                    f"swipl did not finish within {self._timeout}s"
                ) from error
            except OSError as error:
                raise PrologUnavailableError(f"could not run {executable}") from error

        if completed.returncode != 0:
            raise PrologQueryError(
                f"swipl exited {completed.returncode}: "
                f"{completed.stderr.strip() or 'no diagnostics'}"
            )

        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise PrologQueryError(
                f"swipl produced no JSON on stdout: {completed.stdout[:200]!r}"
            ) from error

    def _to_result(self, payload: dict, facts: FactBase) -> InferenceResult:
        try:
            migration = RiskLevel(payload["migration_risk"])
            urgency = RiskLevel(payload["upgrade_urgency"])
            raw_findings = payload["findings"]
            tests = tuple(payload.get("recommended_tests", ()))
        except (KeyError, ValueError) as error:
            raise PrologQueryError(f"unexpected answer from swipl: {payload}") from error

        findings: list[RiskFinding] = []
        migration_reasons: list[RiskReason] = []
        urgency_reasons: list[RiskReason] = []

        for entry in raw_findings:
            findings.extend(_findings_from(entry, facts))
            reason = RiskReason(
                level=RiskLevel(entry["level"]),
                rule_name=entry["rule"],
                subject=entry["subject"],
            )
            if entry["dimension"] == "migration":
                migration_reasons.append(reason)
            else:
                urgency_reasons.append(reason)

        assessment = RiskAssessment(
            migration_risk=migration,
            upgrade_urgency=urgency,
            migration_reasons=_at_level(migration_reasons, migration),
            urgency_reasons=_at_level(urgency_reasons, urgency),
        )
        return InferenceResult(
            assessment=assessment,
            findings=tuple(findings),
            recommended_tests=tests,
            engine="prolog",
        )


def _findings_from(entry: dict, facts: FactBase) -> list[RiskFinding]:
    """Expand one Prolog answer into the findings a reader acts on.

    A symbol used at three call sites becomes three findings, because each
    is a separate edit. Everything else becomes one.
    """
    rule = entry["rule"]
    subject = entry["subject"]
    level = RiskLevel(entry["level"])
    kind = SUBJECT_KINDS.get(rule, "other")
    support = tuple(
        fact("confidence_support", atom(subject), atom(k))
        for k in entry.get("support", ())
    )

    if kind == "symbol" and entry.get("sites"):
        return [
            RiskFinding(
                risk_level=level,
                reason=explain(rule),
                rule_name=rule,
                file=Path(site["file"]),
                line=site["line"],
                symbol=subject,
                supporting_facts=(
                    fact(
                        "affected_usage",
                        atom(site["file"]),
                        str(site["line"]),
                        atom(subject),
                        atom(site["change"]),
                    ),
                )
                + support,
            )
            for site in entry["sites"]
        ]

    supporting: tuple[str, ...] = support
    if kind == "change":
        # The prose never entered Prolog; this is where it rejoins its
        # finding. See fact_builder's module docstring.
        prose = facts.notes.get(subject)
        if prose:
            supporting = (prose,) + supporting

    return [
        RiskFinding(
            risk_level=level,
            reason=explain(rule),
            rule_name=rule,
            symbol=subject if kind == "symbol" else None,
            supporting_facts=supporting,
        )
    ]


def _at_level(
    reasons: Sequence[RiskReason], level: RiskLevel
) -> tuple[RiskReason, ...]:
    seen: dict[tuple[str, str], RiskReason] = {}
    for reason in reasons:
        if reason.level is level:
            seen.setdefault((reason.rule_name, reason.subject), reason)
    return tuple(seen.values())


def infer(
    upgrade: DependencyUpgrade,
    usages: Sequence[ApiUsage] = (),
    api_changes: Sequence[ApiChange] = (),
    affected: Sequence[AffectedUsage] = (),
    classified_changes: Sequence[ClassifiedChange] = (),
    evidence: EvidenceBundle | None = None,
    test_references: Sequence[TestReference] = (),
    engine: PrologRiskEngine | None = None,
    require_prolog: bool = False,
) -> InferenceResult:
    """Assess an upgrade, through Prolog when it is available.

    Falls back to the Python assessor when SWI-Prolog is missing, unless
    ``require_prolog`` is set. A query that fails once Prolog *is* present
    is never swallowed: that means the rules are broken, and hiding it
    behind a fallback would make the two engines silently disagree.
    """
    facts = build_facts(
        upgrade,
        usages=usages,
        api_changes=api_changes,
        affected=affected,
        classified_changes=classified_changes,
        evidence=evidence,
        test_references=test_references,
    )
    engine = engine or PrologRiskEngine()

    try:
        return engine.infer(facts)
    except PrologUnavailableError:
        if require_prolog:
            raise

    assessment = RiskAssessor().assess(
        upgrade,
        affected=affected,
        classified_changes=classified_changes,
        evidence=evidence,
    )
    return InferenceResult(
        assessment=assessment,
        findings=_findings_from_assessment(assessment, facts),
        recommended_tests=_tests_from(affected, test_references),
        engine="python",
        warnings=(
            AnalysisWarning(
                "prolog", "Prolog unavailable; Python fallback used"
            ),
        ),
    )


def _findings_from_assessment(
    assessment: RiskAssessment, facts: FactBase
) -> tuple[RiskFinding, ...]:
    """The same RiskFinding shape, without the call-site detail Prolog adds."""
    findings = []
    for reason in (*assessment.migration_reasons, *assessment.urgency_reasons):
        kind = SUBJECT_KINDS.get(reason.rule_name, "other")
        prose = facts.notes.get(reason.subject) if kind == "change" else None
        findings.append(
            RiskFinding(
                risk_level=reason.level,
                reason=explain(reason.rule_name),
                rule_name=reason.rule_name,
                symbol=reason.subject if kind == "symbol" else None,
                supporting_facts=(prose,) if prose else (),
            )
        )
    return tuple(findings)


def _tests_from(
    affected: Sequence[AffectedUsage], references: Sequence[TestReference]
) -> tuple[str, ...]:
    """The Python equivalent of recommended_test/1.

    Paths go through the same normalisation fact_builder applies, so the
    two engines name tests identically.
    """
    touched = {item.usage.file.as_posix() for item in affected}
    return tuple(
        sorted(
            {
                reference.test_file.as_posix()
                for reference in references
                if reference.source_file.as_posix() in touched
            }
        )
    )


__all__ = [
    "RULE_EXPLANATIONS",
    "SUBJECT_KINDS",
    "InferenceResult",
    "PrologError",
    "PrologQueryError",
    "PrologRiskEngine",
    "PrologUnavailableError",
    "infer",
]
