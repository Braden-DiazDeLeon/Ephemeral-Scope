"""Domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ephemeral_scope.domain.enums import (
    ApiSymbolKind,
    ChangeType,
    ReleaseNoteCategory,
    RiskLevel,
    SelectionReason,
    UsageKind,
)


@dataclass(frozen=True, slots=True)
class AnalysisRequest:
    project_path: Path
    package_name: str
    current_version: str
    target_version: str


@dataclass(frozen=True, slots=True)
class Dependency:
    name: str
    specifier: str | None
    source_file: Path


@dataclass(frozen=True, slots=True)
class ProjectManifest:
    root_path: Path
    source_files: tuple[Path, ...]
    test_files: tuple[Path, ...]
    dependency_files: tuple[Path, ...]
    dependencies: tuple[Dependency, ...] = ()


@dataclass(frozen=True, slots=True)
class DependencyUpgrade:
    package_name: str
    current_version: str
    target_version: str


@dataclass(frozen=True, slots=True)
class ApiUsage:
    package_name: str
    symbol: str
    file: Path
    line: int
    column: int
    usage_kind: UsageKind
    import_alias: str | None = None


@dataclass(frozen=True, slots=True)
class TestReference:
    test_file: Path
    source_file: Path
    related_symbol: str | None = None


@dataclass(frozen=True, slots=True)
class ApiSymbol:
    qualified_name: str
    symbol_kind: ApiSymbolKind
    signature: str | None = None
    return_type: str | None = None


@dataclass(frozen=True, slots=True)
class ApiSnapshot:
    package_name: str
    version: str
    symbols: tuple[ApiSymbol, ...]


@dataclass(frozen=True, slots=True)
class ApiChange:
    symbol: str
    change_type: ChangeType
    old_signature: str | None = None
    new_signature: str | None = None
    details: str | None = None

    def affects(self, usage: ApiUsage) -> bool:
        """True when this change touches the API that ``usage`` refers to.

        The comparison ignores the module path. A project writing
        ``pandas.DataFrame.append`` means the same object that Griffe records
        at its definition site, ``pandas.core.frame.DataFrame.append``, so the
        shorter name only has to match the tail of the longer one.

        A change to an *enclosing* object counts too: removing the
        ``DataFrame`` class affects every usage of its methods. The reverse
        does not hold, since removing one method says nothing about code that
        merely references the class.
        """
        if self.symbol.split(".", 1)[0] != usage.package_name:
            return False

        change_parts = self.symbol.split(".")[1:]
        usage_parts = usage.symbol.split(".")[1:]
        if not change_parts or not usage_parts:
            return False

        # i == len(usage_parts) compares the usage itself; shorter slices
        # compare the objects that enclose it.
        return any(
            _same_object(usage_parts[:i], change_parts)
            for i in range(1, len(usage_parts) + 1)
        )


def _same_object(a: list[str], b: list[str]) -> bool:
    """True when the shorter dotted path is a tail of the longer one."""
    if not a or not b:
        return False
    shorter, longer = (a, b) if len(a) <= len(b) else (b, a)
    return longer[-len(shorter) :] == shorter


@dataclass(frozen=True, slots=True)
class AffectedUsage:
    """A place in the project that a dependency change lands on."""

    usage: ApiUsage
    change: ApiChange

    def to_dict(self, root_path: Path | None = None) -> dict:
        """Serialize for the API response, with paths relative to the project."""
        file = self.usage.file
        if root_path is not None:
            try:
                file = file.relative_to(root_path)
            except ValueError:
                pass
        return {
            "file": str(file),
            "line": self.usage.line,
            "symbol": self.usage.symbol,
            "change": str(self.change.change_type),
        }


@dataclass(frozen=True, slots=True)
class ReleaseNoteItem:
    text: str
    release_version: str
    source_url: str | None = None
    package_name: str | None = None
    #: The changelog heading the statement sat under
    section: str | None = None


@dataclass(frozen=True, slots=True)
class VulnerabilityRecord:
    vulnerability_id: str
    summary: str
    affected_versions: tuple[str, ...] = ()
    fixed_versions: tuple[str, ...] = ()
    source_url: str | None = None


@dataclass(frozen=True, slots=True)
class ClassificationDecision:
    """Both classifiers' answers plus the reason one of them was chosen.

    Keeping the rule and the model side by side means a disagreement shows up
    in the report rather than being averaged away. ``selected_category`` is
    ``None`` when neither could categorise the statement, which is a
    different claim from IRRELEVANT: one says the classifiers had nothing to
    offer, the other says the statement genuinely does not matter.
    """

    selected_category: ReleaseNoteCategory | None
    rule_category: ReleaseNoteCategory | None
    rule_confidence: float
    model_category: ReleaseNoteCategory | None
    model_confidence: float
    agreement: bool
    selection_reason: SelectionReason

    @property
    def confidence(self) -> float:
        """Confidence in ``selected_category``.

        Agreement between two independent classifiers is worth more than
        either alone, so it is scored above the rule's own confidence while
        still capped below certainty.
        """
        if self.selection_reason is SelectionReason.RULE_MODEL_AGREEMENT:
            return min(0.95, self.rule_confidence + 0.2)
        if self.selected_category is None:
            return 0.0
        if self.model_category is not None and self.rule_category is None:
            return self.model_confidence
        return self.rule_confidence

    @property
    def is_model_only(self) -> bool:
        """True when nothing but the TF-IDF model supports the category.

        Risk rules consult this: a statement no deterministic rule recognised
        must not on its own raise a high-risk finding.
        """
        return self.selection_reason is SelectionReason.MODEL_SUGGESTION_ONLY

    def to_dict(self) -> dict:
        return {
            "selected_category": _category_value(self.selected_category),
            "rule_category": _category_value(self.rule_category),
            "rule_confidence": round(self.rule_confidence, 4),
            "model_category": _category_value(self.model_category),
            "model_confidence": round(self.model_confidence, 4),
            "agreement": self.agreement,
            "selection_reason": str(self.selection_reason),
            "confidence": round(self.confidence, 4),
        }


def _category_value(category: ReleaseNoteCategory | None) -> str | None:
    return None if category is None else str(category)


@dataclass(frozen=True, slots=True)
class ClassifiedChange:
    note: ReleaseNoteItem
    #: ``None`` when no classifier could categorise the statement.
    category: ReleaseNoteCategory | None
    confidence: float
    mentioned_symbols: tuple[str, ...] = ()
    matched_project_symbols: tuple[str, ...] = ()
    relevance_score: float = 0.0
    #: Provenance for ``category``; ``None`` predates the hybrid policy.
    decision: ClassificationDecision | None = None


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    release_notes: tuple[ReleaseNoteItem, ...] = ()
    #: Every advisory touching either version, deduplicated by id.
    vulnerabilities: tuple[VulnerabilityRecord, ...] = ()
    #: Advisories affecting the version the project is on today.
    current_vulnerabilities: tuple[VulnerabilityRecord, ...] = ()
    #: Advisories still affecting the version it would move to.
    target_vulnerabilities: tuple[VulnerabilityRecord, ...] = ()

    @property
    def fixed_by_upgrade(self) -> tuple[VulnerabilityRecord, ...]:
        """Advisories the upgrade resolves.

        These are a reason to upgrade, not a hazard of upgrading, so they
        must never be folded into migration risk.
        """
        still_open = {record.vulnerability_id for record in self.target_vulnerabilities}
        return tuple(
            record
            for record in self.current_vulnerabilities
            if record.vulnerability_id not in still_open
        )

    @property
    def introduced_by_upgrade(self) -> tuple[VulnerabilityRecord, ...]:
        """Advisories that affect the target but not the current version."""
        already_open = {
            record.vulnerability_id for record in self.current_vulnerabilities
        }
        return tuple(
            record
            for record in self.target_vulnerabilities
            if record.vulnerability_id not in already_open
        )


@dataclass(frozen=True, slots=True)
class RiskFinding:
    risk_level: RiskLevel
    reason: str
    rule_name: str
    file: Path | None = None
    line: int | None = None
    symbol: str | None = None
    supporting_facts: tuple[str, ...] = ()
    recommendation: str | None = None


@dataclass(frozen=True, slots=True)
class RiskReason:
    """One piece of evidence behind a risk or urgency level."""

    level: RiskLevel
    rule_name: str
    subject: str

    def __str__(self) -> str:
        return f"{self.rule_name}: {self.subject}"


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """The two independent questions asked of one upgrade.

    ``migration_risk`` answers "will this break my project"; it is driven by
    removed symbols, changed signatures and relevant behavioural changes.
    ``upgrade_urgency`` answers "how badly do I need this anyway"; it is
    driven by vulnerabilities.

    They never feed each other. A vulnerability the target version fixes
    raises urgency and leaves migration risk untouched, because a security
    fix is a reason to upgrade rather than a hazard of upgrading.
    """

    migration_risk: RiskLevel = RiskLevel.LOW
    upgrade_urgency: RiskLevel = RiskLevel.LOW
    migration_reasons: tuple[RiskReason, ...] = ()
    urgency_reasons: tuple[RiskReason, ...] = ()

    def to_dict(self) -> dict:
        return {
            "migration_risk": str(self.migration_risk),
            "upgrade_urgency": str(self.upgrade_urgency),
            "migration_reasons": [
                {"rule": r.rule_name, "subject": r.subject} for r in self.migration_reasons
            ],
            "urgency_reasons": [
                {"rule": r.rule_name, "subject": r.subject} for r in self.urgency_reasons
            ],
        }


@dataclass(frozen=True, slots=True)
class UpgradeReport:
    upgrade: DependencyUpgrade
    #: Retained for compatibility; mirrors ``assessment.migration_risk``,
    #: since "is this upgrade dangerous" is the migration question alone.
    overall_risk: RiskLevel
    assessment: RiskAssessment = field(default_factory=RiskAssessment)
    usages: tuple[ApiUsage, ...] = ()
    api_changes: tuple[ApiChange, ...] = ()
    #: Where the two meet: the project's call sites that a change lands on.
    affected_usages: tuple[AffectedUsage, ...] = ()
    classified_changes: tuple[ClassifiedChange, ...] = ()
    vulnerabilities: tuple[VulnerabilityRecord, ...] = ()
    #: Kept whole so the report can distinguish an advisory the upgrade
    #: closes from one it leaves open; the flat tuple above cannot.
    evidence: EvidenceBundle = field(default_factory=EvidenceBundle)
    findings: tuple[RiskFinding, ...] = ()
    recommended_tests: tuple[str, ...] = ()
    migration_actions: tuple[str, ...] = ()
    #: "prolog" or "python". Disclosed rather than implied, so a reader
    #: knows whether the logic engine actually ran.
    inference_engine: str = "python"

    @property
    def classifier_disagreements(self) -> tuple[ClassifiedChange, ...]:
        """Statements where the keyword rules and TF-IDF chose differently.

        Derived rather than stored: a disagreement is a property of the
        decision already attached to each statement, and duplicating it
        would let the two drift apart.
        """
        return tuple(
            change
            for change in self.classified_changes
            if change.decision is not None
            and change.decision.rule_category is not None
            and change.decision.model_category is not None
            and not change.decision.agreement
        )

    @property
    def fixed_vulnerabilities(self) -> tuple[VulnerabilityRecord, ...]:
        """Advisories the target version resolves: the reason to upgrade."""
        return self.evidence.fixed_by_upgrade

    @property
    def remaining_vulnerabilities(self) -> tuple[VulnerabilityRecord, ...]:
        """Advisories still affecting the target version."""
        return self.evidence.target_vulnerabilities

    @property
    def affected_files(self) -> tuple[Path, ...]:
        seen = {affected.usage.file for affected in self.affected_usages}
        return tuple(sorted(seen))
