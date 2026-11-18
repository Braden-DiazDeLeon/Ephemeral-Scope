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
    vulnerabilities: tuple[VulnerabilityRecord, ...] = ()


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
class UpgradeReport:
    upgrade: DependencyUpgrade
    overall_risk: RiskLevel
    usages: tuple[ApiUsage, ...] = ()
    api_changes: tuple[ApiChange, ...] = ()
    classified_changes: tuple[ClassifiedChange, ...] = ()
    vulnerabilities: tuple[VulnerabilityRecord, ...] = ()
    findings: tuple[RiskFinding, ...] = ()
    recommended_tests: tuple[str, ...] = ()
    migration_actions: tuple[str, ...] = ()
