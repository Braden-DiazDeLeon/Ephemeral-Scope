"""Domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ephemeral_scope.domain.enums import (
    ApiSymbolKind,
    ChangeType,
    ReleaseNoteCategory,
    RiskLevel,
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


@dataclass(frozen=True, slots=True)
class ReleaseNoteItem:
    text: str
    release_version: str
    source_url: str | None = None


@dataclass(frozen=True, slots=True)
class VulnerabilityRecord:
    vulnerability_id: str
    summary: str
    affected_versions: tuple[str, ...] = ()
    fixed_versions: tuple[str, ...] = ()
    source_url: str | None = None


@dataclass(frozen=True, slots=True)
class ClassifiedChange:
    note: ReleaseNoteItem
    category: ReleaseNoteCategory
    confidence: float
    mentioned_symbols: tuple[str, ...] = ()
    matched_project_symbols: tuple[str, ...] = ()
    relevance_score: float = 0.0


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
