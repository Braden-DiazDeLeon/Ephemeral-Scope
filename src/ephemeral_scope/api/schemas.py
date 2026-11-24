"""API request / response schemas.

Requests are pydantic models so FastAPI rejects a malformed body before any
work is queued. Responses are plain dictionaries built from the domain
dataclasses here, which keeps the web layer out of the domain package: the
analysis pipeline does not know it is being served over HTTP.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field, field_validator, model_validator

from ephemeral_scope.domain.models import (
    AffectedUsage,
    AnalysisWarning,
    ApiChange,
    ApiUsage,
    ClassifiedChange,
    Dependency,
    RiskFinding,
    RiskReason,
    UpgradeReport,
    VulnerabilityRecord,
)

# PEP 508 project name.
_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")

#: Lines of source shown either side of an affected call site.
SNIPPET_CONTEXT = 3
#: A release can carry thousands of API changes. The report lists the ones
#: that land on the project in full and only samples the rest.
MAX_API_CHANGES = 200
MAX_USAGES = 500
_MAX_SNIPPET_LINE = 400


def valid_package_name(name: str) -> str:
    name = name.strip()
    if not name or len(name) > 100 or not _PACKAGE_NAME.match(name):
        raise ValueError(f"{name!r} is not a valid PyPI package name")
    return name


def valid_version(version: str) -> str:
    version = version.strip()
    if not version or len(version) > 64:
        raise ValueError("a version is required")
    try:
        Version(version)
    except InvalidVersion as error:
        raise ValueError(f"{version!r} is not a valid version") from error
    return version


class AnalysisCreate(BaseModel):
    """Body of ``POST /api/analyses``."""

    project_id: str = Field(min_length=1, max_length=64)
    package_name: str
    current_version: str
    target_version: str

    @field_validator("package_name")
    @classmethod
    def _package(cls, value: str) -> str:
        return valid_package_name(value)

    @field_validator("current_version", "target_version")
    @classmethod
    def _version(cls, value: str) -> str:
        return valid_version(value)

    @model_validator(mode="after")
    def _is_an_upgrade(self) -> AnalysisCreate:
        if Version(self.target_version) <= Version(self.current_version):
            raise ValueError("target_version must be newer than current_version")
        return self


def pinned_version(specifier: str | None) -> str | None:
    """The exact version a ``==X`` specifier names, else ``None``."""
    if not specifier:
        return None
    parts = [part.strip() for part in specifier.split(",")]
    if len(parts) != 1 or not parts[0].startswith("==") or parts[0].startswith("==="):
        return None
    candidate = parts[0][2:].strip()
    if "*" in candidate:
        return None
    try:
        Version(candidate)
    except InvalidVersion:
        return None
    return candidate


def dependency_dict(dependency: Dependency, root: Path | None = None) -> dict:
    return {
        "name": dependency.name,
        "canonical_name": canonicalize_name(dependency.name),
        "specifier": dependency.specifier,
        "pinned_version": pinned_version(dependency.specifier),
        "source_file": _relative(dependency.source_file, root),
    }


def report_dict(report: UpgradeReport, project_root: Path | None = None) -> dict:
    """Serialize a report for the browser.

    ``project_root`` is only used to read a few lines of source around each
    affected call site. Paths in the report are already project-relative.
    """
    evidence = report.evidence
    affected_keys = {
        (_posix(item.usage.file), item.usage.line, item.usage.symbol)
        for item in report.affected_usages
    }
    open_today = {record.vulnerability_id for record in evidence.current_vulnerabilities}
    return {
        "upgrade": {
            "package_name": report.upgrade.package_name,
            "current_version": report.upgrade.current_version,
            "target_version": report.upgrade.target_version,
        },
        "migration_risk": str(report.assessment.migration_risk),
        "upgrade_urgency": str(report.assessment.upgrade_urgency),
        "migration_reasons": _reasons(report.assessment.migration_reasons),
        "urgency_reasons": _reasons(report.assessment.urgency_reasons),
        "inference_engine": report.inference_engine,
        "declared_dependency": (
            None
            if report.declared_dependency is None
            else dependency_dict(report.declared_dependency)
        ),
        "affected_usages": [
            _affected(item, project_root) for item in report.affected_usages
        ],
        "usages": [
            {
                **_usage(usage),
                "affected": (_posix(usage.file), usage.line, usage.symbol)
                in affected_keys,
            }
            for usage in report.usages[:MAX_USAGES]
        ],
        "usage_count": len(report.usages),
        "api_changes": [
            _change(change) for change in report.api_changes[:MAX_API_CHANGES]
        ],
        "api_change_count": len(report.api_changes),
        "release_notes": [_note(change) for change in report.classified_changes],
        "classifier_disagreement_count": len(report.classifier_disagreements),
        "vulnerabilities": {
            "fixed": _vulnerabilities(evidence.fixed_by_upgrade),
            "remaining": _vulnerabilities(
                record
                for record in evidence.target_vulnerabilities
                if record.vulnerability_id in open_today
            ),
            "introduced": _vulnerabilities(evidence.introduced_by_upgrade),
        },
        "findings": [_finding(finding) for finding in report.findings],
        "recommended_tests": list(report.recommended_tests),
        "migration_actions": list(report.migration_actions),
        "warnings": _warnings(report.warnings),
    }


def _reasons(reasons: Iterable[RiskReason]) -> list[dict]:
    return [
        {"level": str(reason.level), "rule": reason.rule_name, "subject": reason.subject}
        for reason in reasons
    ]


def _usage(usage: ApiUsage) -> dict:
    return {
        "symbol": usage.symbol,
        "file": _posix(usage.file),
        "line": usage.line,
        "column": usage.column,
        "usage_kind": str(usage.usage_kind),
        "import_alias": usage.import_alias,
    }


def _change(change: ApiChange) -> dict:
    return {
        "symbol": change.symbol,
        "change_type": str(change.change_type),
        "old_signature": change.old_signature,
        "new_signature": change.new_signature,
        "details": change.details,
    }


def _affected(item: AffectedUsage, project_root: Path | None) -> dict:
    return {
        **_usage(item.usage),
        "change": _change(item.change),
        "snippet": source_snippet(project_root, item.usage.file, item.usage.line),
    }


def _note(change: ClassifiedChange) -> dict:
    note = change.note
    return {
        "text": note.text,
        "release_version": note.release_version,
        "section": note.section,
        "source_url": note.source_url,
        "category": None if change.category is None else str(change.category),
        "confidence": round(change.confidence, 4),
        "relevance_score": round(change.relevance_score, 4),
        "mentioned_symbols": list(change.mentioned_symbols),
        "matched_project_symbols": list(change.matched_project_symbols),
        "decision": None if change.decision is None else change.decision.to_dict(),
    }


def _vulnerabilities(records: Iterable[VulnerabilityRecord]) -> list[dict]:
    return [
        {
            "id": record.vulnerability_id,
            "summary": record.summary,
            "fixed_versions": list(record.fixed_versions),
            "source_url": record.source_url,
        }
        for record in records
    ]


def _finding(finding: RiskFinding) -> dict:
    return {
        "risk_level": str(finding.risk_level),
        "reason": finding.reason,
        "rule_name": finding.rule_name,
        "file": None if finding.file is None else _posix(finding.file),
        "line": finding.line,
        "symbol": finding.symbol,
        "supporting_facts": list(finding.supporting_facts),
        "recommendation": finding.recommendation,
    }


def _warnings(warnings: Iterable[AnalysisWarning]) -> list[dict]:
    return [
        {"component": warning.component, "message": warning.message}
        for warning in warnings
    ]


def _posix(path: Path) -> str:
    """Forward slashes on every platform, so reports read the same."""
    return Path(path).as_posix()


def _relative(path: Path, root: Path | None) -> str:
    path = Path(path)
    if root is not None:
        try:
            return path.relative_to(root).as_posix()
        except ValueError:
            pass
    return path.name if path.is_absolute() else path.as_posix()


def source_snippet(
    project_root: Path | None, file: Path, line: int, context: int = SNIPPET_CONTEXT
) -> dict | None:
    """A few lines around ``line`` of ``file``, or ``None`` if unreadable.

    ``file`` comes from the report, but it is still resolved and checked
    against the project root before it is opened.
    """
    if project_root is None or line < 1:
        return None
    root = Path(project_root).resolve()
    try:
        target = (root / file).resolve()
        if not target.is_relative_to(root) or not target.is_file():
            return None
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if line > len(lines):
        return None
    start = max(1, line - context)
    end = min(len(lines), line + context)
    return {
        "start_line": start,
        "highlight_line": line,
        "lines": [text[:_MAX_SNIPPET_LINE] for text in lines[start - 1 : end]],
    }
