"""Tests for domain models – construction and serialization."""

from dataclasses import asdict
from pathlib import Path

from ephemeral_scope.domain.enums import RiskLevel
from ephemeral_scope.domain.models import (
    AnalysisRequest,
    DependencyUpgrade,
    UpgradeReport,
)


def test_analysis_request_construction():
    req = AnalysisRequest(
        project_path=Path("/tmp/project"),
        package_name="pandas",
        current_version="1.5.3",
        target_version="2.0.0",
    )
    assert req.package_name == "pandas"
    assert req.project_path == Path("/tmp/project")


def test_analysis_request_serialization():
    req = AnalysisRequest(
        project_path=Path("/tmp/project"),
        package_name="requests",
        current_version="2.28.0",
        target_version="2.31.0",
    )
    d = asdict(req)
    assert d["package_name"] == "requests"
    assert d["current_version"] == "2.28.0"


def test_empty_upgrade_report():
    upgrade = DependencyUpgrade(
        package_name="pandas",
        current_version="1.5.3",
        target_version="2.0.0",
    )
    report = UpgradeReport(upgrade=upgrade, overall_risk=RiskLevel.UNKNOWN)
    assert report.overall_risk == RiskLevel.UNKNOWN
    assert report.usages == ()
    assert report.findings == ()


def test_upgrade_report_serialization():
    upgrade = DependencyUpgrade(
        package_name="pandas",
        current_version="1.5.3",
        target_version="2.0.0",
    )
    report = UpgradeReport(upgrade=upgrade, overall_risk=RiskLevel.LOW)
    d = asdict(report)
    assert d["upgrade"]["package_name"] == "pandas"
    assert d["overall_risk"] == RiskLevel.LOW
    assert d["migration_actions"] == ()


class TestRiskLevelOrdering:
    """The single severity ordering: HIGH > MEDIUM > LOW > UNKNOWN."""

    def test_the_ranks_are_strictly_ordered(self):
        assert (
            RiskLevel.UNKNOWN.rank
            < RiskLevel.LOW.rank
            < RiskLevel.MEDIUM.rank
            < RiskLevel.HIGH.rank
        )

    def test_highest_picks_the_most_severe(self):
        assert RiskLevel.highest([RiskLevel.LOW, RiskLevel.HIGH, RiskLevel.MEDIUM]) is (
            RiskLevel.HIGH
        )

    def test_unknown_loses_to_every_derived_level(self):
        assert RiskLevel.highest([RiskLevel.UNKNOWN, RiskLevel.LOW]) is RiskLevel.LOW

    def test_the_empty_default_is_the_enum_member_not_its_value(self):
        """A bare LOW inside the Enum body would be the string "low",
        which passes == but fails is, and silently breaks identity checks."""
        assert RiskLevel.highest([]) is RiskLevel.LOW
        assert isinstance(RiskLevel.highest([]), RiskLevel)

    def test_an_explicit_default_is_honoured(self):
        assert RiskLevel.highest([], default=RiskLevel.UNKNOWN) is RiskLevel.UNKNOWN
