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
