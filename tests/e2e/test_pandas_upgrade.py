"""Pandas 1.5.3 to 2.0.0: DataFrame.append was removed.

The recorded test replays the symbols Griffe recovered from the wheels.
The live test builds those snapshots from PyPI again, which is the check
that the wheel still exposes the method as source.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ephemeral_scope.domain.enums import ChangeType, RiskLevel
from ephemeral_scope.domain.models import EvidenceBundle
from ephemeral_scope.main import create_service
from tests.e2e.conftest import (
    REQUIRES_PROLOG,
    RecordedEvidence,
    RecordedSnapshots,
    pandas_request,
    pandas_symbols,
    recorded_service,
)


def assert_pandas_report(report) -> None:
    assert report.declared_dependency is not None
    assert report.declared_dependency.specifier == "==1.5.3"
    assert report.overall_risk is RiskLevel.HIGH
    assert report.overall_risk == report.assessment.migration_risk
    assert any(
        item.usage.symbol == "pandas.DataFrame.append"
        and item.change.change_type is ChangeType.REMOVED
        for item in report.affected_usages
    )
    assert Path("src/report.py") in report.affected_files
    assert "tests/test_report.py" in report.recommended_tests
    assert report.inference_engine == "prolog"
    assert not any(warning.component == "api_snapshot" for warning in report.warnings)


@REQUIRES_PROLOG
@pytest.mark.integration
def test_pandas_upgrade_from_recorded_snapshot():
    service = recorded_service(
        snapshot_builder=RecordedSnapshots(pandas_symbols()),
        evidence_collector=RecordedEvidence(EvidenceBundle()),
    )

    assert_pandas_report(service.analyze(pandas_request()))


@REQUIRES_PROLOG
@pytest.mark.live
@pytest.mark.integration
def test_pandas_upgrade_against_pypi():
    """Griffe reads the published wheels. A snapshot warning means it could not."""
    assert_pandas_report(create_service().analyze(pandas_request()))
