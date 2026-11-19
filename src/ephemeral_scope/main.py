"""Composition root.

`create_service` is the only place that reads process configuration and
builds the production collaborators. Tests construct `UpgradeAnalysisService`
directly so they do not load the model or open caches they did not ask for.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from ephemeral_scope.analysis.ast_usage_analyzer import AstUsageAnalyzer
from ephemeral_scope.analysis.test_mapper import TestMapper
from ephemeral_scope.analysis.usage_change_matcher import UsageChangeMatcher
from ephemeral_scope.domain.models import AnalysisWarning
from ephemeral_scope.evidence.evidence_collector import EvidenceCollector
from ephemeral_scope.evidence.osv_client import OSVClient
from ephemeral_scope.evidence.release_notes_client import ReleaseNotesClient
from ephemeral_scope.http_cache import DEFAULT_CACHE_DIR, HttpCache
from ephemeral_scope.inference.fact_builder import FactBuilder
from ephemeral_scope.inference.prolog_risk_engine import PrologRiskEngine
from ephemeral_scope.ingestion.dependency_parser import DependencyParser
from ephemeral_scope.ingestion.project_loader import ProjectLoader
from ephemeral_scope.ml.release_note_classifier import ReleaseNoteClassifier
from ephemeral_scope.ml.relevance_matcher import RelevanceMatcher
from ephemeral_scope.packages.api_comparator import ApiComparator
from ephemeral_scope.packages.api_snapshot_builder import ApiSnapshotBuilder
from ephemeral_scope.packages.pypi_client import DEFAULT_PACKAGE_CACHE, PyPIClient
from ephemeral_scope.reporting.report_builder import ReportBuilder
from ephemeral_scope.services.upgrade_analysis_service import UpgradeAnalysisService

#: Training writes here. A source checkout prefers this file so a retrain is
#: picked up without rebuilding the wheel. It is not present after install.
CHECKOUT_MODEL = (
    Path(__file__).resolve().parents[2] / "models" / "release_note_classifier.joblib"
)
PACKAGED_MODEL = "release_note_classifier.joblib"

DEFAULT_TIMEOUT_SECONDS = 30.0

_TRUE = {"1", "true", "yes", "on"}


class ConfigurationError(ValueError):
    """An environment variable is set but not usable."""


@dataclass(frozen=True, slots=True)
class Settings:
    """Process configuration. Every field has a default except the model.

    The model is resolved rather than defaulted: an explicit
    ``EPHEMERAL_SCOPE_MODEL_PATH``, then the checkout file, then the copy
    packaged inside ``ephemeral_scope.ml``. None of those means the service
    runs the keyword rules and says so.
    """

    model_path: Path | None
    http_cache_dir: Path
    package_cache_dir: Path
    offline: bool
    timeout: float
    swipl: str | None

    @classmethod
    def from_environ(cls, environ: Mapping[str, str] | None = None) -> Settings:
        environ = os.environ if environ is None else environ
        return cls(
            model_path=resolve_model_path(environ),
            http_cache_dir=_path(
                environ, "EPHEMERAL_SCOPE_HTTP_CACHE", DEFAULT_CACHE_DIR
            ),
            package_cache_dir=_path(
                environ, "EPHEMERAL_SCOPE_PACKAGE_CACHE", DEFAULT_PACKAGE_CACHE
            ),
            offline=_flag(environ.get("EPHEMERAL_SCOPE_OFFLINE")),
            timeout=_timeout(environ.get("EPHEMERAL_SCOPE_TIMEOUT")),
            swipl=_text(environ.get("EPHEMERAL_SCOPE_SWIPL")),
        )


def model_path(environ: Mapping[str, str] | None = None) -> Path | None:
    """Where the verified classifier is, or None when nothing provides one."""
    return resolve_model_path(os.environ if environ is None else environ)


def resolve_model_path(environ: Mapping[str, str]) -> Path | None:
    configured = _text(environ.get("EPHEMERAL_SCOPE_MODEL_PATH"))
    if configured is not None:
        return Path(configured)
    if CHECKOUT_MODEL.is_file():
        return CHECKOUT_MODEL
    return _packaged_model()


def create_service(settings: Settings | None = None) -> UpgradeAnalysisService:
    """Build the service the application actually runs."""
    settings = settings or Settings.from_environ()
    http = HttpCache(
        cache_dir=settings.http_cache_dir,
        timeout=settings.timeout,
        offline=settings.offline,
    )
    engine = PrologRiskEngine(swipl=settings.swipl, timeout=settings.timeout)
    return UpgradeAnalysisService(
        project_loader=ProjectLoader(),
        usage_analyzer=AstUsageAnalyzer(),
        snapshot_builder=ApiSnapshotBuilder(
            pypi_client=PyPIClient(
                cache_dir=settings.package_cache_dir,
                timeout=settings.timeout,
            )
        ),
        comparator=ApiComparator(),
        matcher=UsageChangeMatcher(),
        evidence_collector=EvidenceCollector(
            release_notes_client=ReleaseNotesClient(http=http),
            osv_client=OSVClient(http=http),
        ),
        dependency_parser=DependencyParser(),
        release_note_classifier=_classifier(settings.model_path),
        relevance_matcher=RelevanceMatcher,
        test_mapper=TestMapper(),
        fact_builder=FactBuilder,
        risk_engine=engine,
        report_builder=ReportBuilder(engine=engine),
    )


def _classifier(path: Path | None) -> ReleaseNoteClassifier:
    if path is None:
        classifier = ReleaseNoteClassifier()
        classifier.warning = AnalysisWarning(
            "model",
            "TF-IDF model unavailable: set EPHEMERAL_SCOPE_MODEL_PATH "
            "or install the packaged classifier",
        )
        return classifier
    return ReleaseNoteClassifier(model_path=path)


def _packaged_model() -> Path | None:
    """The joblib shipped inside the package, for an installed wheel."""
    resource = files("ephemeral_scope.ml").joinpath(PACKAGED_MODEL)
    if not resource.is_file():
        return None
    located = Path(str(resource))
    return located if located.is_file() else None


def _path(environ: Mapping[str, str], name: str, default: Path) -> Path:
    configured = _text(environ.get(name))
    return Path(configured) if configured is not None else default


def _text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _flag(value: str | None) -> bool:
    return (value or "").strip().lower() in _TRUE


def _timeout(value: str | None) -> float:
    if value is None or not value.strip():
        return DEFAULT_TIMEOUT_SECONDS
    try:
        timeout = float(value)
    except ValueError as exc:
        raise ConfigurationError(
            f"EPHEMERAL_SCOPE_TIMEOUT must be a number of seconds, got {value!r}"
        ) from exc
    if timeout <= 0:
        raise ConfigurationError(
            f"EPHEMERAL_SCOPE_TIMEOUT must be positive, got {timeout}"
        )
    return timeout
