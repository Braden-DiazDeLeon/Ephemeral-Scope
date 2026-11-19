"""Composition root.

The service itself stays free of the trained model so tests can construct
it without loading scikit-learn. This is the place that decides which
model a real analysis uses.
"""

from __future__ import annotations

import os
from pathlib import Path

from ephemeral_scope.ml.release_note_classifier import ReleaseNoteClassifier
from ephemeral_scope.services.upgrade_analysis_service import UpgradeAnalysisService

DEFAULT_MODEL_PATH = Path("models/release_note_classifier.joblib")


def model_path() -> Path:
    """The verified classifier, unless EPHEMERAL_SCOPE_MODEL_PATH overrides it."""
    return Path(os.environ.get("EPHEMERAL_SCOPE_MODEL_PATH", DEFAULT_MODEL_PATH))


def create_service() -> UpgradeAnalysisService:
    """The application configuration: hybrid classification, not rules alone."""
    return UpgradeAnalysisService(
        release_note_classifier=ReleaseNoteClassifier(model_path=model_path())
    )
