"""Release note classification."""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from pathlib import Path

from ephemeral_scope.domain.enums import ReleaseNoteCategory
from ephemeral_scope.domain.models import ClassifiedChange, ReleaseNoteItem

logger = logging.getLogger(__name__)

Category = ReleaseNoteCategory

#: Headings map to a category far more reliably than prose does, so a
#: recognised section outranks any keyword match.
SECTION_LABELS: dict[str, Category] = {
    "security": Category.SECURITY_FIX,
    "security fixes": Category.SECURITY_FIX,
    "vulnerabilities": Category.SECURITY_FIX,
    "breaking": Category.BREAKING_CHANGE,
    "breaking changes": Category.BREAKING_CHANGE,
    "backwards incompatible changes": Category.BREAKING_CHANGE,
    "backwards-incompatible changes": Category.BREAKING_CHANGE,
    "removals": Category.BREAKING_CHANGE,
    "removed": Category.BREAKING_CHANGE,
    "deprecations": Category.DEPRECATION,
    "deprecated": Category.DEPRECATION,
    "pending deprecation": Category.DEPRECATION,
    "bugfixes": Category.BUG_FIX,
    "bug fixes": Category.BUG_FIX,
    "fixes": Category.BUG_FIX,
    "fixed": Category.BUG_FIX,
    "features": Category.FEATURE,
    "new features": Category.FEATURE,
    "added": Category.FEATURE,
    "improvements": Category.FEATURE,
    "enhancements": Category.FEATURE,
    "changes": Category.BEHAVIORAL_CHANGE,
    "changed": Category.BEHAVIORAL_CHANGE,
    "behaviour changes": Category.BEHAVIORAL_CHANGE,
    "behavior changes": Category.BEHAVIORAL_CHANGE,
    "documentation": Category.IRRELEVANT,
    "docs": Category.IRRELEVANT,
    "packaging": Category.IRRELEVANT,
    "dependencies": Category.IRRELEVANT,
    "typing": Category.IRRELEVANT,
    "internal": Category.IRRELEVANT,
    "misc": Category.IRRELEVANT,
}

#: Ordered strongest signal first: a line that is both a security fix and a
#: bug fix should be reported as security fix.
KEYWORD_RULES: list[tuple[Category, re.Pattern[str]]] = [
    (
        Category.SECURITY_FIX,
        re.compile(
            r"\b(cve-\d{4}-\d+|ghsa-[\w-]+|security (?:fix|issue|advisory|"
            r"vulnerabilit)|vulnerabilit\w*|exploit|sanitiz\w+ )",
            re.I,
        ),
    ),
    (
        Category.BREAKING_CHANGE,
        re.compile(
            r"\b(breaking change|backwards?[- ]incompatible|"
            r"no longer (?:support|accept|available|work)|"
            r"(?:has|have|was|were|is|are) been removed|"
            r"remove[sd]? (?:the )?(?:support|deprecated|argument|parameter|"
            r"method|function|class|module|option)|"
            r"renamed (?:the )?(?:argument|parameter|method|function|class)|"
            r"now raises|dropped support|requires? (?:at least )?python)\b",
            re.I,
        ),
    ),
    (
        Category.DEPRECATION,
        re.compile(r"\b(deprecat\w+|will be removed|pending removal)\b", re.I),
    ),
    (
        Category.BEHAVIORAL_CHANGE,
        re.compile(
            r"\b(default (?:value )?(?:is |has )?(?:now |changed)|"
            r"now returns|now uses|now defaults|behaviou?r (?:has )?changed|"
            r"changed the behaviou?r)\b",
            re.I,
        ),
    ),
    # Housekeeping markers outrank "fixed"/"added": a typo correction or a
    # CI tweak is noise for an upgrade decision regardless of its verb.
    (
        Category.IRRELEVANT,
        re.compile(
            r"\b(typo|docstring|changelog|readme|ci|lint|formatting|"
            r"test suite|bump|pre-commit)\b",
            re.I,
        ),
    ),
    (
        Category.BUG_FIX,
        re.compile(r"\b(fix(?:ed|es)?|bug|regression|crash|traceback|incorrect)\b", re.I),
    ),
    (
        Category.FEATURE,
        re.compile(
            r"\b(add(?:ed|s)?|new (?:option|method|parameter|argument|class|"
            r"function|feature)|introduce[sd]?|support for|now supports|"
            r"implement(?:ed|s)?)\b",
            re.I,
        ),
    ),
    (
        Category.IRRELEVANT,
        re.compile(r"\b(documentation|docs)\b", re.I),
    ),
]


class KeywordReleaseNoteClassifier:
    """Rule-based labelling used to seed the dataset and as a fallback.

    Section headings are trusted first because they are authored as
    categories; keyword rules only run when the heading is missing or
    unrecognised.
    """

    def label(self, text: str, section: str | None = None) -> Category | None:
        """Return a best-guess category, or ``None`` when nothing matches."""
        if section:
            mapped = SECTION_LABELS.get(section.strip().lower())
            if mapped is not None:
                return mapped
        for category, pattern in KEYWORD_RULES:
            if pattern.search(text):
                return category
        return None

    def label_with_confidence(
        self, text: str, section: str | None = None
    ) -> tuple[Category, float]:
        """Label a statement, reporting how much to trust the result."""
        if section and section.strip().lower() in SECTION_LABELS:
            return SECTION_LABELS[section.strip().lower()], 0.8
        guess = self.label(text, section=None)
        if guess is None:
            return Category.IRRELEVANT, 0.1
        return guess, 0.5


class ReleaseNoteClassifier:
    """Assigns change category and confidence.

    Uses a trained scikit-learn pipeline when one is available and falls back
    to the keyword rules, so the runtime pipeline works before any model has
    been trained.
    """

    def __init__(self, model_path: Path | None = None) -> None:
        self.keyword_classifier = KeywordReleaseNoteClassifier()
        self.model = _load_model(model_path) if model_path else None

    def classify(self, notes: Sequence[ReleaseNoteItem]) -> list[ClassifiedChange]:
        """Assign a category and confidence to each release note."""
        if not notes:
            return []
        if self.model is not None:
            return self._classify_with_model(notes)
        return [
            ClassifiedChange(note=note, category=category, confidence=confidence)
            for note in notes
            for category, confidence in [
                self.keyword_classifier.label_with_confidence(note.text, note.section)
            ]
        ]

    def _classify_with_model(
        self, notes: Sequence[ReleaseNoteItem]
    ) -> list[ClassifiedChange]:
        # Text only. The section heading is withheld from the model on
        # purpose: see the note on `to_xy` in ml.trainer.
        texts = [note.text for note in notes]
        predictions = self.model.predict(texts)
        confidences = _confidences(self.model, texts)
        return [
            ClassifiedChange(
                note=note,
                category=ReleaseNoteCategory(prediction),
                confidence=confidence,
            )
            for note, prediction, confidence in zip(notes, predictions, confidences)
        ]


def _confidences(model, texts: list[str]) -> list[float]:
    predict_proba = getattr(model, "predict_proba", None)
    if predict_proba is None:
        return [0.5] * len(texts)
    return [float(max(row)) for row in predict_proba(texts)]


def _load_model(model_path: Path):
    try:
        import joblib

        return joblib.load(model_path)
    except (ImportError, OSError, ValueError) as exc:
        logger.warning("Falling back to keyword rules; could not load model: %s", exc)
        return None
