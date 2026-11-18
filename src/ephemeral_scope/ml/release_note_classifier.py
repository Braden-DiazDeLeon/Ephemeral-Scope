"""Release note classification."""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ephemeral_scope.domain.enums import ReleaseNoteCategory, SelectionReason
from ephemeral_scope.domain.models import (
    ClassificationDecision,
    ClassifiedChange,
    ReleaseNoteItem,
)

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


@dataclass(frozen=True, slots=True)
class RuleOutcome:
    """What the deterministic rules concluded, and on what basis."""

    category: Category | None
    confidence: float
    source: SelectionReason


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
        """Label a statement, reporting how much to trust the result.

        Falls back to IRRELEVANT so callers always get a category. Prefer
        :meth:`label_with_source`, which reports "no rule matched" honestly.
        """
        outcome = self.label_with_source(text, section)
        if outcome.category is None:
            return Category.IRRELEVANT, 0.1
        return outcome.category, outcome.confidence

    def label_with_source(
        self, text: str, section: str | None = None
    ) -> RuleOutcome:
        """Label a statement, reporting which mechanism fired.

        A ``None`` category means no rule recognised the statement. That is
        deliberately not collapsed into IRRELEVANT: the hybrid policy needs
        to tell "the rules had nothing to say" apart from "the rules decided
        this does not matter", because only the first leaves room for the
        model to supply a category.
        """
        if section:
            mapped = SECTION_LABELS.get(section.strip().lower())
            if mapped is not None:
                return RuleOutcome(mapped, 0.8, SelectionReason.SECTION_RULE)

        for category, pattern in KEYWORD_RULES:
            if pattern.search(text):
                return RuleOutcome(category, 0.5, SelectionReason.KEYWORD_RULE)

        return RuleOutcome(None, 0.0, SelectionReason.NO_EVIDENCE)


def decide(
    rule: RuleOutcome,
    model_category: Category | None,
    model_confidence: float,
) -> ClassificationDecision:
    """Combine a rule outcome and a model prediction into one decision.

    An evidence hierarchy rather than a blend of probabilities. The two
    classifiers are not interchangeable: the rules are deterministic and
    auditable, while the model is a statistical guess trained on a few
    hundred hand-labelled statements. Averaging their scores would let the
    weaker signal quietly move an answer the rules were certain about, so
    instead the model may corroborate a rule or speak where no rule fired,
    but never overrule one.
    """
    agreement = (
        rule.category is not None
        and model_category is not None
        and rule.category == model_category
    )

    if rule.category is not None and agreement:
        selected, reason = rule.category, SelectionReason.RULE_MODEL_AGREEMENT
    elif rule.category is not None and model_category is not None:
        selected, reason = rule.category, SelectionReason.RULE_PREFERRED_OVER_MODEL
    elif rule.category is not None:
        # No model loaded at all, so name the rule that fired.
        selected, reason = rule.category, rule.source
    elif model_category is not None:
        selected, reason = model_category, SelectionReason.MODEL_SUGGESTION_ONLY
    else:
        selected, reason = None, SelectionReason.NO_EVIDENCE

    return ClassificationDecision(
        selected_category=selected,
        rule_category=rule.category,
        rule_confidence=rule.confidence,
        model_category=model_category,
        model_confidence=model_confidence,
        agreement=agreement,
        selection_reason=reason,
    )


class ReleaseNoteClassifier:
    """Assigns change category and confidence.

    Runs the keyword rules always and the trained scikit-learn pipeline when
    one is available, then reconciles them through :func:`decide`. Both
    answers are kept on the resulting :class:`ClassificationDecision`, so the
    report can say where a category came from and whether the two classifiers
    agreed.
    """

    def __init__(self, model_path: Path | None = None) -> None:
        self.keyword_classifier = KeywordReleaseNoteClassifier()
        self.model = _load_model(model_path) if model_path else None

    def classify(self, notes: Sequence[ReleaseNoteItem]) -> list[ClassifiedChange]:
        """Assign a category and confidence to each release note."""
        if not notes:
            return []

        model_categories, model_confidences = self._model_predictions(notes)

        changes = []
        for note, model_category, model_confidence in zip(
            notes, model_categories, model_confidences
        ):
            rule = self.keyword_classifier.label_with_source(note.text, note.section)
            decision = decide(rule, model_category, model_confidence)
            changes.append(
                ClassifiedChange(
                    note=note,
                    category=decision.selected_category,
                    confidence=decision.confidence,
                    decision=decision,
                )
            )
        return changes

    def _model_predictions(
        self, notes: Sequence[ReleaseNoteItem]
    ) -> tuple[list[Category | None], list[float]]:
        if self.model is None:
            return [None] * len(notes), [0.0] * len(notes)

        # Text only. The section heading is withheld from the model on
        # purpose: see the note on `to_xy` in ml.trainer.
        texts = [note.text for note in notes]
        predictions = [Category(value) for value in self.model.predict(texts)]
        return predictions, _confidences(self.model, texts)


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
