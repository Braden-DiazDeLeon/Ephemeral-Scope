"""Tests for the reporting helpers in scripts/evaluate_classifiers.py.

The script produces the numbers quoted in the write-up, so the parts that
could quietly distort a comparison are pinned here.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from ephemeral_scope.domain.enums import ReleaseNoteCategory as Category
from ephemeral_scope.ml.dataset import LabeledNote

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_classifiers.py"


def _load_script():
    """Import by path; `scripts/` is deliberately not a package.

    Registered in ``sys.modules`` before execution because ``@dataclass``
    resolves annotations through ``sys.modules[cls.__module__]``.
    """
    spec = importlib.util.spec_from_file_location("evaluate_classifiers", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


evaluate_classifiers = _load_script()
UNCLASSIFIED = evaluate_classifiers.UNCLASSIFIED


def note(text: str, label: Category, section: str | None = None) -> LabeledNote:
    return LabeledNote(
        text=text,
        package_name="requests",
        release_version="2.32.0",
        source_url=None,
        section=section,
        suggested_label=None,
        verified_label=label,
    )


class TestUnclassifiedHandling:
    def test_rule_miss_is_not_scored_as_irrelevant(self):
        """Folding misses into IRRELEVANT would pay a method for declining
        to answer, which is how the keyword baseline was overstated before."""
        notes = [note("Mostly a meta update.", Category.IRRELEVANT)]

        predicted = evaluate_classifiers.predict_keyword(notes)

        assert predicted == [UNCLASSIFIED]

    def test_unclassified_never_counts_as_correct(self):
        notes = [note("Mostly a meta update.", Category.IRRELEVANT)]
        scored = evaluate_classifiers.Scored(
            "keyword_rule",
            "test",
            evaluate_classifiers.labels_of(notes),
            evaluate_classifiers.predict_keyword(notes),
        )

        assert evaluate_classifiers.metrics_for(scored)["accuracy"] == 0.0


class TestKeywordBaselineIsTextOnly:
    def test_section_is_withheld_from_the_keyword_baseline(self):
        """Otherwise the text-only and section-aware baselines collapse into
        the same method and the comparison says nothing."""
        notes = [note("Mostly a meta update.", Category.SECURITY_FIX, "Security")]

        text_only = evaluate_classifiers.predict_keyword(notes)
        with_section = evaluate_classifiers.predict_section_and_keyword(notes)

        assert text_only == [UNCLASSIFIED]
        assert with_section == ["security_fix"]


class TestAgreementRate:
    def test_identical_predictions(self):
        assert evaluate_classifiers.agreement_rate(["a", "b"], ["a", "b"]) == 1.0

    def test_no_overlap(self):
        assert evaluate_classifiers.agreement_rate(["a", "b"], ["c", "d"]) == 0.0

    def test_partial_overlap(self):
        rate = evaluate_classifiers.agreement_rate(["a", "b"], ["a", "d"])

        assert rate == pytest.approx(0.5)

    def test_empty_input_does_not_divide_by_zero(self):
        assert evaluate_classifiers.agreement_rate([], []) == 0.0


class TestMetrics:
    def test_reports_per_class_precision_recall_and_f1(self):
        notes = [
            note("Fixed a crash.", Category.BUG_FIX),
            note("Added an option.", Category.FEATURE),
        ]
        scored = evaluate_classifiers.Scored(
            "keyword_rule",
            "test",
            evaluate_classifiers.labels_of(notes),
            ["bug_fix", "feature"],
        )

        entry = evaluate_classifiers.metrics_for(scored)

        assert entry["examples"] == 2
        assert entry["accuracy"] == 1.0
        for values in entry["per_class"].values():
            assert {"precision", "recall", "f1", "support"} <= values.keys()

    def test_every_method_has_a_report_name(self):
        """The write-up quotes these strings, so a new method must be named."""
        assert set(evaluate_classifiers.METHOD_NAMES) == {
            "majority",
            "keyword_rule",
            "section_and_keyword",
            "tfidf",
            "hybrid",
        }


class TestConfusionRows:
    def test_matrix_is_square_over_observed_labels(self):
        scored = evaluate_classifiers.Scored(
            "hybrid", "test", ["bug_fix", "feature"], ["bug_fix", "bug_fix"]
        )

        rows = evaluate_classifiers.confusion_rows(scored)

        assert len(rows) == 4
        assert sum(row["count"] for row in rows) == 2
