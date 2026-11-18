"""Tests for TF-IDF training, split validation, and model round-tripping."""

from pathlib import Path

import pytest

from ephemeral_scope.domain.enums import ReleaseNoteCategory as Category
from ephemeral_scope.domain.models import ReleaseNoteItem
from ephemeral_scope.ml.dataset import LabeledNote
from ephemeral_scope.ml.release_note_classifier import ReleaseNoteClassifier
from ephemeral_scope.ml.trainer import (
    LeakageError,
    check_splits,
    deduplicate_across,
    evaluate,
    label_distribution,
    save_model,
    to_xy,
    train,
)

SECURITY = [
    "Fixes CVE-2023-32681 in the proxy handler",
    "Resolves a security vulnerability in the parser",
    "Patched an exploit in the session handler",
    "Security fix for the cookie jar leak",
    "Fixes GHSA-9wx4-h78v-vm56 affecting verification",
    "Resolves a vulnerability in certificate handling",
]
BREAKING = [
    "DataFrame.append has been removed in this release",
    "This is a breaking change to the request API",
    "Dropped support for Python 3.7 entirely",
    "Removed the deprecated timeout argument",
    "Backwards-incompatible change to the session API",
    "The old parser module has been removed",
]


def note(text: str, label: Category, package: str) -> LabeledNote:
    return LabeledNote(
        text=text,
        package_name=package,
        release_version="1.0",
        source_url=None,
        section=None,
        suggested_label=None,
        verified_label=label,
    )


@pytest.fixture()
def corpus() -> list[LabeledNote]:
    notes = [note(t, Category.SECURITY_FIX, "pkg_a") for t in SECURITY]
    notes += [note(t, Category.BREAKING_CHANGE, "pkg_b") for t in BREAKING]
    return notes


class TestCheckSplits:
    def test_disjoint_packages_pass(self):
        check_splits(
            {
                "train": [note("Added a timeout option.", Category.FEATURE, "numpy")],
                "test": [note("Added a retry option.", Category.FEATURE, "flask")],
            }
        )

    def test_shared_package_is_rejected(self):
        with pytest.raises(LeakageError, match="numpy"):
            check_splits(
                {
                    "train": [note("Added a timeout option.", Category.FEATURE, "numpy")],
                    "test": [note("Added a retry option.", Category.FEATURE, "numpy")],
                }
            )

    def test_held_out_package_in_training_is_rejected(self):
        with pytest.raises(LeakageError, match="requests"):
            check_splits(
                {"train": [note("Added an option.", Category.FEATURE, "requests")]}
            )

    def test_held_out_package_is_allowed_elsewhere(self):
        check_splits({"test": [note("Added an option.", Category.FEATURE, "requests")]})

    def test_duplicate_text_across_splits_is_rejected(self):
        """Boilerplate gets copied between projects, crossing splits."""
        shared = "See the upgrade guide before installing this release."
        with pytest.raises(LeakageError, match="duplicate statements"):
            check_splits(
                {
                    "validation": [note(shared, Category.IRRELEVANT, "click")],
                    "test": [note(shared, Category.IRRELEVANT, "flask")],
                }
            )

    def test_duplicate_detection_ignores_case_and_spacing(self):
        with pytest.raises(LeakageError, match="duplicate statements"):
            check_splits(
                {
                    "validation": [note("Upgrade the parser now.", Category.FEATURE, "click")],
                    "test": [note("UPGRADE   the  parser now.", Category.FEATURE, "flask")],
                }
            )

    def test_distinct_text_passes(self):
        check_splits(
            {
                "validation": [note("Added a timeout option.", Category.FEATURE, "click")],
                "test": [note("Removed the legacy parser.", Category.BREAKING_CHANGE, "flask")],
            }
        )


class TestDeduplicateAcross:
    def test_removes_the_duplicate_from_the_lower_priority_split(self):
        shared = "See the upgrade guide before installing."
        splits = {
            "train": [note(shared, Category.IRRELEVANT, "numpy")],
            "test": [note(shared, Category.IRRELEVANT, "flask")],
        }
        result = deduplicate_across(splits, priority=["test", "validation", "train"])
        assert len(result["test"]) == 1
        assert result["train"] == []

    def test_output_passes_the_split_check(self):
        shared = "See the upgrade guide before installing."
        splits = {
            "train": [note(shared, Category.IRRELEVANT, "numpy")],
            "test": [
                note(shared, Category.IRRELEVANT, "flask"),
                note("Removed the legacy parser.", Category.BREAKING_CHANGE, "flask"),
            ],
        }
        check_splits(deduplicate_across(splits, priority=["test", "train"]))

    def test_preserves_split_order(self):
        splits = {
            "train": [note("Added an option.", Category.FEATURE, "numpy")],
            "test": [note("Removed a thing.", Category.BREAKING_CHANGE, "flask")],
        }
        assert list(deduplicate_across(splits).keys()) == ["train", "test"]


class TestToXy:
    def test_unlabelled_notes_are_skipped(self):
        notes = [
            LabeledNote("a", "p", "1", None, None, None),
            note("Fixed a crash", Category.BUG_FIX, "p"),
        ]
        features, labels = to_xy(notes)
        assert len(features) == 1 and labels == ["bug_fix"]

    def test_section_is_withheld_from_the_model(self):
        """Labels are derived from the section, so feeding it back leaks."""
        labelled = LabeledNote(
            "Fixed it", "p", "1", None, "Security", None, Category.SECURITY_FIX
        )
        features, _ = to_xy([labelled])
        assert features == ["Fixed it"]
        assert "security" not in features[0].lower()


class TestTraining:
    def test_learns_to_separate_categories(self, corpus):
        model = train(corpus)
        assert model.predict(["Fixes CVE-2024-1111 in the handler"])[0] == (
            "security_fix"
        )
        assert model.predict(["Dropped support for Python 3.8"])[0] == (
            "breaking_change"
        )

    def test_requires_labelled_data(self):
        with pytest.raises(ValueError, match="no labelled notes"):
            train([LabeledNote("a", "p", "1", None, None, None)])

    def test_requires_two_categories(self):
        single = [note(t, Category.SECURITY_FIX, "pkg_a") for t in SECURITY]
        with pytest.raises(ValueError, match="at least two categories"):
            train(single)

    def test_evaluate_scores_a_split(self, corpus):
        model = train(corpus)
        scores = evaluate(model, corpus)
        assert scores.support == len(corpus)
        assert 0.0 <= scores.accuracy <= 1.0

    def test_evaluate_handles_an_empty_split(self, corpus):
        assert evaluate(train(corpus), []).support == 0

    def test_label_distribution(self, corpus):
        assert label_distribution(corpus) == {"security_fix": 6, "breaking_change": 6}


class TestSavedModel:
    def test_round_trips_through_the_runtime_classifier(self, corpus, tmp_path: Path):
        path = tmp_path / "model.joblib"
        save_model(train(corpus), path)

        classifier = ReleaseNoteClassifier(model_path=path)
        assert classifier.model is not None

        results = classifier.classify(
            [ReleaseNoteItem(text="Fixes CVE-2024-9999", release_version="1.0")]
        )
        assert results[0].category == Category.SECURITY_FIX
        assert 0.0 <= results[0].confidence <= 1.0
