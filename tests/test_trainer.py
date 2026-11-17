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
                "train": [note("x y z", Category.FEATURE, "numpy")],
                "test": [note("x y z", Category.FEATURE, "flask")],
            }
        )

    def test_shared_package_is_rejected(self):
        with pytest.raises(LeakageError, match="numpy"):
            check_splits(
                {
                    "train": [note("x y z", Category.FEATURE, "numpy")],
                    "test": [note("a b c", Category.FEATURE, "numpy")],
                }
            )

    def test_held_out_package_in_training_is_rejected(self):
        with pytest.raises(LeakageError, match="requests"):
            check_splits({"train": [note("x y z", Category.FEATURE, "requests")]})

    def test_held_out_package_is_allowed_elsewhere(self):
        check_splits({"test": [note("x y z", Category.FEATURE, "requests")]})


class TestToXy:
    def test_unlabelled_notes_are_skipped(self):
        notes = [
            LabeledNote("a", "p", "1", None, None, None),
            note("Fixed a crash", Category.BUG_FIX, "p"),
        ]
        features, labels = to_xy(notes)
        assert len(features) == 1 and labels == ["bug_fix"]

    def test_section_is_folded_into_the_features(self):
        labelled = LabeledNote(
            "Fixed it", "p", "1", None, "Security", None, Category.SECURITY_FIX
        )
        features, _ = to_xy([labelled])
        assert features[0].startswith("__section_security__")


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
