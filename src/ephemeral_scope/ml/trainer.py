"""TF-IDF training and evaluation for the release-note classifier."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ephemeral_scope.ml.dataset import LabeledNote, normalized_text

#: Packages whose text must never reach ``fit``. Requests is the end-to-end
#: demonstration package and appears throughout the test suite, so training
#: on it would make every demo result look better than it is.
HELD_OUT_PACKAGES = frozenset({"requests"})


class LeakageError(RuntimeError):
    """Raised when the same package appears in more than one split."""


@dataclass(frozen=True, slots=True)
class Evaluation:
    """Scores for one split."""

    accuracy: float
    macro_f1: float
    report: str
    support: int


def build_pipeline(**kwargs):
    """A word + character TF-IDF pipeline feeding logistic regression.

    Character n-grams matter here because release notes are dense with
    identifiers like ``verify=False`` that word tokenisation splits apart.
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline, FeatureUnion

    return Pipeline(
        [
            (
                "features",
                FeatureUnion(
                    [
                        (
                            "word",
                            TfidfVectorizer(
                                sublinear_tf=True,
                                ngram_range=(1, 2),
                                min_df=2,
                                strip_accents="unicode",
                            ),
                        ),
                        (
                            "char",
                            TfidfVectorizer(
                                analyzer="char_wb",
                                ngram_range=(3, 5),
                                min_df=3,
                                sublinear_tf=True,
                            ),
                        ),
                    ]
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=2000,
                    class_weight="balanced",
                    **kwargs,
                ),
            ),
        ]
    )


def check_splits(splits: dict[str, Sequence[LabeledNote]]) -> None:
    """Fail loudly when splits overlap by package, by text, or by hold-out.

    Statements from one project share vocabulary and phrasing, so a package
    appearing in both train and test inflates every score. Identical text can
    also cross splits independently of the package: boilerplate such as
    upgrade guidance gets copied between projects.
    """
    packages = {
        name: {note.package_name for note in notes} for name, notes in splits.items()
    }
    texts = {
        name: {normalized_text(note.text) for note in notes}
        for name, notes in splits.items()
    }

    names = sorted(splits)
    for index, left in enumerate(names):
        for right in names[index + 1 :]:
            shared = packages[left] & packages[right]
            if shared:
                raise LeakageError(
                    f"packages appear in both {left} and {right}: {sorted(shared)}"
                )
            shared_text = texts[left] & texts[right]
            if shared_text:
                raise LeakageError(
                    f"{len(shared_text)} duplicate statements appear in both "
                    f"{left} and {right}, e.g. {sorted(shared_text)[0]!r}"
                )

    leaked = packages.get("train", set()) & HELD_OUT_PACKAGES
    if leaked:
        raise LeakageError(f"held-out packages present in training data: {sorted(leaked)}")


def deduplicate_across(
    splits: dict[str, list[LabeledNote]], priority: Sequence[str] = ()
) -> dict[str, list[LabeledNote]]:
    """Drop statements that appear in more than one split.

    The first split to claim a text keeps it, so ``priority`` should list the
    evaluation splits first: a duplicate is worth more as a test example than
    as one more training row.
    """
    order = [name for name in priority if name in splits]
    order += [name for name in splits if name not in order]

    claimed: set[str] = set()
    result: dict[str, list[LabeledNote]] = {}
    for name in order:
        kept: list[LabeledNote] = []
        for note in splits[name]:
            key = normalized_text(note.text)
            if key in claimed:
                continue
            claimed.add(key)
            kept.append(note)
        result[name] = kept
    return {name: result[name] for name in splits}


def to_xy(notes: Sequence[LabeledNote]) -> tuple[list[str], list[str]]:
    """Turn labelled notes into model inputs, skipping unlabelled rows.

    Only the statement text is used. The section heading is deliberately
    withheld: suggested labels are derived from that heading, so feeding it
    back in would let the model read off its own label instead of learning
    from the prose. Section stays available for label suggestion, manual
    review, and analysis.
    """
    features: list[str] = []
    labels: list[str] = []
    for note in notes:
        if note.label is None:
            continue
        features.append(note.text)
        labels.append(note.label.value)
    return features, labels


def train(notes: Sequence[LabeledNote], **kwargs):
    """Fit a pipeline on labelled notes."""
    features, labels = to_xy(notes)
    if not features:
        raise ValueError("no labelled notes to train on")
    if len(set(labels)) < 2:
        raise ValueError(f"need at least two categories, found {set(labels)}")

    pipeline = build_pipeline(**kwargs)
    pipeline.fit(features, labels)
    return pipeline


def evaluate(model, notes: Sequence[LabeledNote]) -> Evaluation:
    """Score a fitted pipeline against a held-out split."""
    from sklearn.metrics import accuracy_score, classification_report, f1_score

    features, labels = to_xy(notes)
    if not features:
        return Evaluation(accuracy=0.0, macro_f1=0.0, report="no labelled notes", support=0)

    predictions = model.predict(features)
    return Evaluation(
        accuracy=float(accuracy_score(labels, predictions)),
        macro_f1=float(f1_score(labels, predictions, average="macro", zero_division=0)),
        report=classification_report(labels, predictions, zero_division=0),
        support=len(labels),
    )


def save_model(model, path: Path) -> None:
    import joblib

    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)


def label_distribution(notes: Sequence[LabeledNote]) -> Counter:
    return Counter(note.label.value for note in notes if note.label is not None)
