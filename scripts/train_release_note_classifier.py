#!/usr/bin/env python3
"""Train the release-note classifier from verified JSONL.

    load verified JSONL -> validate splits -> train TF-IDF -> evaluate -> save

Run manually. The web application never invokes this.

    python scripts/train_release_note_classifier.py \
        --train data/train.jsonl \
        --validation data/validation.jsonl \
        --test data/test.jsonl \
        --out models/release_note_classifier.joblib
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ephemeral_scope.ml.dataset import LabeledNote, read_jsonl
from ephemeral_scope.ml.trainer import (
    Evaluation,
    LeakageError,
    check_splits,
    evaluate,
    label_distribution,
    save_model,
    train,
)


#: Marks a model trained on keyword guesses rather than verified labels.
WEAK_SUFFIX = "_weak"


def load(path: Path | None, require_verified: bool) -> list[LabeledNote]:
    if path is None:
        return []
    notes = read_jsonl(path)
    if require_verified:
        verified = [note for note in notes if note.verified_label is not None]
        if not verified:
            raise SystemExit(
                f"{path}: no `verified_label` values found. Review the dataset "
                f"before training, or pass --allow-suggested to train on "
                f"keyword guesses."
            )
        return verified
    return [note for note in notes if note.label is not None]


def report(name: str, scores: Evaluation) -> None:
    print(f"\n{name} (n={scores.support})")
    print(f"  accuracy  {scores.accuracy:.3f}")
    print(f"  macro F1  {scores.macro_f1:.3f}")
    print(scores.report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", type=Path, required=True)
    parser.add_argument("--validation", type=Path)
    parser.add_argument("--test", type=Path)
    parser.add_argument(
        "--out", type=Path, default=Path("models/release_note_classifier.joblib")
    )
    parser.add_argument(
        "--allow-suggested",
        action="store_true",
        help="train on keyword suggestions where no verified label exists",
    )
    args = parser.parse_args()

    # A model trained on keyword guesses only reproduces the regexes, so it
    # must never land on the path the runtime loads. Renaming one by hand
    # already failed once; make the script refuse instead.
    if args.allow_suggested and not args.out.stem.endswith(WEAK_SUFFIX):
        print(
            f"Refusing to write {args.out}: --allow-suggested trains on keyword "
            f"guesses, not verified labels. Use a path ending in "
            f"'{WEAK_SUFFIX}.joblib' to mark it as a diagnostic model.",
            file=sys.stderr,
        )
        return 1

    require_verified = not args.allow_suggested
    training = load(args.train, require_verified)
    validation = load(args.validation, require_verified)
    testing = load(args.test, require_verified)

    splits = {"train": training}
    if validation:
        splits["validation"] = validation
    if testing:
        splits["test"] = testing

    try:
        check_splits(splits)
    except LeakageError as exc:
        print(f"Refusing to train: {exc}", file=sys.stderr)
        return 1

    print("Label distribution (train):")
    for label, count in label_distribution(training).most_common():
        print(f"  {label:<20}{count:>6}")

    model = train(training)

    if validation:
        report("Validation", evaluate(model, validation))
    if testing:
        report("Test", evaluate(model, testing))

    save_model(model, args.out)
    print(f"\nSaved model to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
