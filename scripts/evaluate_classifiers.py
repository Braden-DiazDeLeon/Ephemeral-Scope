#!/usr/bin/env python3
"""Score every release-note classification method against the verified splits.

One command reproduces every number quoted in the report:

    python scripts/evaluate_classifiers.py

Unclassified statements are scored as a distinct `(unclassified)` label
rather than folded into IRRELEVANT, so a method is not rewarded for
declining to answer.

Run manually. The web application never invokes this.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ephemeral_scope.domain.enums import ReleaseNoteCategory
from ephemeral_scope.ml.dataset import LabeledNote, read_jsonl
from ephemeral_scope.ml.release_note_classifier import (
    SECTION_LABELS,
    KeywordReleaseNoteClassifier,
    RuleOutcome,
    decide,
)
from ephemeral_scope.ml.trainer import train

#: Stands in for "no method could categorise this". Kept out of
#: ReleaseNoteCategory because it is a scoring artefact, not a domain value.
UNCLASSIFIED = "(unclassified)"

#: Report-facing names. Used verbatim in the write-up so the prose and the
#: generated tables cannot drift apart.
METHOD_NAMES = {
    "majority": "Majority baseline",
    "keyword_rule": "Keyword-rule baseline",
    "section_and_keyword": "Section-and-keyword baseline",
    "tfidf": "TF-IDF classifier",
    "hybrid": "Hybrid Ephemeral Scope pipeline",
}


@dataclass(frozen=True, slots=True)
class Scored:
    method: str
    split: str
    truth: list[str]
    predicted: list[str]


def labels_of(notes: list[LabeledNote]) -> list[str]:
    return [str(note.verified_label) for note in notes]


def predict_majority(notes: list[LabeledNote], majority: str) -> list[str]:
    return [majority] * len(notes)


def predict_keyword(notes: list[LabeledNote]) -> list[str]:
    """Text only: the heading is withheld so this isolates the regexes."""
    keywords = KeywordReleaseNoteClassifier()
    return [
        str(keywords.label(note.text, section=None) or UNCLASSIFIED) for note in notes
    ]


def predict_section_and_keyword(notes: list[LabeledNote]) -> list[str]:
    keywords = KeywordReleaseNoteClassifier()
    return [
        str(keywords.label(note.text, note.section) or UNCLASSIFIED) for note in notes
    ]


def predict_tfidf(model, notes: list[LabeledNote]) -> list[str]:
    return [str(value) for value in model.predict([note.text for note in notes])]


def predict_hybrid(model, notes: list[LabeledNote]) -> list[str]:
    keywords = KeywordReleaseNoteClassifier()
    texts = [note.text for note in notes]
    predictions = [ReleaseNoteCategory(value) for value in model.predict(texts)]
    confidences = _confidences(model, texts)

    selected = []
    for note, prediction, confidence in zip(notes, predictions, confidences):
        rule = keywords.label_with_source(note.text, note.section)
        decision = decide(rule, prediction, confidence)
        selected.append(
            str(decision.selected_category)
            if decision.selected_category is not None
            else UNCLASSIFIED
        )
    return selected


def _confidences(model, texts: list[str]) -> list[float]:
    predict_proba = getattr(model, "predict_proba", None)
    if predict_proba is None:
        return [0.5] * len(texts)
    return [float(max(row)) for row in predict_proba(texts)]


def agreement_rate(left: list[str], right: list[str]) -> float:
    if not left:
        return 0.0
    return sum(a == b for a, b in zip(left, right)) / len(left)


def metrics_for(scored: Scored) -> dict:
    from sklearn.metrics import (
        accuracy_score,
        f1_score,
        precision_recall_fscore_support,
    )

    categories = sorted({*scored.truth, *scored.predicted})
    precision, recall, f1, support = precision_recall_fscore_support(
        scored.truth, scored.predicted, labels=categories, zero_division=0
    )

    return {
        "method": scored.method,
        "method_name": METHOD_NAMES[scored.method],
        "split": scored.split,
        "examples": len(scored.truth),
        "accuracy": round(float(accuracy_score(scored.truth, scored.predicted)), 4),
        "macro_f1": round(
            float(
                f1_score(
                    scored.truth,
                    scored.predicted,
                    average="macro",
                    zero_division=0,
                )
            ),
            4,
        ),
        "per_class": {
            category: {
                "precision": round(float(precision[index]), 4),
                "recall": round(float(recall[index]), 4),
                "f1": round(float(f1[index]), 4),
                "support": int(support[index]),
            }
            for index, category in enumerate(categories)
        },
    }


def confusion_rows(scored: Scored) -> list[dict]:
    """Confusion counts for the hybrid pipeline, long-form for easy pivoting."""
    categories = sorted({*scored.truth, *scored.predicted})
    counts = Counter(zip(scored.truth, scored.predicted))
    return [
        {
            "true_label": truth,
            "predicted_label": predicted,
            "count": counts.get((truth, predicted), 0),
        }
        for truth in categories
        for predicted in categories
    ]


def write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verified-dir", type=Path, default=Path("data/verified"))
    parser.add_argument("--out-dir", type=Path, default=Path("results"))
    args = parser.parse_args()

    splits = {
        name: [
            note
            for note in read_jsonl(args.verified_dir / f"{name}.jsonl")
            if note.verified_label is not None
        ]
        for name in ("train", "validation", "test")
    }
    for name, notes in splits.items():
        if not notes:
            print(f"{name}: no verified labels found.", file=sys.stderr)
            return 1

    # Fit once on the verified training split; every method is scored against
    # the same untouched validation and test sets.
    model = train(splits["train"])
    majority = Counter(labels_of(splits["train"])).most_common(1)[0][0]
    print(f"Trained on {len(splits['train'])} verified statements.")
    print(f"Majority class in train: {majority}\n")

    all_metrics: list[dict] = []
    flat_rows: list[dict] = []
    agreements: dict[str, float] = {}

    for split in ("validation", "test"):
        notes = splits[split]
        truth = labels_of(notes)

        predictions = {
            "majority": predict_majority(notes, majority),
            "keyword_rule": predict_keyword(notes),
            "section_and_keyword": predict_section_and_keyword(notes),
            "tfidf": predict_tfidf(model, notes),
            "hybrid": predict_hybrid(model, notes),
        }

        agreements[split] = round(
            agreement_rate(predictions["section_and_keyword"], predictions["tfidf"]), 4
        )

        for method, predicted in predictions.items():
            scored = Scored(method, split, truth, predicted)
            entry = metrics_for(scored)
            entry["rule_model_agreement"] = agreements[split]
            all_metrics.append(entry)

            for category, values in entry["per_class"].items():
                flat_rows.append(
                    {
                        "method": method,
                        "method_name": METHOD_NAMES[method],
                        "split": split,
                        "category": category,
                        "precision": values["precision"],
                        "recall": values["recall"],
                        "f1": values["f1"],
                        "support": values["support"],
                        "accuracy": entry["accuracy"],
                        "macro_f1": entry["macro_f1"],
                        "examples": entry["examples"],
                    }
                )

        write_csv(
            args.out_dir / f"{split}_confusion_matrix.csv",
            confusion_rows(Scored("hybrid", split, truth, predictions["hybrid"])),
            ["true_label", "predicted_label", "count"],
        )

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "classifier_metrics.json").write_text(
        json.dumps(
            {
                "generated_on": date.today().isoformat(),
                "training_examples": len(splits["train"]),
                "majority_class": majority,
                "rule_model_agreement": agreements,
                "method_names": METHOD_NAMES,
                "unclassified_label": UNCLASSIFIED,
                "results": all_metrics,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    write_csv(
        args.out_dir / "classifier_metrics.csv",
        flat_rows,
        [
            "method",
            "method_name",
            "split",
            "category",
            "precision",
            "recall",
            "f1",
            "support",
            "accuracy",
            "macro_f1",
            "examples",
        ],
    )

    header = f"{'method':<34}{'split':<12}{'n':>6}{'accuracy':>11}{'macro F1':>11}"
    print(header)
    print("-" * len(header))
    for entry in all_metrics:
        print(
            f"{entry['method_name']:<34}{entry['split']:<12}{entry['examples']:>6}"
            f"{entry['accuracy']:>11.3f}{entry['macro_f1']:>11.3f}"
        )

    print("\nRule/TF-IDF agreement:")
    for split, rate in agreements.items():
        print(f"  {split:<12}{rate:.3f}")
    print(f"\nWrote 4 files to {args.out_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
