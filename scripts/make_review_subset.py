#!/usr/bin/env python3
"""Draw a label-balanced sample out of a split for manual verification.

Reviewing a split end to end is not realistic: `train.jsonl` alone holds
roughly 18,000 statements, and 20% of them are bug fixes. Sampling evenly
across the suggested labels spends the review budget where the scarce
categories are, so the verified subset can actually measure security and
breaking-change performance.

The sample is drawn from `suggested_label`, which is a guess. That biases
the subset towards statements the keyword rules already recognise, and it is
the reason the review asks for a `verified_label` rather than a yes/no
confirmation: a mislabelled draw should be corrected in place, not dropped.

Run manually. The web application never invokes this.

    python scripts/make_review_subset.py data/generated/test.jsonl \
        --out data/review/test.jsonl --per-label 60
"""

from __future__ import annotations

import argparse
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ephemeral_scope.domain.enums import ReleaseNoteCategory
from ephemeral_scope.ml.dataset import LabeledNote, read_jsonl, write_jsonl

#: Fixed so two people reviewing the same split get the same statements.
DEFAULT_SEED = 20261116


def balanced_sample(
    notes: list[LabeledNote], per_label: int, seed: int
) -> list[LabeledNote]:
    """Take up to ``per_label`` notes of each suggested label.

    Categories with fewer than ``per_label`` candidates contribute everything
    they have, so the result is as balanced as the data allows rather than
    truncated to the rarest category.
    """
    by_label: dict[str, list[LabeledNote]] = defaultdict(list)
    for note in notes:
        if note.suggested_label is not None:
            by_label[note.suggested_label.value].append(note)

    rng = random.Random(seed)
    sample: list[LabeledNote] = []
    for category in ReleaseNoteCategory:
        candidates = by_label.get(category.value, [])
        if len(candidates) <= per_label:
            sample.extend(candidates)
        else:
            sample.extend(rng.sample(candidates, per_label))

    # Shuffle so a reviewer does not see every security statement in one run
    # and start pattern-matching on position instead of reading.
    rng.shuffle(sample)
    return sample


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="split to sample from")
    parser.add_argument("--out", type=Path, required=True, help="destination .jsonl")
    parser.add_argument(
        "--per-label", type=int, default=60, help="target statements per category"
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()

    notes = list(read_jsonl(args.source))
    if not notes:
        print(f"{args.source} is empty.", file=sys.stderr)
        return 1

    sample = balanced_sample(notes, args.per_label, args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.out, sample)

    counts = Counter(note.suggested_label.value for note in sample)
    print(f"Sampled {len(sample)} of {len(notes)} statements into {args.out}")
    for category in ReleaseNoteCategory:
        available = sum(
            1 for n in notes if n.suggested_label and n.suggested_label == category
        )
        flag = "" if counts[category.value] >= args.per_label else "  (all available)"
        print(f"  {category.value:<20}{counts[category.value]:>5} of {available}{flag}")

    print("\nSet `verified_label` on every row, correcting the suggestion where")
    print("it is wrong, then train with the verified file.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
