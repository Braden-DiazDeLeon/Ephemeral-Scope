#!/usr/bin/env python3
"""Build a release-note training corpus from GitHub Releases.

    get_all_notes -> normalize and deduplicate -> suggest labels -> JSONL

Run manually. The web application never invokes this.

    python scripts/build_training_dataset.py --split train --out data/train.jsonl
    python scripts/build_training_dataset.py --inventory
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ephemeral_scope.domain.enums import ReleaseNoteCategory
from ephemeral_scope.evidence.release_notes_client import ReleaseNotesClient
from ephemeral_scope.ml.dataset import LabeledNote, normalize, write_jsonl
from ephemeral_scope.ml.release_note_classifier import KeywordReleaseNoteClassifier
from ephemeral_scope.ml.trainer import (
    HELD_OUT_PACKAGES,
    check_splits,
    deduplicate_across,
)

# Chosen from a real inventory of GitHub Release coverage; projects that
# publish changelogs only in-repo like django, sqlalchemy, cryptography yield
# nothing here and are deliberately absent. No package appears twice.
#
# The assignment is driven by the scarce categories rather than by volume.
# urllib3 and werkzeug carry most of the security statements, attrs and rich
# most of the behavioural ones, so they go to test; pytest supplies validation
# its breaking changes and pyjwt its behavioural ones. Run --coverage after
# any change here: a split that reads sensibly can still leave a category with
# too few examples to measure.
SPLITS: dict[str, tuple[str, ...]] = {
    "train": (
        "numpy",
        "fastapi",
        "pydantic",
        "black",
        "pandas",
        "click",
        "oauthlib",
        "starlette",
        "uvicorn",
        "sentry-sdk",
    ),
    "validation": ("pytest", "pyjwt", "flask", "jinja2"),
    "test": ("urllib3", "werkzeug", "attrs", "rich"),
}

# Evaluation splits claim a duplicated statement before train does: the same
# sentence is worth more as a test example than as one more training row.
DEDUP_PRIORITY = ("test", "validation", "train")

# The floors the splits are checked against, per the measurement we want to be
# able to make. Train is not checked; it takes whatever is left.
MINIMUM_PER_CATEGORY = {"validation": 20, "test": 30}

INVENTORY_PACKAGES = sorted(
    {package for packages in SPLITS.values() for package in packages}
    | set(HELD_OUT_PACKAGES)
    | {"django", "sqlalchemy", "cryptography"}
)


def collect(
    client: ReleaseNotesClient,
    packages: tuple[str, ...],
    max_per_package: int | None,
) -> list[LabeledNote]:
    keywords = KeywordReleaseNoteClassifier()
    notes: list[LabeledNote] = []

    for package in packages:
        if package in HELD_OUT_PACKAGES:
            print(f"  {package}: skipped (held out)")
            continue

        items = normalize(client.get_all_notes(package))
        if max_per_package is not None:
            items = items[:max_per_package]

        notes.extend(
            LabeledNote(
                text=item.text,
                package_name=item.package_name or package,
                release_version=item.release_version,
                source_url=item.source_url,
                section=item.section,
                suggested_label=keywords.label(item.text, item.section),
            )
            for item in items
        )
        print(f"  {package}: {len(items)} statements")
    return notes


def inventory(client: ReleaseNotesClient) -> None:
    print(f"{'Package':<14}{'Releases':>9}{'Statements':>12}{'Sections':>10}  Verdict")
    print("-" * 60)
    for package in INVENTORY_PACKAGES:
        releases = client._get_releases(package)
        items = normalize(client.get_all_notes(package))
        with_section = sum(1 for item in items if item.section)
        percent = round(100 * with_section / len(items)) if items else 0
        verdict = "no" if len(items) < 40 else ("yes" if percent >= 50 else "partial")
        print(
            f"{package:<14}{len(releases):>9}{len(items):>12}{percent:>9}%  {verdict}"
        )


def coverage_report(splits: dict[str, list[LabeledNote]]) -> bool:
    """Print per-category counts and report whether the floors are met."""
    categories = [category.value for category in ReleaseNoteCategory]
    header = f"{'split':<12}{'total':>7}" + "".join(
        f"{name[:8]:>9}" for name in categories
    )
    print(header)
    print("-" * len(header))

    short: list[str] = []
    for name in ("train", "validation", "test"):
        notes = splits.get(name, [])
        counts = Counter(note.label.value for note in notes if note.label)
        print(
            f"{name:<12}{len(notes):>7}"
            + "".join(f"{counts[c]:>9}" for c in categories)
        )
        floor = MINIMUM_PER_CATEGORY.get(name)
        if floor is None:
            continue
        short += [
            f"{name}.{c} has {counts[c]} (want {floor})"
            for c in categories
            if counts[c] < floor
        ]

    if short:
        print("\nBelow the measurement floor:")
        for line in short:
            print(f"  {line}")
    return not short


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=sorted(SPLITS), help="which split to build")
    parser.add_argument(
        "--all",
        dest="build_all",
        action="store_true",
        help="build every split into --out-dir, deduplicating across them",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("data/generated"),
        help="destination directory for --all",
    )
    parser.add_argument("--coverage", action="store_true", help="report coverage only")
    parser.add_argument("--out", type=Path, help="destination .jsonl file")
    parser.add_argument(
        "--packages", nargs="+", help="override the packages for this split"
    )
    parser.add_argument(
        "--max-per-package",
        type=int,
        default=None,
        help=(
            "cap per package. Off by default: the cap keeps the newest N "
            "statements, and since scarce categories are spread over a "
            "project's whole history, capping numpy and fastapi at 1500 threw "
            "away two thirds of the security examples. Large projects "
            "dominating the vocabulary is the lesser problem."
        ),
    )
    parser.add_argument(
        "--inventory", action="store_true", help="report coverage and exit"
    )
    args = parser.parse_args()

    client = ReleaseNotesClient()

    if args.inventory:
        inventory(client)
        return 0

    if args.build_all or args.coverage:
        splits: dict[str, list[LabeledNote]] = {}
        for name, packages in SPLITS.items():
            print(f"Building '{name}' from {len(packages)} packages:")
            splits[name] = collect(client, packages, args.max_per_package)

        before = {name: len(notes) for name, notes in splits.items()}
        splits = deduplicate_across(splits, priority=DEDUP_PRIORITY)
        dropped = sum(before[name] - len(notes) for name, notes in splits.items())
        print(f"\nDropped {dropped} statements duplicated across splits.")

        # Proves the files we are about to write are clean rather than
        # trusting that deduplicate_across did its job.
        check_splits(splits)

        print()
        met = coverage_report(splits)

        if args.coverage:
            return 0 if met else 1

        args.out_dir.mkdir(parents=True, exist_ok=True)
        print()
        for name, notes in splits.items():
            destination = args.out_dir / f"{name}.jsonl"
            print(f"Wrote {write_jsonl(destination, notes)} notes to {destination}")
        print("\nReview and fill in `verified_label` before training.")
        return 0

    if not args.split or not args.out:
        parser.error("--split and --out are required unless --inventory is given")

    packages = tuple(args.packages) if args.packages else SPLITS[args.split]
    print(f"Building '{args.split}' from {len(packages)} packages:")
    notes = collect(client, packages, args.max_per_package)

    if not notes:
        print("No statements collected; nothing written.", file=sys.stderr)
        return 1

    written = write_jsonl(args.out, notes)
    suggested = Counter(
        note.suggested_label.value for note in notes if note.suggested_label
    )
    unlabelled = sum(1 for note in notes if note.suggested_label is None)

    print(f"\nWrote {written} notes to {args.out}")
    print("Suggested labels:")
    for label, count in suggested.most_common():
        print(f"  {label:<20}{count:>6}")
    if unlabelled:
        print(f"  {'(no suggestion)':<20}{unlabelled:>6}")
    print("\nReview and fill in `verified_label` before training.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
