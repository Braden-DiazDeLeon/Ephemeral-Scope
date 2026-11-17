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

from ephemeral_scope.evidence.release_notes_client import ReleaseNotesClient
from ephemeral_scope.ml.dataset import LabeledNote, normalize, write_jsonl
from ephemeral_scope.ml.release_note_classifier import KeywordReleaseNoteClassifier
from ephemeral_scope.ml.trainer import HELD_OUT_PACKAGES

# Chosen from a real inventory of GitHub Release coverage; projects that
# publish changelogs only in-repo like django, sqlalchemy, cryptography yield
# nothing here and are deliberately absent. No package appears twice.
SPLITS: dict[str, tuple[str, ...]] = {
    "train": ("numpy", "fastapi", "pydantic", "pytest", "rich", "black", "urllib3", "pandas"),
    "validation": ("httpx", "click", "attrs"),
    "test": ("flask", "werkzeug", "jinja2"),
}

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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=sorted(SPLITS), help="which split to build")
    parser.add_argument("--out", type=Path, help="destination .jsonl file")
    parser.add_argument(
        "--packages", nargs="+", help="override the packages for this split"
    )
    parser.add_argument(
        "--max-per-package",
        type=int,
        default=1500,
        help="cap per package so one large project cannot dominate",
    )
    parser.add_argument(
        "--inventory", action="store_true", help="report coverage and exit"
    )
    args = parser.parse_args()

    client = ReleaseNotesClient()

    if args.inventory:
        inventory(client)
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
