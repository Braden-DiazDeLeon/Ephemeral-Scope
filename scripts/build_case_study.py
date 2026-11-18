#!/usr/bin/env python3
"""Build a case-study corpus for one specific upgrade.

This exists because the first `requests` case study was built with
`get_all_notes`, which returns a project's entire history. The file then
carried 2.27.x and 2.33.x statements that an upgrade from 2.28.0 to 2.32.0
would never surface. Going through `DependencyUpgrade` and `get_notes` makes
the window the same one the analyser itself would use, and the script fails
if anything outside it slips through.

The range is half-open, `(current, target]`: the version you are leaving is
already installed, so its notes are not news, while the version you are
moving to is.

Run manually. The web application never invokes this.

    python scripts/build_case_study.py requests 2.28.0 2.32.0 \
        --out data/case_studies/requests.jsonl
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from packaging.version import InvalidVersion, Version

from ephemeral_scope.domain.models import DependencyUpgrade
from ephemeral_scope.evidence.release_notes_client import ReleaseNotesClient
from ephemeral_scope.ml.dataset import LabeledNote, normalize, write_jsonl
from ephemeral_scope.ml.release_note_classifier import KeywordReleaseNoteClassifier


def check_range(notes: list[LabeledNote], current: str, target: str) -> list[str]:
    """Return any release versions that fall outside ``(current, target]``."""
    lower, upper = Version(current), Version(target)
    outside = []
    for version in sorted({note.release_version for note in notes}):
        try:
            parsed = Version(version)
        except InvalidVersion:
            outside.append(version)
            continue
        if parsed <= lower or parsed > upper:
            outside.append(version)
    return outside


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package")
    parser.add_argument("current_version")
    parser.add_argument("target_version")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    upgrade = DependencyUpgrade(
        package_name=args.package,
        current_version=args.current_version,
        target_version=args.target_version,
    )

    client = ReleaseNotesClient()
    keywords = KeywordReleaseNoteClassifier()
    items = normalize(client.get_notes(upgrade))

    notes = [
        LabeledNote(
            text=item.text,
            package_name=item.package_name or args.package,
            release_version=item.release_version,
            source_url=item.source_url,
            section=item.section,
            suggested_label=keywords.label(item.text, item.section),
        )
        for item in items
    ]

    if not notes:
        print(
            f"No statements found for {args.package} "
            f"{args.current_version} -> {args.target_version}.",
            file=sys.stderr,
        )
        return 1

    outside = check_range(notes, args.current_version, args.target_version)
    if outside:
        print(
            f"Versions outside ({args.current_version}, {args.target_version}]: "
            f"{outside}",
            file=sys.stderr,
        )
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    written = write_jsonl(args.out, notes)

    versions = sorted({note.release_version for note in notes}, key=Version)
    print(
        f"{args.package} {args.current_version} -> {args.target_version}: "
        f"{written} statements from {len(versions)} releases"
    )
    print(f"  versions: {', '.join(versions)}")

    counts = Counter(
        note.suggested_label.value if note.suggested_label else "(no suggestion)"
        for note in notes
    )
    print("  suggested labels:")
    for label, count in counts.most_common():
        print(f"    {label:<20}{count:>5}")
    print(f"\nWrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
