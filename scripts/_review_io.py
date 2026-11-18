#!/usr/bin/env python3
"""Helpers for the manual review pass: dump statements, apply labels back.

Underscore-prefixed because this is reviewer tooling, not part of the
pipeline. The web application never invokes it.

    python scripts/_review_io.py dump data/verified/test.jsonl
    python scripts/_review_io.py apply data/verified/test.jsonl labels.txt
"""

from __future__ import annotations

import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ephemeral_scope.domain.enums import ReleaseNoteCategory
from ephemeral_scope.ml.dataset import read_jsonl, write_jsonl

SHORT = {
    "s": ReleaseNoteCategory.SECURITY_FIX,
    "k": ReleaseNoteCategory.BREAKING_CHANGE,
    "h": ReleaseNoteCategory.BEHAVIORAL_CHANGE,
    "d": ReleaseNoteCategory.DEPRECATION,
    "b": ReleaseNoteCategory.BUG_FIX,
    "f": ReleaseNoteCategory.FEATURE,
    "i": ReleaseNoteCategory.IRRELEVANT,
}


def dump(path: Path, width: int = 190) -> None:
    for index, note in enumerate(read_jsonl(path)):
        section = (note.section or "-")[:16]
        suggestion = note.suggested_label.value if note.suggested_label else "NONE"
        text = " ".join(note.text.split())[:width]
        print(f"{index:>3} [{section:<16}] [{suggestion[:6]:<6}] {text}")


def apply(path: Path, labels_path: Path) -> None:
    """Apply a whitespace-separated list of short codes, one per statement."""
    notes = read_jsonl(path)
    codes = labels_path.read_text(encoding="utf-8").split()
    if len(codes) != len(notes):
        raise SystemExit(
            f"{labels_path}: {len(codes)} labels for {len(notes)} statements"
        )

    updated = [
        replace(note, verified_label=SHORT[code]) for note, code in zip(notes, codes)
    ]
    write_jsonl(path, updated)

    counts = Counter(note.verified_label.value for note in updated)
    changed = sum(
        1 for note in updated if note.suggested_label != note.verified_label
    )
    print(f"{path}: verified {len(updated)} statements, {changed} differ from the rule")
    for label, count in counts.most_common():
        print(f"  {label:<20}{count:>5}")


def main() -> int:
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    command = sys.argv[1]
    if command == "dump":
        dump(Path(sys.argv[2]))
    elif command == "apply":
        apply(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        raise SystemExit(__doc__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
