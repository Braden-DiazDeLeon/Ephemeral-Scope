#!/usr/bin/env python3
"""Record what the dataset was built from, so it can be rebuilt later.

`data/generated/` is ignored by git: it is 7 MB of text we do not own and can
regenerate from GitHub. The manifest is what makes that defensible - it pins
the packages, the release range each split covers, the counts, and a hash of
every committed file, so a later rebuild can be checked against the run the
results were reported from.

Run manually after rebuilding the dataset. The web application never invokes
this.

    python scripts/write_dataset_manifest.py --out data/manifest.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections import Counter
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ephemeral_scope.evidence.release_notes_client import ReleaseNotesClient
from ephemeral_scope.ml.dataset import read_jsonl

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_training_dataset import SPLITS  # noqa: E402

GENERATED_DIR = Path("data/generated")
VERIFIED_DIR = Path("data/verified")
CASE_STUDY_DIR = Path("data/case_studies")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def file_record(path: Path) -> dict | None:
    if not path.exists():
        return None
    notes = list(read_jsonl(path))
    verified = sum(1 for note in notes if note.verified_label is not None)
    return {
        "path": str(path),
        "sha256": sha256(path),
        "bytes": path.stat().st_size,
        "statements": len(notes),
        "verified": verified,
        "labels": dict(
            Counter(note.label.value for note in notes if note.label).most_common()
        ),
    }


def package_record(client: ReleaseNotesClient, package: str) -> dict:
    """Pin the release range a package contributed, not just its name.

    A project that cuts ten releases after collection would otherwise produce
    a silently different dataset under the same manifest.
    """
    releases = client._get_releases(package)
    tags = [release.get("tag_name", "") for release in releases if release.get("tag_name")]
    repository = client.find_repository(package)
    return {
        "package": package,
        "repository": f"https://github.com/{repository}" if repository else None,
        "source_url": f"https://api.github.com/repos/{repository}/releases"
        if repository
        else None,
        "releases": len(releases),
        "oldest_release": tags[-1] if tags else None,
        "newest_release": tags[0] if tags else None,
    }


def git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("data/manifest.json"))
    args = parser.parse_args()

    client = ReleaseNotesClient()

    splits = {}
    for name, packages in SPLITS.items():
        splits[name] = {
            "packages": [package_record(client, package) for package in packages],
            "generated": file_record(GENERATED_DIR / f"{name}.jsonl"),
            "verified": file_record(VERIFIED_DIR / f"{name}.jsonl"),
        }

    manifest = {
        "collected_on": date.today().isoformat(),
        "code_commit": git_commit(),
        "source": "GitHub Releases API",
        "note": (
            "data/generated/ and models/ are not committed. Rebuild with "
            "scripts/build_training_dataset.py --all, then compare the hashes "
            "below. Release notes are the upstream projects' own text and are "
            "redistributed here only as the verified subsets."
        ),
        "splits": splits,
        "case_studies": [
            record
            for record in (
                file_record(path) for path in sorted(CASE_STUDY_DIR.glob("*.jsonl"))
            )
            if record
        ],
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    for name, split in splits.items():
        generated = split["generated"]
        verified = split["verified"]
        print(
            f"  {name:<12}{len(split['packages'])} packages, "
            f"{generated['statements'] if generated else 0} generated, "
            f"{verified['statements'] if verified else 0} for review"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
