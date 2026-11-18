"""Training-only records for the release-note classifier.

These types exist for dataset construction and evaluation. The runtime
pipeline consumes :class:`ReleaseNoteItem` instead; nothing here is imported
by the web application.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path

from ephemeral_scope.domain.enums import ReleaseNoteCategory
from ephemeral_scope.domain.models import ReleaseNoteItem

#: Headings whose contents are repository chatter rather than release claims.
#: "New Contributors" alone accounts for roughly half of some changelogs.
NOISE_SECTIONS = frozenset({"new contributors", "contributors", "acknowledgements"})

_FIRST_CONTRIBUTION = re.compile(r"@[\w-]+ made their first contribution", re.I)
_VERSION_ONLY = re.compile(r"^v?\d+(\.\d+)*[a-z0-9.\-]*$", re.I)
_URL = re.compile(r"https?://\S+")
#: "Released on 2026-11-15.", "2024-05-20", "Release date: ..."
_RELEASE_DATE = re.compile(
    r"^(?:released?(?:\s+on)?|release date|published)?\s*:?\s*"
    r"\d{4}-\d{2}-\d{2}\.?$",
    re.I,
)
#: "Compare: v1.2.0...v1.3.0", "Full diff", bare tag references.
_BARE_REFERENCE = re.compile(
    r"^(?:compare|diff|full diff|changelog|release notes|docs?|documentation|"
    r"pypi|milestone|commits?)\s*:?\s*$",
    re.I,
)
#: Promotional and social chatter: sponsor pledges, follow-us lines, thanks.
_PROMOTIONAL = re.compile(
    r"\b(follow (?:us|me) on|star (?:us|the repo)|sponsor\w*|donate|patreon|"
    r"twitter\.com|x\.com/|mastodon|discord\.gg|join our|subscribe|"
    r"thanks? (?:to )?(?:all|everyone|our)|shout-?out)\b",
    re.I,
)
_LABELLED_LINK = re.compile(r"^[\w .#/-]{0,40}:\s*https?://\S+$", re.I)


@dataclass(frozen=True, slots=True)
class LabeledNote:
    """One training or evaluation example.

    ``suggested_label`` is what the keyword heuristic guessed;
    ``verified_label`` is what a human confirmed. Training reads the verified
    column so that unreviewed guesses never silently become ground truth.
    """

    text: str
    package_name: str
    release_version: str
    source_url: str | None
    section: str | None
    suggested_label: ReleaseNoteCategory | None
    verified_label: ReleaseNoteCategory | None = None

    @property
    def label(self) -> ReleaseNoteCategory | None:
        """The label to train on, preferring human verification."""
        return self.verified_label or self.suggested_label

    def to_json(self) -> dict:
        return {
            "text": self.text,
            "package_name": self.package_name,
            "release_version": self.release_version,
            "source_url": self.source_url,
            "section": self.section,
            "suggested_label": _label_value(self.suggested_label),
            "verified_label": _label_value(self.verified_label),
        }

    @classmethod
    def from_json(cls, document: dict) -> LabeledNote:
        return cls(
            text=document["text"],
            package_name=document["package_name"],
            release_version=document.get("release_version", ""),
            source_url=document.get("source_url"),
            section=document.get("section"),
            suggested_label=_to_label(document.get("suggested_label")),
            verified_label=_to_label(document.get("verified_label")),
        )


def is_noise(item: ReleaseNoteItem) -> bool:
    """True for pure metadata that says nothing about an upgrade.

    The bar is deliberately narrow. A real maintenance or documentation
    claim is kept and labelled IRRELEVANT, because the classifier needs
    negative examples; only statements with no upgrade meaning at all,
    release dates, link dumps, contributor chatter, are discarded.
    """
    if item.section and item.section.strip().lower() in NOISE_SECTIONS:
        return True

    text = " ".join(item.text.split())
    if len(text) < 12:
        return True
    if _VERSION_ONLY.match(text) or _RELEASE_DATE.match(text):
        return True
    if _BARE_REFERENCE.match(text) or _LABELLED_LINK.match(text):
        return True
    if _FIRST_CONTRIBUTION.search(text) or _PROMOTIONAL.search(text):
        return True

    # Link collections: once URLs are stripped there is no claim left.
    without_links = _URL.sub("", text)
    if len(_strip_decoration(without_links)) < 12:
        return True

    # A statement needs a verb-bearing clause; a bare noun phrase such as
    # "PyPI" or "Milestone 3" is a reference, not a claim.
    return len(text.split()) < 3


def _strip_decoration(text: str) -> str:
    """Remove punctuation and emphasis so link-only lines collapse to empty."""
    return re.sub(r"[^\w\s]", "", text).strip()


def normalized_text(text: str) -> str:
    """Canonical form used for duplicate detection across packages and splits."""
    return " ".join(text.casefold().split())


def normalize(items: Iterable[ReleaseNoteItem]) -> list[ReleaseNoteItem]:
    """Drop noise and collapse statements repeated across releases.

    Projects restate the same line in a patch release and its successor, so
    without this the corpus over-weights whatever text got copied forward.
    """
    seen: set[tuple[str | None, str]] = set()
    kept: list[ReleaseNoteItem] = []
    for item in items:
        if is_noise(item):
            continue
        cleaned = " ".join(item.text.split())
        key = (item.package_name, normalized_text(cleaned))
        if key in seen:
            continue
        seen.add(key)
        kept.append(replace(item, text=cleaned))
    return kept


def write_jsonl(path: Path, notes: Iterable[LabeledNote]) -> int:
    """Write notes as JSON Lines, returning how many were written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for note in notes:
            handle.write(json.dumps(note.to_json(), ensure_ascii=False) + "\n")
            count += 1
    return count


def read_jsonl(path: Path) -> list[LabeledNote]:
    """Read notes from JSON Lines, ignoring blank lines."""
    return list(_iter_jsonl(path))


def _iter_jsonl(path: Path) -> Iterator[LabeledNote]:
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield LabeledNote.from_json(json.loads(line))
            except (json.JSONDecodeError, KeyError) as exc:
                raise ValueError(f"{path}:{number}: malformed record ({exc})") from exc


def _label_value(label: ReleaseNoteCategory | None) -> str | None:
    return label.value if label is not None else None


def _to_label(value: str | None) -> ReleaseNoteCategory | None:
    if not value:
        return None
    return ReleaseNoteCategory(value)
