"""Release notes retrieval."""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

from ephemeral_scope.domain.models import DependencyUpgrade, ReleaseNoteItem
from ephemeral_scope.http_cache import HttpCache

PYPI_JSON_URL = "https://pypi.org/pypi"
GITHUB_API_URL = "https://api.github.com"
GITHUB_PAGE_SIZE = 100

_GITHUB_REPO = re.compile(r"github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", re.I)
# github.com paths that look like `owner/name` but are site features, not
# repositories. Funding links such as github.com/sponsors/<user> are the
# common in PyPI project_urls.
_RESERVED_OWNERS = frozenset(
    {
        "sponsors",
        "orgs",
        "users",
        "apps",
        "features",
        "marketplace",
        "topics",
        "collections",
        "explore",
        "settings",
        "about",
        "pricing",
        "security",
        "readme",
    }
)
_CODE_FENCE = re.compile(r"```.*?```", re.S)
_HTML_TAG = re.compile(r"<[^>]+>")
_MARKDOWN_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_BULLET = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")
# An RST/setext heading underline, or a horizontal rule.
_UNDERLINE = re.compile(r"^[-=~^\"'`#*+<>_.]{3,}$")
# A line that is nothing but bold text, e.g. `**Security**` - a section
# label rather than a claim.
_BOLD_HEADING = re.compile(r"^(?:\*\*|__)[^*_]+(?:\*\*|__):?$")
_TRAILING_ATTRIBUTION = re.compile(r"\s+by\s+@[\w-]+\s+in\s+\S+$", re.I)
# A heading that is really the release title like "2.32.0 (2024-05-20)".
# It names the release not a category, so it is not a section.
_RELEASE_TITLE = re.compile(r"^v?\d+\.\d+")


@dataclass(frozen=True, slots=True)
class ParsedStatement:
    """One claim from a release body, with the heading it appeared under."""

    text: str
    section: str | None = None


class ReleaseNotesClient:
    """Retrieves and splits release notes into individual statements."""

    def __init__(
        self,
        http: HttpCache | None = None,
        github_token: str | None = None,
    ) -> None:
        self.http = http or HttpCache()
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")

    def get_notes(self, upgrade: DependencyUpgrade) -> list[ReleaseNoteItem]:
        """Return one item per statement published between the two versions.

        Returns an empty list when the project's repository cannot be found or
        its releases are unavailable; evidence gathering is best-effort.
        """
        lower, upper = _parse(upgrade.current_version), _parse(upgrade.target_version)
        return self._to_items(
            upgrade.package_name,
            self._get_releases(upgrade.package_name),
            keep=lambda version: _in_range(version, lower, upper),
        )

    def get_all_notes(self, package_name: str) -> list[ReleaseNoteItem]:
        """Return every statement the project has ever published.

        Intended for building a training corpus, where restricting to an
        upgrade window would throw away most of the available text.
        """
        return self._to_items(
            package_name,
            self._get_releases(package_name),
            keep=lambda version: version is not None,
        )

    def _get_releases(self, package_name: str) -> list[dict]:
        """Fetch every release page for a package's GitHub repository.

        GitHub caps a page at 100 entries, so a project with a long history
        would be silently truncated without following the pages. Each page is
        a distinct URL and therefore cached separately.
        """
        repository = self.find_repository(package_name)
        if repository is None:
            return []

        releases: list[dict] = []
        page = 1
        while True:
            batch = self.http.get_json(
                f"{GITHUB_API_URL}/repos/{repository}/releases"
                f"?per_page={GITHUB_PAGE_SIZE}&page={page}",
                headers=self._github_headers(),
            )
            if not isinstance(batch, list) or not batch:
                break
            releases.extend(entry for entry in batch if isinstance(entry, dict))
            if len(batch) < GITHUB_PAGE_SIZE:
                break
            page += 1
        return releases

    def _to_items(
        self,
        package_name: str,
        releases: list[dict],
        keep: Callable[[Version | None], bool],
    ) -> list[ReleaseNoteItem]:
        items: list[ReleaseNoteItem] = []
        for release in releases:
            if release.get("draft"):
                continue
            label = release.get("tag_name") or release.get("name") or ""
            if not keep(_parse(label)):
                continue

            url = release.get("html_url")
            for statement in split_statement_records(release.get("body") or ""):
                items.append(
                    ReleaseNoteItem(
                        text=statement.text,
                        release_version=_normalize(label),
                        source_url=url,
                        package_name=package_name,
                        section=statement.section,
                    )
                )
        return items

    def find_repository(self, package_name: str) -> str | None:
        """Resolve a package to its `owner/name` GitHub repository."""
        metadata = self.http.get_json(f"{PYPI_JSON_URL}/{package_name}/json")
        if not isinstance(metadata, dict):
            return None

        info = metadata.get("info") or {}
        candidates = list((info.get("project_urls") or {}).values())
        candidates.append(info.get("home_page"))

        for url in candidates:
            if not isinstance(url, str):
                continue
            match = _GITHUB_REPO.search(url.strip())
            if match and match.group(1).lower() not in _RESERVED_OWNERS:
                return f"{match.group(1)}/{match.group(2)}"
        return None

    def _github_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers


def split_statement_records(body: str) -> list[ParsedStatement]:
    """Break a release body into claims, each tagged with its heading.

    Downstream classification scores one claim at a time, so a bullet list has
    to become one statement per bullet rather than a single blob of markdown.

    Changelogs hard-wrap prose, so lines are first regrouped into blocks: a
    bullet absorbs its continuation lines instead of being torn into
    fragments mid-sentence. The heading above a block
    is kept, because it is a strong label signal for training.
    """
    statements: list[ParsedStatement] = []
    seen: set[str] = set()

    for is_bullet, lines, section in _blocks(
        _CODE_FENCE.sub(" ", body.replace("\r\n", "\n"))
    ):
        text = _clean(" ".join(lines))
        if not text or text.lower().startswith("full changelog"):
            continue
        # A bullet is already one claim; a paragraph may pack several together.
        pieces = [text] if is_bullet else _SENTENCE_SPLIT.split(text)
        for piece in pieces:
            piece = piece.strip()
            if len(piece) > 2 and piece not in seen:
                seen.add(piece)
                statements.append(ParsedStatement(text=piece, section=section))

    return statements


def split_statements(body: str) -> list[str]:
    """Break a release body into statements, discarding heading metadata."""
    return [statement.text for statement in split_statement_records(body)]


def _blocks(body: str) -> list[tuple[bool, list[str], str | None]]:
    """Group wrapped lines into (is_bullet, lines, section) blocks.

    Headings are consumed rather than emitted: each one becomes the section
    applied to the blocks that follow it.
    """
    blocks: list[tuple[bool, list[str], str | None]] = []
    current: tuple[bool, list[str]] | None = None
    section: str | None = None

    def flush() -> None:
        nonlocal current
        if current is not None:
            blocks.append((current[0], current[1], section))
            current = None

    def set_section(text: str) -> None:
        nonlocal section
        cleaned = _clean(text).rstrip(":")
        # A release title names the release, not a category of change.
        section = None if _RELEASE_TITLE.match(cleaned) else (cleaned or None)

    for raw in body.split("\n"):
        line = raw.strip()

        if not line:
            flush()
        elif _UNDERLINE.match(line):
            # The line above was a heading, not prose: it names this section.
            if current is not None and not current[0]:
                set_section(" ".join(current[1]))
            current = None
        elif line.startswith("#"):
            flush()
            set_section(line.lstrip("#"))
        elif _BOLD_HEADING.match(line):
            flush()
            set_section(line)
        elif _BULLET.match(line):
            flush()
            current = (True, [_BULLET.sub("", line)])
        elif current is None:
            current = (False, [line])
        else:
            current[1].append(line)

    flush()
    return blocks


def _clean(text: str) -> str:
    text = _MARKDOWN_LINK.sub(r"\1", text)
    text = _HTML_TAG.sub("", text)
    text = text.replace("**", "").replace("__", "")
    text = _TRAILING_ATTRIBUTION.sub("", text)
    return " ".join(text.split())


def _normalize(label: str) -> str:
    label = label.strip()
    return label[1:] if label[:1].lower() == "v" else label


def _parse(label: str) -> Version | None:
    try:
        return Version(_normalize(label))
    except InvalidVersion:
        return None


def _in_range(version: Version | None, lower: Version | None, upper: Version | None) -> bool:
    """Keep releases published after the current version, up to the target."""
    if version is None:
        return False
    if lower is not None and version <= lower:
        return False
    if upper is not None and version > upper:
        return False
    return True
