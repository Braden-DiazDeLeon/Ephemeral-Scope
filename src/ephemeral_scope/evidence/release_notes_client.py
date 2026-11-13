"""Release notes retrieval."""

from __future__ import annotations

import os
import re
from packaging.version import InvalidVersion, Version

from ephemeral_scope.domain.models import DependencyUpgrade, ReleaseNoteItem
from ephemeral_scope.http_cache import HttpCache

PYPI_JSON_URL = "https://pypi.org/pypi"
GITHUB_API_URL = "https://api.github.com"

_GITHUB_REPO = re.compile(r"github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", re.I)
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
        repository = self.find_repository(upgrade.package_name)
        if repository is None:
            return []

        releases = self.http.get_json(
            f"{GITHUB_API_URL}/repos/{repository}/releases?per_page=100",
            headers=self._github_headers(),
        )
        if not isinstance(releases, list):
            return []

        lower, upper = _parse(upgrade.current_version), _parse(upgrade.target_version)

        items: list[ReleaseNoteItem] = []
        for release in releases:
            if not isinstance(release, dict) or release.get("draft"):
                continue
            label = release.get("tag_name") or release.get("name") or ""
            version = _parse(label)
            if not _in_range(version, lower, upper):
                continue

            url = release.get("html_url")
            for statement in split_statements(release.get("body") or ""):
                items.append(
                    ReleaseNoteItem(
                        text=statement,
                        release_version=_normalize(label),
                        source_url=url,
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
            if match:
                return f"{match.group(1)}/{match.group(2)}"
        return None

    def _github_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers


def split_statements(body: str) -> list[str]:
    """Break a release body into individually classifiable statements.

    Downstream classification scores one claim at a time, so a bullet list has
    to become one statement per bullet rather than a single blob of markdown.

    Changelogs hard-wrap prose, so lines are first regrouped into blocks: a
    bullet absorbs its continuation lines instead of being torn into
    fragments mid-sentence.
    """
    blocks = _blocks(_CODE_FENCE.sub(" ", body.replace("\r\n", "\n")))

    statements: list[str] = []
    for is_bullet, lines in blocks:
        text = _clean(" ".join(lines))
        if not text or text.lower().startswith("full changelog"):
            continue
        # A bullet is already one claim; a paragraph may pack several together.
        pieces = [text] if is_bullet else _SENTENCE_SPLIT.split(text)
        statements.extend(piece.strip() for piece in pieces if len(piece.strip()) > 2)

    return list(dict.fromkeys(statements))


def _blocks(body: str) -> list[tuple[bool, list[str]]]:
    """Group wrapped lines into (is_bullet, lines) blocks, dropping headings."""
    blocks: list[tuple[bool, list[str]]] = []
    current: tuple[bool, list[str]] | None = None

    def flush() -> None:
        nonlocal current
        if current is not None:
            blocks.append(current)
            current = None

    for raw in body.split("\n"):
        line = raw.strip()

        if not line:
            flush()
        elif _UNDERLINE.match(line):
            # The line above was a heading, not prose: discard both.
            current = None
        elif line.startswith("#") or _BOLD_HEADING.match(line):
            flush()
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
