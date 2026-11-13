"""Tests for ReleaseNotesClient (offline, with a stubbed transport)."""

import pytest

from ephemeral_scope.domain.models import DependencyUpgrade
from ephemeral_scope.evidence.release_notes_client import (
    ReleaseNotesClient,
    split_statements,
)

# Mirrors the shape of a real psf/requests release body: an RST title with an
# underline, bold section labels, and hard-wrapped bullets.
BODY = """2.32.0 (2024-05-20)
-------------------
## PyCon Edition

**Security**
- Fixed an issue where setting `verify=False` on the first request from a
  Session will cause subsequent requests to the same origin to also ignore
  cert verification. (GHSA-9wx4-h78v-vm56)

**Deprecations**
- Requests has deprecated support for Python 3.7.

**Full Changelog**: https://github.com/psf/requests/compare/v2.31.0...v2.32.0
"""


class FakeHttp:
    def __init__(self, documents: dict):
        self.documents = documents
        self.urls: list[str] = []

    def get_json(self, url, headers=None):
        self.urls.append(url)
        for fragment, document in self.documents.items():
            if fragment in url:
                return document
        return None


def release(tag: str, body: str = BODY, **extra) -> dict:
    return {
        "tag_name": tag,
        "body": body,
        "html_url": f"https://github.com/psf/requests/releases/tag/{tag}",
        **extra,
    }


def client(releases, metadata=None) -> ReleaseNotesClient:
    documents = {
        "pypi.org": metadata
        if metadata is not None
        else {"info": {"project_urls": {"Source": "https://github.com/psf/requests"}}},
        "api.github.com": releases,
    }
    return ReleaseNotesClient(http=FakeHttp(documents), github_token=None)


class TestSplitStatements:
    def test_joins_hard_wrapped_bullets(self):
        statements = split_statements(BODY)
        security = next(s for s in statements if s.startswith("Fixed an issue"))
        assert "cert verification" in security
        assert "\n" not in security

    def test_drops_headings_and_underlines(self):
        statements = split_statements(BODY)
        assert "Security" not in statements
        assert "Deprecations" not in statements
        assert not any(set(s) == {"-"} for s in statements)

    def test_drops_the_version_title(self):
        assert "2.32.0 (2024-05-20)" not in split_statements(BODY)

    def test_drops_full_changelog_link(self):
        assert not any("Full Changelog" in s for s in split_statements(BODY))

    def test_one_statement_per_bullet(self):
        assert len(split_statements(BODY)) == 2

    def test_markdown_links_become_their_text(self):
        assert split_statements("- See [the docs](https://x.test) now.") == [
            "See the docs now."
        ]

    def test_code_blocks_are_removed(self):
        body = "- Real statement.\n\n```python\nimport junk\n```\n"
        assert split_statements(body) == ["Real statement."]

    def test_prose_is_split_into_sentences(self):
        body = "We removed the old API. Use the new one instead."
        assert split_statements(body) == [
            "We removed the old API.",
            "Use the new one instead.",
        ]

    def test_duplicates_are_collapsed(self):
        assert split_statements("- Same thing.\n- Same thing.\n") == ["Same thing."]

    def test_empty_body(self):
        assert split_statements("") == []


class TestGetNotes:
    def test_returns_statements_for_a_release_in_range(self):
        notes = client([release("v2.32.0")]).get_notes(
            DependencyUpgrade("requests", "2.31.0", "2.32.0")
        )
        assert notes
        assert all(n.release_version == "2.32.0" for n in notes)

    def test_source_url_is_recorded(self):
        notes = client([release("v2.32.0")]).get_notes(
            DependencyUpgrade("requests", "2.31.0", "2.32.0")
        )
        assert notes[0].source_url.endswith("/releases/tag/v2.32.0")

    def test_excludes_the_current_version(self):
        notes = client([release("v2.31.0")]).get_notes(
            DependencyUpgrade("requests", "2.31.0", "2.32.0")
        )
        assert notes == []

    def test_excludes_releases_beyond_the_target(self):
        notes = client([release("v2.33.0")]).get_notes(
            DependencyUpgrade("requests", "2.31.0", "2.32.0")
        )
        assert notes == []

    def test_includes_intermediate_releases(self):
        releases = [release("v2.31.0"), release("v2.32.0")]
        notes = client(releases).get_notes(
            DependencyUpgrade("requests", "2.30.0", "2.32.0")
        )
        assert {n.release_version for n in notes} == {"2.31.0", "2.32.0"}

    def test_drafts_are_skipped(self):
        notes = client([release("v2.32.0", draft=True)]).get_notes(
            DependencyUpgrade("requests", "2.31.0", "2.32.0")
        )
        assert notes == []

    def test_unparsable_tags_are_skipped(self):
        notes = client([release("nightly")]).get_notes(
            DependencyUpgrade("requests", "2.31.0", "2.32.0")
        )
        assert notes == []

    def test_no_repository_yields_nothing(self):
        notes = client([release("v2.32.0")], metadata={"info": {}}).get_notes(
            DependencyUpgrade("requests", "2.31.0", "2.32.0")
        )
        assert notes == []

    def test_unreachable_github_yields_nothing(self):
        notes = client(None).get_notes(DependencyUpgrade("requests", "2.31.0", "2.32.0"))
        assert notes == []


class TestFindRepository:
    @pytest.mark.parametrize(
        "url",
        [
            "https://github.com/psf/requests",
            "https://github.com/psf/requests/",
            "https://github.com/psf/requests.git",
            "http://www.github.com/psf/requests",
        ],
    )
    def test_recognises_github_urls(self, url):
        notes = ReleaseNotesClient(
            http=FakeHttp({"pypi.org": {"info": {"project_urls": {"X": url}}}})
        )
        assert notes.find_repository("requests") == "psf/requests"

    def test_falls_back_to_home_page(self):
        notes = ReleaseNotesClient(
            http=FakeHttp(
                {"pypi.org": {"info": {"home_page": "https://github.com/psf/requests"}}}
            )
        )
        assert notes.find_repository("requests") == "psf/requests"

    def test_ignores_non_github_hosts(self):
        notes = ReleaseNotesClient(
            http=FakeHttp(
                {"pypi.org": {"info": {"project_urls": {"X": "https://gitlab.com/a/b"}}}}
            )
        )
        assert notes.find_repository("requests") is None
