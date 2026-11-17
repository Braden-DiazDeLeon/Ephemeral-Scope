"""Tests for ReleaseNotesClient (offline, with a stubbed transport)."""

import pytest

from ephemeral_scope.domain.models import DependencyUpgrade
from ephemeral_scope.evidence.release_notes_client import (
    GITHUB_PAGE_SIZE,
    ReleaseNotesClient,
    split_statement_records,
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


class TestSections:
    def test_bold_heading_becomes_the_section(self):
        records = split_statement_records(BODY)
        security = next(r for r in records if r.text.startswith("Fixed an issue"))
        assert security.section == "Security"

    def test_section_applies_to_following_bullets(self):
        records = split_statement_records(BODY)
        deprecation = next(r for r in records if "deprecated support" in r.text)
        assert deprecation.section == "Deprecations"

    def test_markdown_heading_becomes_the_section(self):
        records = split_statement_records("## Bug Fixes\n\n- Fixed a crash here.\n")
        assert records[0].section == "Bug Fixes"

    def test_rst_underlined_heading_becomes_the_section(self):
        body = "Security\n--------\n\n- Fixed a leak in the parser.\n"
        assert split_statement_records(body)[0].section == "Security"

    def test_release_title_is_not_a_section(self):
        """`2.32.0 (2024-05-20)` names the release, not a category."""
        body = "2.32.0 (2024-05-20)\n-------------------\n\n- Fixed a crash here.\n"
        assert split_statement_records(body)[0].section is None

    def test_statement_without_a_heading_has_no_section(self):
        assert split_statement_records("- Fixed a crash here.\n")[0].section is None

    def test_section_is_replaced_by_the_next_heading(self):
        body = "**Security**\n- Fixed a leak here.\n\n**Features**\n- Added an option.\n"
        records = split_statement_records(body)
        assert [r.section for r in records] == ["Security", "Features"]

    def test_split_statements_still_returns_plain_strings(self):
        assert all(isinstance(s, str) for s in split_statements(BODY))


class TestPackageNameAndSection:
    def test_notes_carry_the_package_name(self):
        notes = client([release("v2.32.0")]).get_notes(
            DependencyUpgrade("requests", "2.31.0", "2.32.0")
        )
        assert all(n.package_name == "requests" for n in notes)

    def test_notes_carry_the_section(self):
        notes = client([release("v2.32.0")]).get_notes(
            DependencyUpgrade("requests", "2.31.0", "2.32.0")
        )
        assert any(n.section == "Security" for n in notes)


class TestGetAllNotes:
    def test_ignores_the_upgrade_window(self):
        releases = [release("v1.0.0"), release("v2.31.0"), release("v9.9.9")]
        notes = client(releases).get_all_notes("requests")
        assert {n.release_version for n in notes} == {"1.0.0", "2.31.0", "9.9.9"}

    def test_still_skips_drafts(self):
        notes = client([release("v1.0.0", draft=True)]).get_all_notes("requests")
        assert notes == []

    def test_still_skips_unparsable_tags(self):
        notes = client([release("nightly")]).get_all_notes("requests")
        assert notes == []

    def test_no_repository_yields_nothing(self):
        notes = client([release("v1.0.0")], metadata={"info": {}}).get_all_notes(
            "requests"
        )
        assert notes == []


class PagedHttp:
    """Serves a release list across GitHub-sized pages."""

    def __init__(self, total: int):
        self.pages = [
            [release(f"v1.0.{i}") for i in range(start, min(start + GITHUB_PAGE_SIZE, total))]
            for start in range(0, max(total, 1), GITHUB_PAGE_SIZE)
        ]
        self.requested: list[int] = []

    def get_json(self, url, headers=None):
        if "pypi.org" in url:
            return {"info": {"project_urls": {"Source": "https://github.com/a/b"}}}
        page = int(url.rsplit("page=", 1)[1])
        self.requested.append(page)
        return self.pages[page - 1] if page <= len(self.pages) else []


class TestPagination:
    def test_follows_pages_until_a_partial_one(self):
        http = PagedHttp(total=250)
        releases = ReleaseNotesClient(http=http)._get_releases("pkg")
        assert len(releases) == 250
        assert http.requested == [1, 2, 3]

    def test_stops_after_a_single_partial_page(self):
        http = PagedHttp(total=19)
        assert len(ReleaseNotesClient(http=http)._get_releases("pkg")) == 19
        assert http.requested == [1]

    def test_exactly_one_full_page_checks_for_more(self):
        """A full page is indistinguishable from a truncated one."""
        http = PagedHttp(total=GITHUB_PAGE_SIZE)
        assert len(ReleaseNotesClient(http=http)._get_releases("pkg")) == GITHUB_PAGE_SIZE
        assert http.requested == [1, 2]


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

    def test_ignores_sponsors_funding_links(self):
        """github.com/sponsors/<user> is a funding page, not a repository."""
        notes = ReleaseNotesClient(
            http=FakeHttp(
                {
                    "pypi.org": {
                        "info": {
                            "project_urls": {
                                "Funding": "https://github.com/sponsors/samuelcolvin",
                                "Source": "https://github.com/pydantic/pydantic",
                            }
                        }
                    }
                }
            )
        )
        assert notes.find_repository("pydantic") == "pydantic/pydantic"

    def test_sponsors_link_alone_resolves_to_nothing(self):
        notes = ReleaseNotesClient(
            http=FakeHttp(
                {
                    "pypi.org": {
                        "info": {
                            "project_urls": {
                                "Funding": "https://github.com/sponsors/hynek"
                            }
                        }
                    }
                }
            )
        )
        assert notes.find_repository("attrs") is None
