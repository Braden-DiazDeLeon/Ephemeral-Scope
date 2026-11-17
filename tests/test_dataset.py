"""Tests for the training dataset records."""

from pathlib import Path

import pytest

from ephemeral_scope.domain.enums import ReleaseNoteCategory
from ephemeral_scope.domain.models import ReleaseNoteItem
from ephemeral_scope.ml.dataset import (
    LabeledNote,
    is_noise,
    normalize,
    read_jsonl,
    write_jsonl,
)


def item(text: str, section: str | None = None, package: str = "flask"):
    return ReleaseNoteItem(
        text=text,
        release_version="1.0",
        source_url="https://example.test",
        package_name=package,
        section=section,
    )


def note(**kwargs) -> LabeledNote:
    defaults = dict(
        text="Removed the old API.",
        package_name="flask",
        release_version="1.0",
        source_url=None,
        section="Breaking",
        suggested_label=ReleaseNoteCategory.BREAKING_CHANGE,
    )
    return LabeledNote(**{**defaults, **kwargs})


class TestNoise:
    def test_new_contributors_section_is_noise(self):
        assert is_noise(item("Someone did a thing here", section="New Contributors"))

    def test_first_contribution_line_is_noise(self):
        assert is_noise(item("@octocat made their first contribution in #42"))

    def test_bare_version_is_noise(self):
        assert is_noise(item("v2.31.0"))

    def test_very_short_text_is_noise(self):
        assert is_noise(item("Fixed."))

    def test_real_statement_is_kept(self):
        assert not is_noise(item("Removed the deprecated append method."))


class TestNormalize:
    def test_drops_noise(self):
        kept = normalize([item("Removed the deprecated append method."), item("v1.0")])
        assert len(kept) == 1

    def test_collapses_repeats_within_a_package(self):
        text = "Removed the deprecated append method."
        assert len(normalize([item(text), item(text)])) == 1

    def test_keeps_same_text_from_different_packages(self):
        text = "Removed the deprecated append method."
        kept = normalize([item(text, package="flask"), item(text, package="click")])
        assert len(kept) == 2

    def test_collapses_whitespace(self):
        kept = normalize([item("Removed   the\told  append method.")])
        assert kept[0].text == "Removed the old append method."

    def test_matching_ignores_case(self):
        kept = normalize(
            [item("Removed the append method."), item("REMOVED THE APPEND METHOD.")]
        )
        assert len(kept) == 1


class TestRoundTrip:
    def test_write_then_read(self, tmp_path: Path):
        path = tmp_path / "train.jsonl"
        written = write_jsonl(path, [note(), note(text="Added a new option here.")])
        assert written == 2

        loaded = read_jsonl(path)
        assert [n.text for n in loaded] == [
            "Removed the old API.",
            "Added a new option here.",
        ]

    def test_labels_survive(self, tmp_path: Path):
        path = tmp_path / "train.jsonl"
        write_jsonl(path, [note(verified_label=ReleaseNoteCategory.SECURITY_FIX)])
        loaded = read_jsonl(path)[0]
        assert loaded.suggested_label == ReleaseNoteCategory.BREAKING_CHANGE
        assert loaded.verified_label == ReleaseNoteCategory.SECURITY_FIX

    def test_verified_label_wins(self):
        assert note(verified_label=ReleaseNoteCategory.FEATURE).label == (
            ReleaseNoteCategory.FEATURE
        )

    def test_suggested_label_is_the_fallback(self):
        assert note().label == ReleaseNoteCategory.BREAKING_CHANGE

    def test_unlabelled_note(self):
        assert note(suggested_label=None).label is None

    def test_blank_lines_are_ignored(self, tmp_path: Path):
        path = tmp_path / "train.jsonl"
        write_jsonl(path, [note()])
        path.write_text(path.read_text() + "\n\n")
        assert len(read_jsonl(path)) == 1

    def test_malformed_line_reports_its_location(self, tmp_path: Path):
        path = tmp_path / "bad.jsonl"
        path.write_text('{"text": "ok"}\n')
        with pytest.raises(ValueError, match="bad.jsonl:1"):
            read_jsonl(path)
