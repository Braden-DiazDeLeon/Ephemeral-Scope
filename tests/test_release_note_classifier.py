"""Tests for the keyword and trained release-note classifiers."""

import pytest

from ephemeral_scope.domain.enums import ReleaseNoteCategory as Category
from ephemeral_scope.domain.models import ReleaseNoteItem
from ephemeral_scope.ml.release_note_classifier import (
    KeywordReleaseNoteClassifier,
    ReleaseNoteClassifier,
)


@pytest.fixture()
def keywords() -> KeywordReleaseNoteClassifier:
    return KeywordReleaseNoteClassifier()


def item(text: str, section: str | None = None) -> ReleaseNoteItem:
    return ReleaseNoteItem(text=text, release_version="1.0", section=section)


class TestSectionLabels:
    @pytest.mark.parametrize(
        "section,expected",
        [
            ("Security", Category.SECURITY_FIX),
            ("Deprecations", Category.DEPRECATION),
            ("Bugfixes", Category.BUG_FIX),
            ("Breaking Changes", Category.BREAKING_CHANGE),
            ("Features", Category.FEATURE),
            ("Documentation", Category.IRRELEVANT),
        ],
    )
    def test_known_sections(self, keywords, section, expected):
        assert keywords.label("something happened", section) == expected

    def test_section_is_case_insensitive(self, keywords):
        assert keywords.label("x", "SECURITY") == Category.SECURITY_FIX

    def test_section_outranks_keywords(self, keywords):
        """A heading is authored as a category; prose is incidental."""
        assert keywords.label("Fixed a bug", "Security") == Category.SECURITY_FIX

    def test_unknown_section_falls_through_to_keywords(self, keywords):
        assert keywords.label("Fixed a crash", "Whatever") == Category.BUG_FIX


class TestKeywordRules:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("Fixes CVE-2023-32681 in the proxy handler", Category.SECURITY_FIX),
            ("Resolves GHSA-9wx4-h78v-vm56", Category.SECURITY_FIX),
            ("This is a breaking change to the API", Category.BREAKING_CHANGE),
            ("DataFrame.append has been removed", Category.BREAKING_CHANGE),
            ("Dropped support for Python 3.7", Category.BREAKING_CHANGE),
            ("The append method is deprecated", Category.DEPRECATION),
            ("This helper will be removed in 3.0", Category.DEPRECATION),
            ("get() now returns a tuple", Category.BEHAVIORAL_CHANGE),
            ("Fixed a regression in the parser", Category.BUG_FIX),
            ("Added a new timeout parameter", Category.FEATURE),
            ("Fixed a typo in the documentation", Category.IRRELEVANT),
        ],
    )
    def test_rules(self, keywords, text, expected):
        assert keywords.label(text) == expected

    def test_security_outranks_bug_fix(self, keywords):
        assert keywords.label("Fixed a security vulnerability") == Category.SECURITY_FIX

    def test_breaking_outranks_feature(self, keywords):
        text = "Removed the deprecated option and added a replacement"
        assert keywords.label(text) == Category.BREAKING_CHANGE

    def test_no_match_returns_none(self, keywords):
        assert keywords.label("Thanks to everyone involved") is None


class TestConfidence:
    def test_section_match_is_most_confident(self, keywords):
        _, confidence = keywords.label_with_confidence("x", "Security")
        assert confidence == pytest.approx(0.8)

    def test_keyword_match_is_less_confident(self, keywords):
        category, confidence = keywords.label_with_confidence("Fixed a crash")
        assert category == Category.BUG_FIX
        assert confidence == pytest.approx(0.5)

    def test_no_match_is_irrelevant_and_unconfident(self, keywords):
        category, confidence = keywords.label_with_confidence("Thanks everyone")
        assert category == Category.IRRELEVANT
        assert confidence < 0.2


class TestReleaseNoteClassifier:
    def test_falls_back_to_keywords_without_a_model(self):
        results = ReleaseNoteClassifier().classify(
            [item("Fixes CVE-2023-32681"), item("Added an option", "Features")]
        )
        assert [r.category for r in results] == [
            Category.SECURITY_FIX,
            Category.FEATURE,
        ]

    def test_empty_input(self):
        assert ReleaseNoteClassifier().classify([]) == []

    def test_notes_are_preserved_on_the_result(self):
        note = item("Fixed a crash")
        assert ReleaseNoteClassifier().classify([note])[0].note is note

    def test_missing_model_file_degrades_to_keywords(self, tmp_path):
        classifier = ReleaseNoteClassifier(model_path=tmp_path / "absent.joblib")
        assert classifier.model is None
        assert classifier.classify([item("Fixed a crash")])[0].category == (
            Category.BUG_FIX
        )
