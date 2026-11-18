"""Tests for matching release-note statements to a project's own usage."""

from __future__ import annotations

from pathlib import Path

import pytest

from ephemeral_scope.domain.enums import ChangeType, ReleaseNoteCategory, UsageKind
from ephemeral_scope.domain.models import ApiChange, ApiUsage, ReleaseNoteItem
from ephemeral_scope.ml.relevance_matcher import (
    EXACT_QUALIFIED_MATCH,
    FINAL_NAME_MATCH,
    NO_CONNECTION,
    PACKAGE_MENTION_ONLY,
    PARAMETER_MATCH,
    RelevanceMatcher,
    extract_parameters,
    extract_symbols,
)


def usage(symbol: str) -> ApiUsage:
    return ApiUsage(
        package_name=symbol.split(".")[0],
        symbol=symbol,
        file=Path("src/report.py"),
        line=4,
        column=0,
        usage_kind=UsageKind.METHOD_CALL,
    )


def note(text: str) -> ReleaseNoteItem:
    return ReleaseNoteItem(text=text, release_version="2.32.0", package_name="requests")


@pytest.fixture()
def matcher() -> RelevanceMatcher:
    return RelevanceMatcher(
        usages=[usage("requests.Session.send"), usage("requests.get")],
        changes=[
            ApiChange(
                symbol="requests.Session.request",
                change_type=ChangeType.DEFAULT_CHANGED,
                old_signature="(self, method, url, verify=False)",
                new_signature="(self, method, url, verify=True)",
            )
        ],
        package_name="requests",
    )


class TestExtractSymbols:
    def test_backticked_symbol(self):
        assert "Session.send" in extract_symbols("The `Session.send` method changed.")

    def test_dotted_name_without_markup(self):
        assert "requests.Session" in extract_symbols("requests.Session is now reusable")

    def test_call_expression(self):
        assert "get_adapter" in extract_symbols("Calling get_adapter() is faster.")

    def test_backticked_prose_yields_only_word_like_tokens(self):
        """Extraction is deliberately permissive here; the scoring step, not
        this one, decides whether a token connects to the project."""
        symbols = extract_symbols("`this is just prose` in a note")

        assert symbols == ("just", "prose")

    def test_stop_words_are_discarded(self):
        """Without this every project matches a note containing `True`."""
        assert extract_symbols("Set the flag to `True` or `None`.") == ()

    def test_duplicates_collapse(self):
        symbols = extract_symbols("`Session` and Session.send and `Session`")

        assert symbols.count("Session") == 1


class TestExtractParameters:
    def test_keyword_argument(self):
        assert "verify" in extract_parameters("Passing verify=False is discouraged.")

    def test_multiple_parameters(self):
        parameters = extract_parameters("Use timeout=30 and stream=True together.")

        assert set(parameters) == {"timeout", "stream"}

    def test_equality_comparison_is_not_a_parameter(self):
        assert extract_parameters("when value == 3") == ()


class TestExactMatch:
    def test_fully_qualified_symbol_scores_highest(self, matcher):
        result = matcher.score("`requests.Session.send` no longer retries.")

        assert result.score == EXACT_QUALIFIED_MATCH
        assert "requests.Session.send" in result.matched_project_symbols

    def test_the_connecting_symbol_is_reported(self, matcher):
        result = matcher.score("`requests.get` gained a parameter.")

        assert result.matched_project_symbols == ("requests.get",)


class TestPartialMatch:
    def test_final_component_matches_a_used_symbol(self, matcher):
        result = matcher.score("The `send` method is now synchronous.")

        assert result.score == FINAL_NAME_MATCH
        assert "requests.Session.send" in result.matched_project_symbols

    def test_class_qualified_but_differently_rooted(self, matcher):
        """Changelogs write Session.send where the project writes requests.Session.send."""
        result = matcher.score("`Session.send` now validates the URL.")

        assert result.score >= FINAL_NAME_MATCH

    def test_exact_outranks_final_name(self, matcher):
        exact = matcher.score("`requests.Session.send` changed.")
        partial = matcher.score("`send` changed.")

        assert exact.score > partial.score


class TestParameterMatch:
    def test_parameter_from_a_changed_signature(self, matcher):
        result = matcher.score("The verify=False default has been reversed.")

        assert result.score == PARAMETER_MATCH
        assert "requests.Session.request" in result.matched_project_symbols

    def test_unknown_parameter_does_not_match(self, matcher):
        result = matcher.score("The frobnicate=False default has been reversed.")

        assert result.score < PARAMETER_MATCH


class TestUnrelatedNotes:
    def test_no_connection_scores_zero(self):
        bare = RelevanceMatcher(usages=[usage("requests.Session.send")])

        result = bare.score("Updated the sponsor list in the readme.")

        assert result.score == NO_CONNECTION
        assert result.matched_project_symbols == ()

    def test_package_mention_alone_is_weak(self, matcher):
        result = matcher.score("requests is now tested on Python 3.13.")

        assert result.score == PACKAGE_MENTION_ONLY
        assert result.is_relevant is False

    def test_symbol_from_another_project_does_not_match(self, matcher):
        result = matcher.score("`pandas.DataFrame.append` was removed.")

        assert result.score <= PACKAGE_MENTION_ONLY

    def test_strongest_connection_wins_over_many_weak_ones(self, matcher):
        """One real match should not be diluted by surrounding noise."""
        result = matcher.score(
            "`foo.bar` and `baz.qux` and `quux` and `requests.Session.send` changed."
        )

        assert result.score == EXACT_QUALIFIED_MATCH


class TestPartition:
    def test_splits_relevant_from_general(self, matcher):
        changes = [
            matcher.match(note("`requests.Session.send` no longer retries.")),
            matcher.match(note("Updated the readme.")),
        ]

        relevant, general = matcher.partition(changes)

        assert len(relevant) == 1
        assert len(general) == 1
        assert "Session.send" in relevant[0].note.text

    def test_category_and_decision_survive_partitioning(self, matcher):
        change = matcher.match(
            note("`requests.Session.send` no longer retries."),
            category=ReleaseNoteCategory.BEHAVIORAL_CHANGE,
            confidence=0.8,
        )

        relevant, _ = matcher.partition([change])

        assert relevant[0].category is ReleaseNoteCategory.BEHAVIORAL_CHANGE
        assert relevant[0].confidence == pytest.approx(0.8)

    def test_empty_input(self, matcher):
        assert matcher.partition([]) == ([], [])


class TestMatch:
    def test_produces_the_documented_shape(self, matcher):
        result = matcher.match(
            note("`Session.send` now honours verify=False."),
            category=ReleaseNoteCategory.BEHAVIORAL_CHANGE,
            confidence=0.8,
        )

        assert result.category is ReleaseNoteCategory.BEHAVIORAL_CHANGE
        assert "Session.send" in result.mentioned_symbols
        assert "verify" in result.mentioned_symbols
        assert "requests.Session.send" in result.matched_project_symbols
        assert result.relevance_score > 0

    def test_a_matcher_without_a_project_matches_nothing(self):
        empty = RelevanceMatcher()

        assert empty.score("`requests.Session.send` changed.").score == NO_CONNECTION
