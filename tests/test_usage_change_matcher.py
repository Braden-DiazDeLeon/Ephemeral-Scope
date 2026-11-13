"""Tests for ApiChange.affects and UsageChangeMatcher."""

from pathlib import Path

import pytest

from ephemeral_scope.analysis.usage_change_matcher import UsageChangeMatcher
from ephemeral_scope.domain.enums import ChangeType, UsageKind
from ephemeral_scope.domain.models import ApiChange, ApiUsage


def usage(symbol: str, package: str = "pandas", line: int = 1) -> ApiUsage:
    return ApiUsage(
        package_name=package,
        symbol=symbol,
        file=Path("/proj/src/report.py"),
        line=line,
        column=0,
        usage_kind=UsageKind.METHOD_CALL,
    )


def change(symbol: str, change_type: ChangeType = ChangeType.REMOVED) -> ApiChange:
    return ApiChange(symbol=symbol, change_type=change_type)


class TestAffects:
    def test_exact_match(self):
        assert change("pandas.DataFrame.append").affects(usage("pandas.DataFrame.append"))

    def test_matches_across_definition_site_module_path(self):
        """Projects write `pandas.DataFrame`; Griffe records the real module."""
        assert change("pandas.core.frame.DataFrame.append").affects(
            usage("pandas.DataFrame.append")
        )

    def test_removed_class_affects_usage_of_its_method(self):
        assert change("pandas.core.frame.DataFrame").affects(
            usage("pandas.DataFrame.append")
        )

    def test_removed_method_does_not_affect_usage_of_the_class(self):
        """Referencing DataFrame says nothing about calling append."""
        assert not change("pandas.core.frame.DataFrame.append").affects(
            usage("pandas.DataFrame")
        )

    def test_different_package_never_matches(self):
        assert not change("numpy.core.array").affects(usage("pandas.array"))

    def test_unrelated_symbol(self):
        assert not change("pandas.core.series.Series.append").affects(
            usage("pandas.read_csv")
        )

    def test_bare_package_import_is_not_affected(self):
        """`import pandas` alone pins no specific API."""
        assert not change("pandas.core.frame.DataFrame.append").affects(
            usage("pandas")
        )

    def test_same_leaf_different_class_still_matches_tail(self):
        """Known limitation: matching is tail-based, so leaves can collide."""
        assert change("pandas.core.series.Series.append").affects(
            usage("pandas.append")
        )


class TestMatcher:
    def test_produces_expected_record(self):
        usages = [usage("pandas.DataFrame.append", line=4)]
        changes = [change("pandas.core.frame.DataFrame.append")]

        affected = UsageChangeMatcher().match(usages, changes)
        assert len(affected) == 1
        assert affected[0].to_dict(Path("/proj")) == {
            "file": "src/report.py",
            "line": 4,
            "symbol": "pandas.DataFrame.append",
            "change": "removed",
        }

    def test_ignores_additions_by_default(self):
        usages = [usage("pandas.DataFrame.append")]
        changes = [change("pandas.DataFrame.append", ChangeType.ADDED)]
        assert UsageChangeMatcher().match(usages, changes) == []

    def test_change_types_can_be_overridden(self):
        usages = [usage("pandas.DataFrame.append")]
        changes = [change("pandas.DataFrame.append", ChangeType.ADDED)]
        affected = UsageChangeMatcher().match(
            usages, changes, change_types=[ChangeType.ADDED]
        )
        assert len(affected) == 1

    def test_unused_changes_are_dropped(self):
        usages = [usage("pandas.read_csv")]
        changes = [change("pandas.core.frame.DataFrame.append")]
        assert UsageChangeMatcher().match(usages, changes) == []

    def test_one_record_per_usage_change_pair(self):
        usages = [usage("pandas.DataFrame.append")]
        changes = [
            change("pandas.core.frame.DataFrame.append", ChangeType.SIGNATURE_CHANGED),
            change("pandas.core.frame.DataFrame.append", ChangeType.PARAMETER_REMOVED),
        ]
        affected = UsageChangeMatcher().match(usages, changes)
        assert {a.change.change_type for a in affected} == {
            ChangeType.SIGNATURE_CHANGED,
            ChangeType.PARAMETER_REMOVED,
        }

    def test_results_are_sorted_by_location(self):
        usages = [
            usage("pandas.DataFrame.append", line=9),
            usage("pandas.DataFrame.append", line=2),
        ]
        changes = [change("pandas.core.frame.DataFrame.append")]
        affected = UsageChangeMatcher().match(usages, changes)
        assert [a.usage.line for a in affected] == [2, 9]

    def test_to_dict_keeps_absolute_path_outside_root(self):
        affected = UsageChangeMatcher().match(
            [usage("pandas.DataFrame.append")],
            [change("pandas.DataFrame.append")],
        )
        assert affected[0].to_dict(Path("/elsewhere"))["file"] == "/proj/src/report.py"
