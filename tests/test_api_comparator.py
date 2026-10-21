"""Tests for ApiComparator."""

import pytest

from ephemeral_scope.domain.enums import ApiSymbolKind, ChangeType
from ephemeral_scope.domain.models import ApiSnapshot, ApiSymbol
from ephemeral_scope.packages.api_comparator import ApiComparator


def func(name: str, signature: str, return_type: str | None = None) -> ApiSymbol:
    return ApiSymbol(
        qualified_name=name,
        symbol_kind=ApiSymbolKind.FUNCTION,
        signature=signature,
        return_type=return_type,
    )


def snapshot(*symbols: ApiSymbol, version: str = "1.0.0") -> ApiSnapshot:
    return ApiSnapshot(package_name="requests", version=version, symbols=symbols)


def diff(old_symbols, new_symbols):
    return ApiComparator().compare(
        snapshot(*old_symbols, version="2.28.0"),
        snapshot(*new_symbols, version="2.32.0"),
    )


def kinds_for(changes, symbol):
    return {c.change_type for c in changes if c.symbol == symbol}


def test_identical_snapshots_produce_no_changes():
    symbols = [func("requests.get", "get(url, params=None)")]
    assert diff(symbols, symbols) == []


def test_removed_symbol():
    changes = diff([func("requests.post", "post(url)")], [])
    assert [c.change_type for c in changes] == [ChangeType.REMOVED]
    assert changes[0].symbol == "requests.post"
    assert changes[0].old_signature == "post(url)"


def test_added_symbol():
    changes = diff([], [func("requests.patch", "patch(url)")])
    assert [c.change_type for c in changes] == [ChangeType.ADDED]
    assert changes[0].new_signature == "patch(url)"


def test_signature_changed_matches_spec_example():
    """The exact example from the design: an optional keyword-only param added."""
    changes = diff(
        [func("requests.get", "get(url, params=None)")],
        [func("requests.get", "get(url, params=None, *, timeout=None)")],
    )
    assert len(changes) == 1
    change = changes[0]
    assert change.symbol == "requests.get"
    assert change.change_type == ChangeType.SIGNATURE_CHANGED
    assert change.old_signature == "get(url, params=None)"
    assert change.new_signature == "get(url, params=None, *, timeout=None)"


def test_required_parameter_added():
    changes = diff(
        [func("requests.get", "get(url)")],
        [func("requests.get", "get(url, session)")],
    )
    assert ChangeType.PARAMETER_ADDED_REQUIRED in kinds_for(changes, "requests.get")


def test_optional_parameter_added_is_not_flagged_as_required():
    changes = diff(
        [func("requests.get", "get(url)")],
        [func("requests.get", "get(url, verify=True)")],
    )
    assert ChangeType.PARAMETER_ADDED_REQUIRED not in kinds_for(changes, "requests.get")


def test_parameter_removed():
    changes = diff(
        [func("requests.get", "get(url, verify=True)")],
        [func("requests.get", "get(url)")],
    )
    assert ChangeType.PARAMETER_REMOVED in kinds_for(changes, "requests.get")


def test_parameter_renamed():
    changes = diff(
        [func("requests.get", "get(url, params=None)")],
        [func("requests.get", "get(url, query=None)")],
    )
    kinds = kinds_for(changes, "requests.get")
    assert ChangeType.PARAMETER_RENAMED in kinds
    # A rename must not also be reported as an unrelated add plus remove.
    assert ChangeType.PARAMETER_REMOVED not in kinds


def test_default_changed():
    changes = diff(
        [func("requests.get", "get(url, verify=True)")],
        [func("requests.get", "get(url, verify=False)")],
    )
    change = next(c for c in changes if c.change_type == ChangeType.DEFAULT_CHANGED)
    assert "True" in change.details and "False" in change.details


def test_return_type_changed():
    changes = diff(
        [func("requests.get", "get(url)", return_type="Response")],
        [func("requests.get", "get(url)", return_type="Result")],
    )
    assert [c.change_type for c in changes] == [ChangeType.RETURN_TYPE_CHANGED]


def test_moved_symbol():
    old = ApiSymbol("requests.sessions.Session", ApiSymbolKind.CLASS)
    new = ApiSymbol("requests.Session", ApiSymbolKind.CLASS)
    changes = diff([old], [new])

    assert [c.change_type for c in changes] == [ChangeType.MOVED]
    assert changes[0].symbol == "requests.sessions.Session"
    assert "requests.Session" in changes[0].details


def test_move_suppresses_removed_and_added():
    old = ApiSymbol("requests.sessions.Session", ApiSymbolKind.CLASS)
    new = ApiSymbol("requests.Session", ApiSymbolKind.CLASS)
    kinds = {c.change_type for c in diff([old], [new])}
    assert ChangeType.REMOVED not in kinds
    assert ChangeType.ADDED not in kinds


def test_same_name_different_kind_is_not_a_move():
    old = ApiSymbol("requests.sessions.Session", ApiSymbolKind.CLASS)
    new = ApiSymbol("requests.Session", ApiSymbolKind.FUNCTION)
    kinds = {c.change_type for c in diff([old], [new])}
    assert kinds == {ChangeType.REMOVED, ChangeType.ADDED}


def test_unparsable_signature_still_reports_signature_changed():
    changes = diff(
        [func("requests.get", "get(<cython signature>)")],
        [func("requests.get", "get(??)")],
    )
    assert [c.change_type for c in changes] == [ChangeType.SIGNATURE_CHANGED]


def test_handles_star_args_and_positional_only():
    changes = diff(
        [func("requests.get", "get(url, /, *args, **kwargs)")],
        [func("requests.get", "get(url, /, *args, timeout=None, **kwargs)")],
    )
    assert ChangeType.SIGNATURE_CHANGED in kinds_for(changes, "requests.get")
