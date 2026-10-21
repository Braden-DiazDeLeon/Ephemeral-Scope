"""Tests for ApiSnapshotBuilder."""

from pathlib import Path

import pytest

from ephemeral_scope.domain.enums import ApiSymbolKind
from ephemeral_scope.packages.api_comparator import ApiComparator
from ephemeral_scope.packages.api_snapshot_builder import ApiSnapshotBuilder

OLD_SOURCE = '''
def get(url, params=None):
    """Send a GET request."""
    return url


class Session:
    timeout = 5

    def request(self, method, url):
        return method


def _internal():
    pass
'''

NEW_SOURCE = '''
def get(url, params=None, *, timeout=None):
    """Send a GET request."""
    return url


class Session:
    timeout = 5

    def request(self, method, url, allow_redirects=True):
        return method


def _internal():
    pass
'''


def make_package(root: Path, source: str) -> Path:
    pkg = root / "fakelib"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text(source)
    return root


@pytest.fixture()
def old_snapshot(tmp_path: Path):
    root = make_package(tmp_path / "old", OLD_SOURCE)
    return ApiSnapshotBuilder().build_from_path("fakelib", "2.28.0", root)


@pytest.fixture()
def new_snapshot(tmp_path: Path):
    root = make_package(tmp_path / "new", NEW_SOURCE)
    return ApiSnapshotBuilder().build_from_path("fakelib", "2.32.0", root)


def symbol(snapshot, name):
    return next(s for s in snapshot.symbols if s.qualified_name == name)


def test_snapshot_records_version(old_snapshot):
    assert old_snapshot.package_name == "fakelib"
    assert old_snapshot.version == "2.28.0"


def test_discovers_function(old_snapshot):
    sym = symbol(old_snapshot, "fakelib.get")
    assert sym.symbol_kind == ApiSymbolKind.FUNCTION
    assert sym.signature == "get(url, params=None)"


def test_discovers_class_and_method(old_snapshot):
    assert symbol(old_snapshot, "fakelib.Session").symbol_kind == ApiSymbolKind.CLASS
    method = symbol(old_snapshot, "fakelib.Session.request")
    assert method.symbol_kind == ApiSymbolKind.METHOD


def test_discovers_attribute(old_snapshot):
    sym = symbol(old_snapshot, "fakelib.Session.timeout")
    assert sym.symbol_kind == ApiSymbolKind.ATTRIBUTE


def test_excludes_private_symbols(old_snapshot):
    names = {s.qualified_name for s in old_snapshot.symbols}
    assert "fakelib._internal" not in names


def test_keyword_only_parameter_is_rendered(new_snapshot):
    assert symbol(new_snapshot, "fakelib.get").signature == (
        "get(url, params=None, *, timeout=None)"
    )


SIGNATURES = [
    "a(x, y=1)",
    "b(x, /, y, *, z=2)",
    "c(x, *args, y=1, **kwargs)",
    "d()",
    "e(x: int = 3, *, y: str = 's')",
    "f(a, b, /)",
    "g(*, only)",
]


@pytest.mark.parametrize("signature", SIGNATURES)
def test_signature_rendering_round_trips(tmp_path: Path, signature: str):
    """Rendered signatures must match what `inspect` reports for the same code."""
    root = make_package(tmp_path, f"def {signature}: pass\n")
    snapshot = ApiSnapshotBuilder().build_from_path("fakelib", "1.0", root)

    name = signature.split("(", 1)[0]
    assert symbol(snapshot, f"fakelib.{name}").signature == signature


def test_variadic_params_have_no_phantom_defaults(tmp_path: Path):
    """Griffe reports `()` and `{}` for *args/**kwargs; they are not defaults."""
    root = make_package(tmp_path, "def h(*args, **kwargs): pass\n")
    snapshot = ApiSnapshotBuilder().build_from_path("fakelib", "1.0", root)
    assert symbol(snapshot, "fakelib.h").signature == "h(*args, **kwargs)"


def test_class_signature_omits_self(tmp_path: Path):
    """A class borrows __init__'s parameters; callers never pass `self`."""
    root = make_package(tmp_path, "class C:\n    def __init__(self, host, port=80): pass\n")
    snapshot = ApiSnapshotBuilder().build_from_path("fakelib", "1.0", root)
    assert symbol(snapshot, "fakelib.C").signature == "C(host, port=80)"


def test_method_signature_keeps_self(tmp_path: Path):
    root = make_package(tmp_path, "class C:\n    def go(self, x): pass\n")
    snapshot = ApiSnapshotBuilder().build_from_path("fakelib", "1.0", root)
    assert symbol(snapshot, "fakelib.C.go").signature == "go(self, x)"


def test_end_to_end_diff(old_snapshot, new_snapshot):
    changes = ApiComparator().compare(old_snapshot, new_snapshot)
    by_symbol = {c.symbol: c for c in changes}

    assert "fakelib.get" in by_symbol
    assert by_symbol["fakelib.get"].old_signature == "get(url, params=None)"
    assert by_symbol["fakelib.get"].new_signature == (
        "get(url, params=None, *, timeout=None)"
    )
