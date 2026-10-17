"""Tests for AstUsageAnalyzer."""

from pathlib import Path

import pytest

from ephemeral_scope.analysis.ast_usage_analyzer import AstUsageAnalyzer
from ephemeral_scope.domain.enums import UsageKind


def analyze(tmp_path: Path, source: str, package: str = "requests"):
    file = tmp_path / "client.py"
    file.write_text(source)
    return AstUsageAnalyzer().analyze_file(file, package)


def test_plain_import(tmp_path: Path):
    usages = analyze(tmp_path, "import requests\n")
    assert [(u.symbol, u.usage_kind) for u in usages] == [
        ("requests", UsageKind.IMPORT)
    ]


def test_aliased_import_records_alias(tmp_path: Path):
    usages = analyze(tmp_path, "import requests as rq\n")
    assert usages[0].import_alias == "rq"


def test_from_import(tmp_path: Path):
    usages = analyze(tmp_path, "from requests import get\n")
    assert usages[0].symbol == "requests.get"
    assert usages[0].usage_kind == UsageKind.IMPORT


def test_function_call(tmp_path: Path):
    usages = analyze(tmp_path, "import requests\nresponse = requests.get(url)\n")
    call = next(u for u in usages if u.usage_kind == UsageKind.FUNCTION_CALL)
    assert call.package_name == "requests"
    assert call.symbol == "requests.get"
    assert call.line == 2


def test_call_through_alias(tmp_path: Path):
    usages = analyze(tmp_path, "import requests as rq\nrq.get(url)\n")
    call = next(u for u in usages if u.usage_kind == UsageKind.FUNCTION_CALL)
    assert call.symbol == "requests.get"
    assert call.import_alias == "rq"


def test_bare_call_after_from_import(tmp_path: Path):
    usages = analyze(tmp_path, "from requests import get\nget(url)\n")
    call = next(u for u in usages if u.usage_kind == UsageKind.FUNCTION_CALL)
    assert call.symbol == "requests.get"


def test_class_reference(tmp_path: Path):
    usages = analyze(tmp_path, "import requests\ns = requests.Session()\n")
    ref = next(u for u in usages if u.usage_kind == UsageKind.CLASS_REFERENCE)
    assert ref.symbol == "requests.Session"


def test_method_call_on_instance(tmp_path: Path):
    source = "import requests\nsession = requests.Session()\nsession.get(url)\n"
    usages = analyze(tmp_path, source)
    method = next(u for u in usages if u.usage_kind == UsageKind.METHOD_CALL)
    assert method.symbol == "requests.Session.get"
    assert method.line == 3


def test_inheritance(tmp_path: Path):
    source = (
        "from requests.adapters import HTTPAdapter\n"
        "class MyAdapter(HTTPAdapter):\n"
        "    pass\n"
    )
    usages = analyze(tmp_path, source)
    base = next(u for u in usages if u.usage_kind == UsageKind.INHERITANCE)
    assert base.symbol == "requests.adapters.HTTPAdapter"


def test_submodule_import(tmp_path: Path):
    usages = analyze(tmp_path, "import requests.adapters\n")
    assert usages[0].symbol == "requests.adapters"


def test_ignores_other_packages(tmp_path: Path):
    source = "import json\nimport requests\njson.loads(x)\nrequests.get(url)\n"
    usages = analyze(tmp_path, source)
    assert all(u.symbol.startswith("requests") for u in usages)


def test_ignores_relative_imports(tmp_path: Path):
    usages = analyze(tmp_path, "from . import requests\n")
    assert usages == []


def test_records_position(tmp_path: Path):
    usages = analyze(tmp_path, "import requests\nresponse = requests.get(url)\n")
    call = next(u for u in usages if u.usage_kind == UsageKind.FUNCTION_CALL)
    assert call.line == 2
    assert call.column == 11


def test_unparsable_file_is_skipped(tmp_path: Path):
    usages = analyze(tmp_path, "def broken(:\n")
    assert usages == []
