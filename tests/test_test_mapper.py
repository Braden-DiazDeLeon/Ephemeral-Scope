"""Tests for TestMapper."""

from pathlib import Path

import pytest

from ephemeral_scope.analysis.ast_usage_analyzer import AstUsageAnalyzer
from ephemeral_scope.analysis.test_mapper import TestMapper
from ephemeral_scope.ingestion.project_loader import ProjectLoader


@pytest.fixture()
def project(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "client.py").write_text(
        "import requests\n\n\ndef fetch(url):\n    return requests.get(url)\n"
    )
    (tmp_path / "src" / "unrelated.py").write_text("x = 1\n")

    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_client.py").write_text(
        "from client import fetch\n\n\ndef test_fetch():\n    assert fetch('u')\n"
    )
    (tmp_path / "tests" / "test_unrelated.py").write_text(
        "def test_nothing():\n    assert True\n"
    )
    return tmp_path


def _map(project: Path):
    manifest = ProjectLoader().load_directory(project)
    usages = AstUsageAnalyzer().analyze(manifest, "requests")
    return manifest, usages, TestMapper().map(manifest, usages)


def test_matches_by_naming_convention(project: Path):
    manifest, _, refs = _map(project)
    pairs = {(r.test_file.name, r.source_file.name) for r in refs}
    assert ("test_client.py", "client.py") in pairs


def test_skips_unaffected_sources(project: Path):
    _, _, refs = _map(project)
    assert all(r.source_file.name != "unrelated.py" for r in refs)


def test_symbol_mention_is_recorded(tmp_path: Path):
    (tmp_path / "client.py").write_text("import requests\nrequests.get('u')\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_misc.py").write_text(
        "def test_patched_get(monkeypatch):\n    get = None\n    assert get is None\n"
    )

    manifest = ProjectLoader().load_directory(tmp_path)
    usages = AstUsageAnalyzer().analyze(manifest, "requests")
    refs = TestMapper().map(manifest, usages)

    assert any(r.related_symbol == "requests.get" for r in refs)


def test_symbol_match_requires_whole_word(tmp_path: Path):
    (tmp_path / "client.py").write_text("import requests\nrequests.get('u')\n")
    (tmp_path / "tests").mkdir()
    # "target" contains "get" but must not count as a mention.
    (tmp_path / "tests" / "test_misc.py").write_text(
        "def test_other():\n    target = 1\n    assert target\n"
    )

    manifest = ProjectLoader().load_directory(tmp_path)
    usages = AstUsageAnalyzer().analyze(manifest, "requests")
    refs = TestMapper().map(manifest, usages)

    assert all(r.related_symbol != "requests.get" for r in refs)


def test_no_usages_yields_no_references(project: Path):
    manifest = ProjectLoader().load_directory(project)
    assert TestMapper().map(manifest, []) == []


def test_import_based_match(tmp_path: Path):
    (tmp_path / "service.py").write_text("import requests\nrequests.get('u')\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_everything.py").write_text(
        "import service\n\n\ndef test_it():\n    assert service\n"
    )

    manifest = ProjectLoader().load_directory(tmp_path)
    usages = AstUsageAnalyzer().analyze(manifest, "requests")
    refs = TestMapper().map(manifest, usages)

    pairs = {(r.test_file.name, r.source_file.name) for r in refs}
    assert ("test_everything.py", "service.py") in pairs
