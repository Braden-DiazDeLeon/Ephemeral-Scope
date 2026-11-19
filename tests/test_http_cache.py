"""Tests for the cached HTTP layer."""

import json
import threading
from pathlib import Path

import pytest

from ephemeral_scope.http_cache import HttpCache


@pytest.fixture()
def cache(tmp_path: Path) -> HttpCache:
    return HttpCache(cache_dir=tmp_path)


def stub(cache: HttpCache, monkeypatch, document, counter: list[int]) -> None:
    def fake_request(method, url, body, headers):
        counter.append(1)
        return document

    monkeypatch.setattr(cache, "_request", fake_request)


def test_second_get_is_served_from_cache(cache, monkeypatch):
    calls: list[int] = []
    stub(cache, monkeypatch, {"value": 1}, calls)

    assert cache.get_json("https://example.test/a") == {"value": 1}
    assert cache.get_json("https://example.test/a") == {"value": 1}
    assert len(calls) == 1


def test_different_urls_are_cached_separately(cache, monkeypatch):
    calls: list[int] = []
    stub(cache, monkeypatch, {"value": 1}, calls)

    cache.get_json("https://example.test/a")
    cache.get_json("https://example.test/b")
    assert len(calls) == 2


def test_post_body_is_part_of_the_cache_key(cache, monkeypatch):
    calls: list[int] = []
    stub(cache, monkeypatch, {"vulns": []}, calls)

    cache.post_json("https://example.test/q", {"version": "1.0"})
    cache.post_json("https://example.test/q", {"version": "2.0"})
    cache.post_json("https://example.test/q", {"version": "1.0"})
    assert len(calls) == 2


def test_offline_returns_none_without_requesting(cache, monkeypatch):
    calls: list[int] = []
    stub(cache, monkeypatch, {"value": 1}, calls)
    cache.offline = True

    assert cache.get_json("https://example.test/a") is None
    assert calls == []


def test_offline_still_reads_an_existing_entry(tmp_path: Path, monkeypatch):
    warm = HttpCache(cache_dir=tmp_path)
    stub(warm, monkeypatch, {"value": 7}, [])
    warm.get_json("https://example.test/a")

    offline = HttpCache(cache_dir=tmp_path, offline=True)
    assert offline.get_json("https://example.test/a") == {"value": 7}


def test_failed_request_is_not_cached(cache, monkeypatch):
    calls: list[int] = []
    stub(cache, monkeypatch, None, calls)

    assert cache.get_json("https://example.test/a") is None
    assert cache.get_json("https://example.test/a") is None
    assert len(calls) == 2


def test_corrupt_entry_is_refetched(cache, monkeypatch, tmp_path: Path):
    calls: list[int] = []
    stub(cache, monkeypatch, {"value": 1}, calls)
    cache.get_json("https://example.test/a")

    entry = next(tmp_path.glob("*.json"))
    entry.write_text("{ truncated")

    assert cache.get_json("https://example.test/a") == {"value": 1}
    assert len(calls) == 2


def test_cache_can_be_disabled(monkeypatch):
    cache = HttpCache(cache_dir=None)
    calls: list[int] = []
    stub(cache, monkeypatch, {"value": 1}, calls)

    cache.get_json("https://example.test/a")
    cache.get_json("https://example.test/a")
    assert len(calls) == 2


def test_no_temporary_files_remain(cache, monkeypatch, tmp_path: Path):
    stub(cache, monkeypatch, {"value": 1}, [])
    cache.get_json("https://example.test/a")
    assert list(tmp_path.glob("*.tmp")) == []


def test_concurrent_stores_use_distinct_temporary_files(cache, tmp_path: Path):
    """A shared .tmp name lets one writer truncate the other's file."""
    path = tmp_path / "entry.json"
    names: list[str] = []
    original = Path.replace

    def record(self: Path, target: Path) -> Path:
        names.append(self.name)
        return original(self, target)

    monkey_names = names

    def store(value: int) -> None:
        cache._store(path, {"value": value})

    # Record the temporary name by wrapping replace on the instance class.
    Path.replace = record  # type: ignore[method-assign]
    try:
        threads = [threading.Thread(target=store, args=(i,)) for i in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)
    finally:
        Path.replace = original  # type: ignore[method-assign]

    assert len(monkey_names) == 2
    assert len(set(monkey_names)) == 2
    assert all(name != "entry.tmp" for name in monkey_names)
    assert json.loads(path.read_text(encoding="utf-8"))["value"] in {0, 1}
    assert list(tmp_path.glob("*.tmp")) == []
