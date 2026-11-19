"""Tests for PyPIClient (offline: archive handling and artifact selection)."""

import tarfile
import threading
import time
import zipfile
from pathlib import Path

import pytest

from ephemeral_scope.packages.pypi_client import (
    DEFAULT_PACKAGE_CACHE,
    PyPIClient,
    PyPIError,
    _extract,
    _select_artifact,
    _source_root,
)


class TestPackageCache:
    def test_the_default_cache_is_deliberate(self):
        assert PyPIClient().cache_dir == DEFAULT_PACKAGE_CACHE
        assert DEFAULT_PACKAGE_CACHE == Path(".cache/packages")

    def test_a_cached_release_is_reused_without_downloading(self, tmp_path: Path):
        nested = tmp_path / "requests-2.28.0" / "requests-2.28.0" / "requests"
        nested.mkdir(parents=True)
        (nested / "__init__.py").write_text("")

        found = PyPIClient(cache_dir=tmp_path).download_source("requests", "2.28.0")

        assert found == nested.parent

    def test_one_download_serves_two_callers_of_the_same_version(self, tmp_path: Path):
        client = PyPIClient(cache_dir=tmp_path)
        calls = {"n": 0}

        def install(package_name: str, version: str, target: Path) -> None:
            calls["n"] += 1
            time.sleep(0.05)
            target.mkdir(parents=True, exist_ok=True)
            (target / "marker.txt").write_text(f"{package_name}=={version}\n")

        client._download_into = install  # type: ignore[method-assign]
        results: list[Path] = []

        def fetch() -> None:
            results.append(client.download_source("requests", "2.28.0"))

        threads = [threading.Thread(target=fetch) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)

        assert calls["n"] == 1
        assert results[0] == results[1]
        assert (results[0] / "marker.txt").is_file()

    def test_an_empty_cache_directory_is_not_a_hit(self, tmp_path: Path):
        empty = tmp_path / "requests-2.28.0"
        empty.mkdir()

        assert _source_root(empty, "requests", "2.28.0") is None


class TestSelectArtifact:
    def test_prefers_wheel_over_sdist(self):
        urls = [
            {"packagetype": "sdist", "filename": "p.tar.gz"},
            {"packagetype": "bdist_wheel", "filename": "p.whl"},
        ]
        assert _select_artifact(urls)["filename"] == "p.whl"

    def test_falls_back_to_sdist(self):
        urls = [{"packagetype": "sdist", "filename": "p.tar.gz"}]
        assert _select_artifact(urls)["filename"] == "p.tar.gz"

    def test_no_artifacts(self):
        assert _select_artifact([]) is None


class TestExtract:
    def test_extracts_zip(self, tmp_path: Path):
        archive = tmp_path / "pkg.whl"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("pkg/__init__.py", "x = 1\n")

        target = tmp_path / "out"
        target.mkdir()
        _extract(archive, target)
        assert (target / "pkg" / "__init__.py").read_text() == "x = 1\n"

    def test_rejects_zip_path_traversal(self, tmp_path: Path):
        archive = tmp_path / "evil.whl"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("../../outside.py", "pwned = True")

        target = tmp_path / "out"
        target.mkdir()
        with pytest.raises(PyPIError, match="escape"):
            _extract(archive, target)

    def test_extracts_tarball(self, tmp_path: Path):
        payload = tmp_path / "__init__.py"
        payload.write_text("y = 2\n")

        archive = tmp_path / "pkg.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            tf.add(payload, arcname="pkg/__init__.py")

        target = tmp_path / "out"
        target.mkdir()
        _extract(archive, target)
        assert (target / "pkg" / "__init__.py").read_text() == "y = 2\n"

    def test_rejects_tar_path_traversal(self, tmp_path: Path):
        payload = tmp_path / "evil.py"
        payload.write_text("pwned = True")

        archive = tmp_path / "evil.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            tf.add(payload, arcname="../../outside.py")

        target = tmp_path / "out"
        target.mkdir()
        with pytest.raises(PyPIError, match="escape"):
            _extract(archive, target)
