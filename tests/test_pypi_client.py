"""Tests for PyPIClient (offline: archive handling and artifact selection)."""

import tarfile
import zipfile
from pathlib import Path

import pytest

from ephemeral_scope.packages.pypi_client import (
    PyPIError,
    _extract,
    _select_artifact,
)


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
