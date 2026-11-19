"""The composition root reads the environment and wires production objects."""

from pathlib import Path

import pytest

from ephemeral_scope.main import (
    CHECKOUT_MODEL,
    ConfigurationError,
    Settings,
    create_service,
    model_path,
    resolve_model_path,
)


def test_defaults_leave_the_network_available(monkeypatch):
    monkeypatch.delenv("EPHEMERAL_SCOPE_OFFLINE", raising=False)
    monkeypatch.delenv("EPHEMERAL_SCOPE_TIMEOUT", raising=False)
    monkeypatch.delenv("EPHEMERAL_SCOPE_SWIPL", raising=False)

    settings = Settings.from_environ()

    assert settings.offline is False
    assert settings.timeout == 30.0
    assert settings.swipl is None


def test_environment_configures_caches_offline_and_prolog(tmp_path, monkeypatch):
    monkeypatch.setenv("EPHEMERAL_SCOPE_HTTP_CACHE", str(tmp_path / "http"))
    monkeypatch.setenv("EPHEMERAL_SCOPE_PACKAGE_CACHE", str(tmp_path / "packages"))
    monkeypatch.setenv("EPHEMERAL_SCOPE_OFFLINE", "yes")
    monkeypatch.setenv("EPHEMERAL_SCOPE_TIMEOUT", "12.5")
    monkeypatch.setenv("EPHEMERAL_SCOPE_SWIPL", "/usr/bin/swipl")
    monkeypatch.setenv("EPHEMERAL_SCOPE_MODEL_PATH", str(tmp_path / "missing.joblib"))

    service = create_service()
    http = service.evidence_collector.release_notes_client.http

    assert http is service.evidence_collector.osv_client.http
    assert http.cache_dir == tmp_path / "http"
    assert http.offline is True
    assert http.timeout == 12.5
    assert service.snapshot_builder.pypi_client.cache_dir == tmp_path / "packages"
    assert service.snapshot_builder.pypi_client.timeout == 12.5
    assert service.risk_engine._swipl == "/usr/bin/swipl"
    assert service.risk_engine._timeout == 12.5
    assert service.report_builder.engine is service.risk_engine
    assert service.release_note_classifier.model_path == tmp_path / "missing.joblib"
    assert service.project_loader is not None
    assert service.usage_analyzer is not None
    assert service.comparator is not None
    assert service.dependency_parser is not None


@pytest.mark.parametrize("raw", ["nope", "0", "-1"])
def test_a_bad_timeout_is_rejected(monkeypatch, raw):
    monkeypatch.setenv("EPHEMERAL_SCOPE_TIMEOUT", raw)

    with pytest.raises(ConfigurationError):
        Settings.from_environ()


def test_blank_overrides_are_ignored(monkeypatch):
    monkeypatch.setenv("EPHEMERAL_SCOPE_OFFLINE", "  ")
    monkeypatch.setenv("EPHEMERAL_SCOPE_SWIPL", "")
    monkeypatch.setenv("EPHEMERAL_SCOPE_TIMEOUT", "  ")

    settings = Settings.from_environ()

    assert settings.offline is False
    assert settings.swipl is None
    assert settings.timeout == 30.0


def test_checkout_model_is_preferred_when_present(monkeypatch):
    monkeypatch.delenv("EPHEMERAL_SCOPE_MODEL_PATH", raising=False)

    assert model_path() == CHECKOUT_MODEL
    assert model_path().is_file()


def test_packaged_model_is_used_when_the_checkout_file_is_absent(monkeypatch, tmp_path):
    """An installed wheel has no models/ directory next to site-packages."""
    monkeypatch.delenv("EPHEMERAL_SCOPE_MODEL_PATH", raising=False)
    monkeypatch.setattr(
        "ephemeral_scope.main.CHECKOUT_MODEL", tmp_path / "does-not-exist.joblib"
    )

    resolved = resolve_model_path({})

    assert resolved is not None
    assert resolved.name == "release_note_classifier.joblib"
    assert resolved.is_file()
    assert resolved != CHECKOUT_MODEL


def test_a_missing_model_is_reported_instead_of_inventing_a_path(monkeypatch, tmp_path):
    monkeypatch.setattr("ephemeral_scope.main.resolve_model_path", lambda _environ: None)

    service = create_service()

    assert service.release_note_classifier.model is None
    assert service.release_note_classifier.warning is not None
    assert "EPHEMERAL_SCOPE_MODEL_PATH" in service.release_note_classifier.warning.message
