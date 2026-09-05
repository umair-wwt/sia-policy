"""Credential-file ACL behavior at the platform boundary."""
from __future__ import annotations

import os
from types import SimpleNamespace
from pathlib import Path

import pytest

from sia import config, doctor, settings, windows_security
from sia.config import ConfigError
from sia.windows_security import (CredentialPermissionStatus,
                                  WindowsCredentialProtectionError)


def _ordinary_temp(parent: Path, prefix: str) -> tuple[int, Path]:
    path = parent / f"{prefix}test.tmp"
    return os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600), path


def test_permission_status_maps_to_doctor_states():
    assert CredentialPermissionStatus(True, "private").status == "passed"
    assert CredentialPermissionStatus(False, "broad").status == "warning"
    assert CredentialPermissionStatus(None, "unavailable").status == "not checked"


def test_windows_update_protects_existing_and_staged_files_before_replace(tmp_path, monkeypatch):
    destination = tmp_path / ".env"
    destination.write_text("ONE=old\n", encoding="utf-8")
    events = []

    def create(parent, prefix):
        events.append("protected temp created")
        return _ordinary_temp(parent, prefix)

    def protect(path):
        assert Path(path).read_text(encoding="utf-8") == "ONE=old\n"
        events.append("existing protected")

    def inspect(path):
        events.append("destination verified")
        return CredentialPermissionStatus(True, "private")

    monkeypatch.setattr(settings, "windows_acl_supported", lambda: True)
    monkeypatch.setattr(settings, "create_protected_temporary_file", create)
    monkeypatch.setattr(settings, "protect_credential_file", protect)
    monkeypatch.setattr(settings, "inspect_credential_permissions", inspect)

    settings.update_dotenv(destination, {"ONE": "new"})
    assert events == ["protected temp created", "existing protected", "destination verified"]
    assert destination.read_text(encoding="utf-8") == 'ONE="new"\n'


def test_windows_protection_failure_does_not_publish_new_credentials(tmp_path, monkeypatch):
    destination = tmp_path / ".env"
    destination.write_text("ONE=old\n", encoding="utf-8")

    monkeypatch.setattr(settings, "windows_acl_supported", lambda: True)
    monkeypatch.setattr(settings, "create_protected_temporary_file", _ordinary_temp)

    def fail(path):
        raise WindowsCredentialProtectionError(path, "access denied", published=False)

    monkeypatch.setattr(settings, "protect_credential_file", fail)
    with pytest.raises(WindowsCredentialProtectionError) as caught:
        settings.update_dotenv(destination, {"ONE": "new"})
    assert caught.value.published is False
    assert destination.read_text(encoding="utf-8") == "ONE=old\n"
    assert list(tmp_path.iterdir()) == [destination]


def test_windows_protected_temp_failure_never_creates_destination(tmp_path, monkeypatch):
    destination = tmp_path / ".env"
    monkeypatch.setattr(settings, "windows_acl_supported", lambda: True)

    def fail(parent, prefix):
        raise WindowsCredentialProtectionError(parent, "ACL service unavailable", published=False)

    monkeypatch.setattr(settings, "create_protected_temporary_file", fail)
    with pytest.raises(WindowsCredentialProtectionError) as caught:
        settings.update_dotenv(destination, {"SECRET": "new"})
    assert caught.value.published is False
    assert not destination.exists()


def test_post_replace_verification_failure_is_marked_published(tmp_path, monkeypatch):
    destination = tmp_path / ".env"
    destination.write_text("ONE=old\n", encoding="utf-8")
    monkeypatch.setattr(settings, "windows_acl_supported", lambda: True)
    monkeypatch.setattr(settings, "create_protected_temporary_file", _ordinary_temp)
    monkeypatch.setattr(settings, "protect_credential_file", lambda path: None)
    monkeypatch.setattr(settings, "inspect_credential_permissions",
                        lambda path: CredentialPermissionStatus(None, "inspection unavailable"))

    with pytest.raises(WindowsCredentialProtectionError) as caught:
        settings.update_dotenv(destination, {"ONE": "new"})
    assert caught.value.published is True
    assert destination.read_text(encoding="utf-8") == 'ONE="new"\n'


@pytest.mark.skipif(os.name == "nt", reason="non-Windows result")
def test_acl_inspection_is_explicitly_not_applicable_off_windows(tmp_path):
    path = tmp_path / ".env"
    path.write_text("SECRET=value\n", encoding="utf-8")
    status = windows_security.inspect_credential_permissions(path)
    assert status.secure is None and status.status == "not checked"
    assert "not applicable" in status.message


def test_dotenv_reader_warns_when_windows_acl_is_broad(tmp_path, monkeypatch, caplog):
    path = tmp_path / ".env"
    path.write_text("ONE=value\n", encoding="utf-8")
    monkeypatch.setattr(config, "windows_acl_supported", lambda: True)
    monkeypatch.setattr(
        config, "inspect_credential_permissions",
        lambda target: CredentialPermissionStatus(False, "Windows ACL grants Everyone access"),
    )
    assert config.read_dotenv(path) == {"ONE": "value"}
    assert "Windows ACL grants Everyone access" in caplog.text


def test_doctor_reports_windows_acl_result_without_using_chmod(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text("SIA_CLIENT_ID=user\nSIA_CLIENT_SECRET=secret\n", encoding="utf-8")
    args = SimpleNamespace(
        env=str(env_path), config=str(tmp_path / "missing.toml"),
        input=str(tmp_path / "input"), report_dir=str(tmp_path / "reports"),
    )

    class Session:
        def values(self, path):
            return ({"SIA_CLIENT_ID": "user", "SIA_CLIENT_SECRET": "secret"},
                    {"SIA_CLIENT_ID": "dotenv", "SIA_CLIENT_SECRET": "dotenv"})

    monkeypatch.setattr(doctor, "windows_acl_supported", lambda: True)
    monkeypatch.setattr(
        doctor, "inspect_credential_permissions",
        lambda target: CredentialPermissionStatus(None, "Windows ACL inspection was unavailable"),
    )
    monkeypatch.setattr(doctor.importlib.metadata, "version", lambda package: "test")

    def missing_config(args):
        raise ConfigError("missing")

    checks, _ = doctor.local_checks(args, Session(), load_config=missing_config,
                                    load_inputs=lambda cfg, args: None)
    permission = next(item for item in checks if item["name"] == "Credential file permissions")
    assert permission == {
        "name": "Credential file permissions",
        "status": "not checked",
        "message": "Windows ACL inspection was unavailable",
    }


@pytest.mark.skipif(os.name != "nt", reason="native Windows ACL test")
def test_native_protected_temp_remains_private_after_replace(tmp_path):
    destination = tmp_path / ".env"
    destination.write_text("ONE=old\n", encoding="utf-8")
    windows_security.protect_credential_file(destination)
    descriptor, temporary = windows_security.create_protected_temporary_file(
        tmp_path, ".env.native.")
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(b'ONE="new"\r\n')
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, destination)
    status = windows_security.inspect_credential_permissions(destination)
    assert status.secure is True, status.message
