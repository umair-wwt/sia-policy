import io
import errno
import socket

import pytest
import requests

from sia.checkpoint import CheckpointWriteError
from sia.config import ConfigError
from sia.diagnostics import (Diagnostic, diagnose, get_diagnostic_help, render_diagnostic,
                             search_diagnostic_help)
from sia.http import SIAApiError
from sia.inputs import InputError
from sia.redact import register_secret
from sia.settings import SettingsConflictError


def test_diagnostic_is_stable_redacted_json_data():
    register_secret("private-token")
    diag = Diagnostic("SIA-TEST", "failed private-token", ("remove private-token",),
                      stage="policies", object_name="web01", mutation_state="unknown",
                      details={"password": "unregistered", "raw": "private-token"})
    data = diag.to_dict()
    assert data == {
        "code": "SIA-TEST", "severity": "error", "message": "failed ***", "stage": "policies",
        "object_name": "web01", "mutation_state": "unknown", "actions": ["remove ***"],
        "details": {"password": "***", "raw": "***"},
    }
    with pytest.raises(ValueError, match="mutation_state"):
        Diagnostic("X", "x", mutation_state="maybe")


@pytest.mark.parametrize(("status", "code"), [
    (401, "SIA-AUTH-REJECTED"), (403, "SIA-PERMISSION"), (404, "SIA-NOT-FOUND"),
    (409, "SIA-CONFLICT"), (429, "SIA-RATE-LIMIT"), (503, "SIA-SERVICE"), (422, "SIA-API"),
])
def test_http_statuses_have_specific_diagnostics(status, code):
    diag = diagnose(SIAApiError("GET", "https://tenant.example/api", status, "evidence"), stage="preflight")
    assert diag.code == code and diag.stage == "preflight" and diag.mutation_state == "not_applicable"
    assert diag.details["status"] == status and diag.actions


def test_mutation_state_is_evidence_based():
    uncertain = diagnose(SIAApiError("POST", "https://x/api", 502, "gateway", uncertain=True),
                         stage="policies", object_name="web01")
    rejected = diagnose(SIAApiError("POST", "https://x/api", 409, "duplicate"))
    malformed = diagnose(SIAApiError("POST", "https://x/api", 200, "not json", uncertain=True,
                                     cause="malformed_response"))
    assert uncertain.mutation_state == "unknown" and uncertain.object_name == "web01"
    assert rejected.mutation_state == "not_applied"
    assert malformed.code == "SIA-API-RESPONSE" and malformed.mutation_state == "unknown"
    assert "Do not repeat" in uncertain.actions[0]


@pytest.mark.parametrize(("exc", "code"), [
    (requests.exceptions.ProxyError("proxy unavailable"), "SIA-PROXY"),
    (requests.exceptions.SSLError("certificate verify failed"), "SIA-TLS"),
    (requests.exceptions.Timeout("timed out"), "SIA-TIMEOUT"),
    (requests.exceptions.ConnectionError("connection reset"), "SIA-NETWORK"),
])
def test_request_failures_are_classified_by_evidence(exc, code):
    assert diagnose(exc).code == code


def test_nested_dns_cause_is_detected():
    low = socket.gaierror(-2, "Name or service not known")
    high = requests.exceptions.ConnectionError("connection failed")
    high.__cause__ = low
    assert diagnose(high).code == "SIA-DNS"


def test_local_config_input_and_os_diagnostics(tmp_path):
    assert diagnose(ConfigError("config.toml: invalid TOML")).code == "SIA-CONFIG"
    assert diagnose(InputError("servers.csv:2: invalid fqdn")).code == "SIA-INPUT"
    missing = FileNotFoundError(2, "missing", str(tmp_path / "servers.csv"))
    assert diagnose(missing).code == "SIA-FILE-NOT-FOUND"
    denied = PermissionError(13, "denied", str(tmp_path / "reports"))
    assert diagnose(denied).code == "SIA-LOCAL-PERMISSION"
    assert diagnose(ModuleNotFoundError("No module named 'requests'")).code == "SIA-DEPENDENCY"


def test_config_subclasses_and_named_missing_credentials_are_classified():
    conflict = diagnose(SettingsConflictError("config.toml changed after settings were opened"), stage="Settings")
    assert conflict.code == "SIA-CONFIG" and "changed after settings" in conflict.message
    missing = diagnose(ConfigError("environment variable PVWA_USER is not set (put it in .env or export it)"))
    assert missing.code == "SIA-AUTH-MISSING" and "PVWA_USER" in missing.message
    assert "PVWA_USER" in missing.actions[0]


@pytest.mark.parametrize(("cause", "code"), [
    (FileNotFoundError(errno.ENOENT, "missing", "config.toml"), "SIA-FILE-NOT-FOUND"),
    (PermissionError(errno.EACCES, "denied", "config.toml"), "SIA-LOCAL-PERMISSION"),
    (OSError(errno.ENOSPC, "disk full"), "SIA-DISK-FULL"),
])
def test_wrapped_config_io_keeps_the_actual_recovery_action(cause, code):
    error = ConfigError("Could not update config.toml")
    error.__cause__ = cause
    diagnostic = diagnose(error)
    assert diagnostic.code == code
    assert "config.toml" in diagnostic.message


@pytest.mark.parametrize("status", ["unknown", [], {}, float("inf"), True])
def test_diagnostics_tolerate_malformed_error_metadata(status):
    error = RuntimeError("unexpected response")
    error.status = status
    error.method = "POST"
    error.mutation_state = {}
    diagnostic = diagnose(error)
    assert diagnostic.code == "SIA-UNKNOWN"
    assert diagnostic.mutation_state == "unknown"


def test_checkpoint_failure_keeps_completed_object_evidence(tmp_path):
    path = tmp_path / "checkpoint.jsonl"
    exc = CheckpointWriteError(path, "web01|policy", {"secret": "created", "target_set": "created",
                                                      "policy": "created"}, {"secret": "s1", "policy": "p1"},
                               PermissionError(13, "denied", str(path)))
    diag = diagnose(exc, stage="checkpoint")
    assert diag.code == "SIA-LOCAL-PERMISSION" and diag.mutation_state == "applied"
    assert diag.details["row_key"] == "web01|policy" and diag.details["statuses"]["policy"] == "created"
    assert diag.to_dict()["details"]["refs"]["strong_account"] == "s1"
    assert diag.to_dict()["details"]["statuses"]["strong_account"] == "created"


def test_render_has_plain_sections_and_verbose_details_are_safe():
    register_secret("sensitive-value")
    diag = diagnose(SIAApiError("POST", "https://x/api", 503, "sensitive-value", uncertain=True),
                    stage="secrets", object_name="SA-web")
    normal = io.StringIO()
    render_diagnostic(diag, normal)
    assert "What happened" in normal.getvalue() and "What changed" in normal.getvalue()
    assert "What to do next" in normal.getvalue() and "Technical details" not in normal.getvalue()
    verbose = io.StringIO()
    render_diagnostic(diag, verbose, verbose=True)
    assert "Technical details" in verbose.getvalue() and "sensitive-value" not in verbose.getvalue()


def test_help_catalogue_lookup_and_search():
    assert get_diagnostic_help("sia-tls")["code"] == "SIA-TLS"
    assert get_diagnostic_help("not-a-code") is None
    assert {item["code"] for item in search_diagnostic_help("certificate")} >= {"SIA-TLS"}
    assert len(search_diagnostic_help()) >= 15
