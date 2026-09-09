import io
import errno
import socket
import ssl

import pytest
import requests

from sia.auth import AuthError
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


def test_tls_errno_does_not_read_as_a_local_permission_failure():
    """OpenSSL sets errno = SSL_ERROR_SSL = 1 on ssl.SSLError, colliding with errno.EPERM.

    ssl.SSLError also subclasses OSError, so a probe for local filesystem failures matches a
    certificate error unless it excludes network exceptions. That misreported every TLS failure as
    SIA-LOCAL-PERMISSION and offered file-permission advice for a certificate problem.
    """
    low = ssl.SSLCertVerificationError(
        1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate in certificate chain")
    assert low.errno == errno.EPERM and isinstance(low, OSError)  # pin the collision this guards
    high = requests.exceptions.SSLError(f"Max retries exceeded with url: /oauth2/platformtoken (Caused by {low!r})")
    high.__cause__ = low
    diag = diagnose(high, stage="Authentication")
    assert diag.code == "SIA-TLS"
    assert "ca_bundle" in " ".join(diag.actions)


def test_tls_failure_under_auth_error_reaches_the_tls_code():
    """The shape urllib3 actually produces: AuthError -> requests SSLError -> SSLCertVerificationError."""
    low = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
    high = requests.exceptions.SSLError("HTTPSConnectionPool(host='abc.id.cyberark.cloud', port=443)")
    high.__cause__ = low
    auth = AuthError("could not reach https://abc.id.cyberark.cloud/oauth2/platformtoken: SSLError",
                     operation="platform token request", cause=high)
    assert diagnose(auth, stage="Authentication").code == "SIA-TLS"


def test_tls_is_classified_without_relying_on_the_message_text():
    """Windows builds its verification message with FormatMessageW, so the text is localised.

    truststore raises a bare ssl.SSLCertVerificationError carrying that message, so classification
    has to rest on the exception type rather than on English phrases.
    """
    localised = ssl.SSLCertVerificationError(
        "Die Zertifikatkette wurde von einer nicht vertrauenswuerdigen Stammzertifizierungsstelle ausgestellt.")
    assert diagnose(localised).code == "SIA-TLS"
    wrapped = requests.exceptions.SSLError("HTTPSConnectionPool(host='x', port=443)")
    wrapped.__cause__ = localised
    assert diagnose(wrapped).code == "SIA-TLS"
    auth = AuthError("could not reach the tenant", operation="platform token request", cause=wrapped)
    assert diagnose(auth, stage="Authentication").code == "SIA-TLS"


def test_network_oserrors_do_not_shadow_genuine_filesystem_failures(tmp_path):
    """A real EPERM/EACCES still classifies locally; only network OSErrors are excluded."""
    assert diagnose(PermissionError(errno.EPERM, "Operation not permitted", str(tmp_path))).code == "SIA-LOCAL-PERMISSION"
    assert diagnose(PermissionError(errno.EACCES, "denied", str(tmp_path))).code == "SIA-LOCAL-PERMISSION"
    assert diagnose(OSError(errno.ENOSPC, "No space left on device", str(tmp_path))).code == "SIA-DISK-FULL"
    # a filesystem failure reached through a network exception's context is still local
    denied = PermissionError(errno.EACCES, "denied", str(tmp_path / "corp-ca.pem"))
    wrapper = requests.exceptions.SSLError("could not load CA bundle")
    wrapper.__cause__ = denied
    assert diagnose(wrapper).code == "SIA-LOCAL-PERMISSION"


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
