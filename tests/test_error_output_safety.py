import io
import json
import logging

from sia.checkpoint import CHECKPOINT_VERSION, Checkpoint
from sia.diagnostics import diagnose
from sia.http import SIAApiError
from sia.reconcile import ReconcileError
from sia.redact import RedactingFilter
from sia.redact import sanitize


def test_unregistered_token_in_api_body_is_hidden_in_logs_and_exception():
    token = 'UNREGISTERED-SERVER-TOKEN-with-"-quote'
    error = SIAApiError("POST", "https://example.invalid/api/policies", 400, json.dumps({"access_token": token}))
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactingFilter())
    logger = logging.Logger("output-safety")
    logger.addHandler(handler)
    logger.error("operation failed: %s", error)
    assert "UNREGISTERED-SERVER-TOKEN" not in stream.getvalue() + str(error) + error.body
    assert "***" in stream.getvalue()


def test_logging_exception_traceback_is_sanitized():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactingFilter())
    logger = logging.Logger("trace-safety")
    logger.addHandler(handler)
    try:
        raise RuntimeError('response {"client_secret": "unregistered-secret-value"}')
    except RuntimeError:
        logger.exception("Request failed")
    assert "unregistered-secret-value" not in stream.getvalue()


def test_missing_policy_is_known_diagnostic():
    assert diagnose(ReconcileError("policy 'Nope' not found; check the selected tenant")).code == "SIA-NOT-FOUND"


def test_checkpoint_count_excludes_malformed_complete_records(tmp_path):
    path = tmp_path / "checkpoint.jsonl"
    path.write_text(json.dumps({"version": CHECKPOINT_VERSION, "key": "s|p", "fingerprint": "a" * 64,
                                "statuses": {"secret": "exists", "target_set": "exists", "policy": "exists"},
                                "refs": {}, "at": "2026-09-04T00:00:00+00:00"}) + "\n")
    assert Checkpoint(path).done_count() == 0


def test_checkpoint_probe_rejects_existing_directory(tmp_path):
    path = tmp_path / "directory"
    path.mkdir()
    writable, reason = Checkpoint(path).check_writable()
    assert not writable and "not a regular file" in reason


def test_unregistered_pvwa_secret_is_hidden_but_stage_outcomes_survive():
    value = "DUMMY-UNREGISTERED-PVWA-CREDENTIAL"
    error = SIAApiError("POST", "https://example.invalid/Accounts", 400, json.dumps({"secret": value}))
    assert value not in str(error) + error.body + json.dumps(diagnose(error).to_dict())
    assert sanitize({"secret": value}) == {"secret": "***"}
    assert sanitize({"secret": {"status": "exists", "ref": "sa-123"}})["secret"]["ref"] == "sa-123"
    assert sanitize({"secret": {"password": value}}) == {"secret": {"password": "***"}}
