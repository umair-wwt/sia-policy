"""Command-boundary tests: real local paths, fake tenant side effects, and parseable failures."""
import json
import os

import pytest

import sia_onboard
from sia.auth import AuthError
from sia.config import ConfigError
from sia.http import SIAApiError
from sia.report import ReportPaths, ReportWriteError
from sia.runtime import Session
from tests.fakes import FakePVWA, FakeSIA, FakeUAP
from tests.test_cli import ROOT, FakeContext, cp, run, shared_context, workspace  # noqa: F401 - pytest fixture


def test_offline_export_never_constructs_context(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("SIA_CLIENT_ID", raising=False)
    monkeypatch.delenv("SIA_CLIENT_SECRET", raising=False)
    monkeypatch.setattr(sia_onboard, "Context", lambda cfg: pytest.fail("Offline export authenticated"))
    output = tmp_path / "connections.csv"
    code = sia_onboard.main(["connect-info", "--no-tenant", "--config", str(ROOT / "config.example.toml"),
                             "--env", str(tmp_path / "missing.env"), "--input", str(ROOT / "input"), "--out", str(output), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 0 and output.exists() and not data["tenant_checked"] and len(data["rows"]) == 6


@pytest.mark.parametrize("argv", [["--json", "nonsense"], ["plan", "--json", "--workers", "wrong"], ["--json"]])
def test_parser_failure_is_one_json_document(argv, capsys):
    assert sia_onboard.main(argv) == 2
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert not data["ok"] and data["exit_code"] == 2 and data["diagnostics"]
    assert "What to do next" in captured.err


def test_global_options_before_and_after_command(workspace, capsys):
    code = sia_onboard.main(["--config", str(workspace / "config.toml"), "preflight", "--env", str(workspace / ".env"), "--json"])
    assert code == 0 and json.loads(capsys.readouterr().out)["mode"] == "preflight"


def test_settings_show_works_without_credentials_and_no_context(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sia_onboard, "Context", lambda cfg: pytest.fail("Settings authenticated"))
    code = sia_onboard.main(["settings", "--show", "--config", str(ROOT / "config.example.toml"), "--env", str(tmp_path / "none"), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 0 and data["settings"] and all(row["status"] == "missing" for row in data["credentials"])


def test_doctor_collects_independent_local_failures(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sia_onboard, "Context", lambda cfg: pytest.fail("Local doctor authenticated"))
    env = tmp_path / ".env"
    env.write_text("not a dotenv line", encoding="utf-8")
    code = sia_onboard.main(["doctor", "--config", str(tmp_path / "missing.toml"), "--env", str(env), "--input", str(tmp_path / "input"), "--json"])
    data = json.loads(capsys.readouterr().out)
    failures = {check["name"] for check in data["checks"] if check["status"] == "failed"}
    assert code == 1 and {"Configuration", "Credentials file"} <= failures
    assert any(check["name"] == "Tenant checks" and check["status"] == "not checked" for check in data["checks"])
    assert not (tmp_path / "reports").exists()


def test_doctor_rejects_existing_nonregular_credentials_path(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sia_onboard, "Context", lambda cfg: pytest.fail("Local doctor authenticated"))
    env = tmp_path / "credentials"
    env.mkdir()
    code = sia_onboard.main(["doctor", "--config", str(tmp_path / "missing.toml"), "--env", str(env),
                             "--input", str(tmp_path / "input"), "--json"])
    checks = json.loads(capsys.readouterr().out)["checks"]
    credential = next(check for check in checks if check["name"] == "Credentials file")
    assert code == 1 and credential["status"] == "failed"
    assert str(env.resolve()) in credential["message"] and "not a regular file" in credential["message"]


@pytest.mark.parametrize("error", [AuthError("bad login"), SIAApiError("GET", "https://example.invalid/api/policies", 403, "forbidden"), RuntimeError("unexpected failure")])
def test_command_failures_remain_json(workspace, monkeypatch, capsys, error):
    def fail(cfg):
        raise error
    monkeypatch.setattr(sia_onboard, "Context", fail)
    code = run(workspace, "preflight", "--json")
    data = json.loads(capsys.readouterr().out)
    assert code == 1 and data["exit_code"] == 1 and len(data["diagnostics"]) == 1


def test_bad_csv_precedes_authentication(workspace, monkeypatch, capsys):
    monkeypatch.setattr(sia_onboard, "Context", lambda cfg: pytest.fail("Bad input reached authentication"))
    code = run(workspace, "apply", "--input", str(workspace / "missing-input"), "--json", "--yes")
    assert code == 2 and json.loads(capsys.readouterr().out)["diagnostics"]


def test_invalid_explicit_status_is_usage_before_auth(workspace, monkeypatch, capsys):
    monkeypatch.setattr(sia_onboard, "Context", lambda cfg: pytest.fail("Invalid status flags reached authentication"))
    code = run(workspace, "plan", "--input", str(ROOT / "input"), "--set-policy-status", "Active", "--json")
    assert code == 2 and "--update" in json.loads(capsys.readouterr().out)["diagnostics"][0]["message"]


def test_report_failure_preserves_confirmed_result(workspace, monkeypatch, capsys):
    sia, uap = FakeSIA(), FakeUAP()
    shared_context(monkeypatch, sia=sia, uap=uap)
    def fail(*args, **kwargs):
        raise PermissionError("report destination stopped accepting writes")
    monkeypatch.setattr(sia_onboard, "write_reports", fail)
    code = run(workspace, "apply", "--input", str(ROOT / "input"), "--checkpoint", cp(workspace), "--yes", "--json")
    data = json.loads(capsys.readouterr().out)
    assert code == 1 and uap.policies and data["rows"] == 6
    assert data["counts"]["created"] > 0 and data["diagnostics"][-1]["mutation_state"] == "applied"


def test_report_interrupt_preserves_result_partial_paths_and_exit_130(workspace, monkeypatch, capsys):
    partial = workspace / "reports" / "partial.json"
    paths = ReportPaths(partial, partial.with_suffix(".csv"))

    def interrupt(*args, **kwargs):
        partial.parent.mkdir(parents=True, exist_ok=True)
        partial.write_text("retained", encoding="utf-8")
        raise ReportWriteError(paths.csv_path, KeyboardInterrupt(), paths=paths, completed_paths=(partial,))

    monkeypatch.setattr(sia_onboard, "write_reports", interrupt)
    code = run(workspace, "apply", "--input", str(ROOT / "input"), "--checkpoint", cp(workspace), "--yes", "--json")
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    diagnostic = next(item for item in data["diagnostics"]
                      if item["code"] == "SIA-INTERRUPTED" and item["stage"] == "Saving reports")
    assert code == 130 and data["interrupted"] is True and data["complete"] is False
    assert data["counts"]["created"] > 0 and diagnostic["mutation_state"] == "applied"
    assert diagnostic["details"]["completed_paths"] == [str(partial)]
    assert f"Completed report output(s): {partial}" in captured.err


def test_final_summary_broken_pipe_happens_after_durable_report(workspace, monkeypatch, capsys):
    def broken(*args, **kwargs):
        raise BrokenPipeError("consumer closed output")

    monkeypatch.setattr(sia_onboard, "print_summary", broken)
    code = run(workspace, "apply", "--input", str(ROOT / "input"), "--checkpoint", cp(workspace), "--yes", "--json")
    data = json.loads(capsys.readouterr().out)
    saved = list((workspace / "reports").glob("apply-*.json"))
    assert code == 1 and len(saved) == 1
    assert json.loads(saved[0].read_text())["counts"]["created"] > 0
    assert data["counts"]["created"] > 0
    assert any(item["stage"] == "Displaying results" and item["details"]["reports"] for item in data["diagnostics"])


def test_pvwa_logoff_interrupt_keeps_result_report_and_exit_130(workspace, monkeypatch, capsys):
    text = (workspace / "config.toml").read_text().replace(
        'base_url = ""             # e.g. "https://pvwa.corp.example.com"',
        'base_url = "https://pvwa.corp.example.com"',
    )
    (workspace / "config.toml").write_text(text, encoding="utf-8")

    class InterruptedLogoff(FakePVWA):
        def find_account(self, safe, name):
            self.calls.append(("find_account", (safe, name)))
            return {"id": f"existing-{name}", "name": name, "safeName": safe}

        def logoff(self):
            raise KeyboardInterrupt

    FakeContext.pvwa = InterruptedLogoff()
    code = run(workspace, "apply", "--input", str(ROOT / "input"), "--checkpoint", cp(workspace), "--yes", "--json")
    data = json.loads(capsys.readouterr().out)
    saved = list((workspace / "reports").glob("apply-*.json"))
    assert code == 130 and data["interrupted"] is True and data["complete"] is False
    assert len(saved) == 1 and json.loads(saved[0].read_text())["interrupted"] is True
    assert any(item["stage"] == "PVWA logoff" and item["mutation_state"] == "applied" for item in data["diagnostics"])


def test_unexpected_pvwa_logoff_error_keeps_known_result_and_report(workspace, monkeypatch, capsys):
    text = (workspace / "config.toml").read_text().replace(
        'base_url = ""             # e.g. "https://pvwa.corp.example.com"',
        'base_url = "https://pvwa.corp.example.com"',
    )
    (workspace / "config.toml").write_text(text, encoding="utf-8")

    class FailedLogoff(FakePVWA):
        def find_account(self, safe, name):
            return {"id": f"existing-{name}", "name": name, "safeName": safe}

        def logoff(self):
            raise RuntimeError("unexpected cleanup failure")

    FakeContext.pvwa = FailedLogoff()
    code = run(workspace, "apply", "--input", str(ROOT / "input"), "--checkpoint", cp(workspace), "--yes", "--json")
    data = json.loads(capsys.readouterr().out)
    saved = list((workspace / "reports").glob("apply-*.json"))
    assert code == 1 and data["interrupted"] is False and data["complete"] is False
    assert data["counts"]["created"] > 0 and len(saved) == 1
    assert any(item["stage"] == "PVWA logoff" and item["mutation_state"] == "applied" for item in data["diagnostics"])


def test_env_reload_does_not_pollute_process(workspace, monkeypatch, capsys):
    key = "SIA_CLIENT_SECRET"
    monkeypatch.delenv(key, raising=False)
    seen = []
    class Capture(FakeContext):
        def __init__(self, cfg):
            seen.append(os.environ.get(key))
            super().__init__(cfg)
    monkeypatch.setattr(sia_onboard, "Context", Capture)
    session = Session()
    argv = ["preflight", "--config", str(workspace / "config.toml"), "--env", str(workspace / ".env")]
    assert sia_onboard.execute(sia_onboard.build_parser().parse_args(argv), session) == 0
    assert key not in os.environ
    (workspace / ".env").write_text("SIA_CLIENT_ID=svc@acme\nSIA_CLIENT_SECRET=new-secret-value\n", encoding="utf-8")
    assert sia_onboard.execute(sia_onboard.build_parser().parse_args(argv), session) == 0
    assert seen == ["pw", "new-secret-value"] and key not in os.environ


def test_noninteractive_empty_command_does_not_prompt(monkeypatch, capsys):
    monkeypatch.setattr(sia_onboard.sys.stdin, "isatty", lambda: False)
    assert sia_onboard.main([]) == 2
    assert "settings" in capsys.readouterr().out


def test_redirected_stdout_does_not_disable_hidden_prompt(monkeypatch):
    monkeypatch.setattr(sia_onboard.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sia_onboard.sys.stdout, "isatty", lambda: False)
    monkeypatch.setattr(sia_onboard.sys.stderr, "isatty", lambda: True)
    assert sia_onboard.interactive()


def test_ca_override_can_repair_invalid_stored_path(workspace, capsys):
    config = workspace / "config.toml"
    config.write_text(config.read_text().replace('ca_bundle = ""', 'ca_bundle = "missing-ca.pem"'), encoding="utf-8")
    ca = workspace / "available-ca.pem"
    ca.write_text("test-only CA content", encoding="utf-8")
    assert run(workspace, "preflight", "--ca-bundle", str(ca)) == 0
    assert FakeContext.instances[-1].cfg.http.tls_verify == str(ca)
    assert 'ca_bundle = "missing-ca.pem"' in config.read_text()


def test_password_prompt_never_falls_back_to_echo(monkeypatch):
    import getpass
    import warnings
    from sia.runtime import prompt_secret
    def unavailable(prompt):
        warnings.warn("Can not control echo on the terminal", getpass.GetPassWarning, stacklevel=2)
        pytest.fail("Warning should have stopped echoed input")
    monkeypatch.setattr(getpass, "getpass", unavailable)
    with pytest.raises(ConfigError, match="Hidden password input is unavailable"):
        prompt_secret("Password: ")


def test_doctor_rejects_report_path_that_is_a_file(workspace, capsys):
    path = workspace / "not-a-directory"
    path.write_text("existing file", encoding="utf-8")
    assert run(workspace, "doctor", "--input", str(ROOT / "input"), "--report-dir", str(path), "--json") == 1
    checks = json.loads(capsys.readouterr().out)["checks"]
    assert next(check for check in checks if check["name"] == "Reports path")["status"] == "failed"


def test_verify_preserves_missing_diagnostics_for_home(workspace, capsys):
    session = Session(shell_env={}, in_home=True)
    args = sia_onboard.build_parser().parse_args(["verify", "--config", str(workspace / "config.toml"),
                                                 "--env", str(workspace / ".env"), "--input", str(ROOT / "input"), "--json"])
    assert sia_onboard.execute(args, session) == 1
    data = json.loads(capsys.readouterr().out)
    assert any(item["code"] == "SIA-MISSING" for item in data["diagnostics"])
    assert session.last_diagnostics == data["diagnostics"]


def test_wrong_tenant_token_is_structured_failure(workspace, monkeypatch, capsys):
    from tests.test_cli import FakeToken
    class Token(FakeToken):
        claims = {"subdomain": "different-tenant"}
    class Context(FakeContext):
        def __init__(self, cfg):
            super().__init__(cfg)
            self.token = Token()
    monkeypatch.setattr(sia_onboard, "Context", Context)
    assert run(workspace, "preflight", "--json") == 1
    data = json.loads(capsys.readouterr().out)
    assert not data["ok"] and any(check.get("diagnostic", {}).get("code") == "SIA-TENANT-MISMATCH" for check in data["checks"])
    assert not FakeContext.instances[-1].sia.calls


def test_report_failure_does_not_claim_unverified_object_was_created(workspace, monkeypatch, capsys):
    from tests.test_report_redact import result_with
    result = result_with([("unverified", "blocked")])
    result.vault.clear()
    monkeypatch.setattr(sia_onboard.Reconciler, "reconcile", lambda self, **kw: result)
    def fail(*args, **kwargs):
        raise PermissionError("cannot save report")
    monkeypatch.setattr(sia_onboard, "write_reports", fail)
    assert run(workspace, "apply", "--input", str(ROOT / "input"), "--checkpoint", cp(workspace), "--yes", "--json") == 1
    data = json.loads(capsys.readouterr().out)
    assert data["diagnostics"][-1]["mutation_state"] == "unknown"


@pytest.mark.parametrize("status", [404, 405, 501])
def test_unavailable_optional_settings_endpoint_is_not_required(workspace, monkeypatch, capsys, status):
    sia = FakeSIA()
    sia.raise_on_settings = SIAApiError("GET", "https://example.invalid/api/settings", status, "unavailable")
    shared_context(monkeypatch, sia=sia)
    assert run(workspace, "preflight", "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert next(check for check in data["checks"] if check["name"] == "Settings")["status"] == "warning"


def test_apply_exception_keeps_known_rejection_state(capsys):
    args = sia_onboard.argparse.Namespace(command="apply", json=True, verbose=False, _mutation_started=True)
    error = SIAApiError("POST", "https://example.invalid/api/policies", 400, "rejected")
    assert sia_onboard.emit_failure(error, args, Session(shell_env={})) == 1
    assert json.loads(capsys.readouterr().out)["diagnostics"][0]["mutation_state"] == "not_applied"


def test_export_interrupt_keeps_exit_130_and_completed_path_evidence(tmp_path, capsys):
    from sia.artifacts import ArtifactWriteError
    path = tmp_path / "connections.csv"
    error = ArtifactWriteError(path, KeyboardInterrupt(), (path,), (path,))
    args = sia_onboard.argparse.Namespace(command="connect-info", json=True, verbose=False)
    assert sia_onboard.emit_failure(error, args, Session(shell_env={})) == 130
    data = json.loads(capsys.readouterr().out)
    diagnostic = data["diagnostics"][0]
    assert data["exit_code"] == 130 and diagnostic["code"] == "SIA-INTERRUPTED"
    assert diagnostic["details"]["completed_paths"] == [str(path)]
    assert diagnostic["mutation_state"] == "not_applicable"


def test_checkpoint_failure_keeps_partial_json_and_report(workspace, monkeypatch, capsys):
    import errno
    from sia.checkpoint import CheckpointWriteError
    def fail(self, key, fp, statuses, refs):
        raise CheckpointWriteError(self.path, key, statuses, refs, OSError(errno.ENOSPC, "disk full"))
    monkeypatch.setattr(sia_onboard.Checkpoint, "record", fail)
    code = run(workspace, "apply", "--input", str(ROOT / "input"), "--checkpoint", cp(workspace), "--yes", "--json")
    output = capsys.readouterr()
    data = json.loads(output.out)
    assert code == 1 and data["complete"] is False and data["rows"] == 6
    assert data["counts"]["created"] > 0
    assert any(item["code"] == "SIA-DISK-FULL" and item["mutation_state"] == "applied" for item in data["diagnostics"])
    assert list((workspace / "reports").glob("apply-*.json"))


def test_interrupt_during_mutation_is_partial_json_with_exit_130(workspace, monkeypatch, capsys):
    class Interrupted(FakeUAP):
        def create_policy(self, payload):
            super().create_policy(payload)
            raise KeyboardInterrupt
    tenant = Interrupted()
    shared_context(monkeypatch, uap=tenant)
    assert run(workspace, "apply", "--input", str(ROOT / "input"), "--checkpoint", cp(workspace), "--yes", "--json") == 130
    data = json.loads(capsys.readouterr().out)
    assert data["interrupted"] is True and data["complete"] is False
    assert len(tenant.policies) == 1
    assert any(item["code"] == "SIA-INTERRUPTED" and item["mutation_state"] == "unknown" for item in data["diagnostics"])


def test_doctor_accounts_validates_an_fqdn_only_list(workspace, monkeypatch, capsys):
    monkeypatch.setattr(sia_onboard, "Context", lambda cfg: pytest.fail("Local doctor authenticated"))
    cfg = workspace / "config.toml"
    cfg.write_text(cfg.read_text().replace('strong_account_type = "vault"', 'strong_account_type = "credentials"'), encoding="utf-8")
    inp = workspace / "input"
    inp.mkdir()
    (inp / "servers.csv").write_text("fqdn,domain_joined\nsrv01.example.com,no\n", encoding="utf-8")
    assert run(workspace, "doctor", "--accounts", "--input", str(inp), "--json") == 0
    check = next(c for c in json.loads(capsys.readouterr().out)["checks"] if c["name"] == "Server input")
    assert check["status"] == "passed" and "1 servers" in check["message"]
    assert run(workspace, "doctor", "--input", str(inp), "--json") == 1
    check = next(c for c in json.loads(capsys.readouterr().out)["checks"] if c["name"] == "Server input")
    assert check["status"] == "failed" and "principal is required" in check["message"]
