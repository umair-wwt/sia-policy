"""Accounts-only onboarding (--accounts): the template guard, checkpoint and report-dir handling, flag checks, account
order, the confirmation prompt and skipped ssh rows, each driven through the CLI with the fake tenant."""
import csv
import json

import pytest

from tests.fakes import FakeSIA
from tests.test_cli import FakeContext, _accounts_workspace, _no_account_env, run, shared_context, workspace  # noqa: F401

TEMPLATE = "Golden-Template"


def created_secrets(sia):
    return [payload["secret_name"] for name, payload in sia.calls if name == "create_secret"]


def test_accounts_run_never_reads_the_template_policy(workspace, monkeypatch, capsys):
    """[defaults] template_policy shapes policies only; an accounts run builds none, so it must not need the template."""
    inp, _ = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    cfg = workspace / "config.toml"
    cfg.write_text(cfg.read_text().replace('template_policy = ""', f'template_policy = "{TEMPLATE}"'), encoding="utf-8")
    assert run(workspace, "plan", "--accounts", "--input", str(inp), "--no-report") == 0
    assert "Summary: planned=2" in capsys.readouterr().out
    assert FakeContext.instances[-1].uap.calls == []
    # The same configuration in a server run looks the template up, and fails on this tenant, which has none.
    assert run(workspace, "plan", "--input", str(inp), "--no-report") == 1
    assert f"template_policy {TEMPLATE!r} not found in UAP" in capsys.readouterr().err
    assert ("find_policy_by_name", TEMPLATE) in FakeContext.instances[-1].uap.calls


@pytest.mark.parametrize("existing", [False, True])
def test_apply_accounts_neither_prepares_nor_reports_a_checkpoint(workspace, monkeypatch, capsys, existing):
    inp, pwfile = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    if existing:   # left by an earlier server run
        checkpoint = workspace / "ckpt.jsonl"
        checkpoint.write_text('{"key": "srv01.example.com|srv01.example.com", "version": 3}\n', encoding="utf-8")
    else:
        checkpoint = workspace / "no-such-dir" / "ckpt.jsonl"
    before = checkpoint.read_bytes() if existing else None
    sia = FakeSIA()
    shared_context(monkeypatch, sia=sia)
    assert run(workspace, "apply", "--accounts", "--yes", "--no-report", "--input", str(inp), "--passwords", str(pwfile),
               "--checkpoint", str(checkpoint)) == 0
    captured = capsys.readouterr()
    assert "Summary: created=2" in captured.out and created_secrets(sia) == ["ADM-srv01", "ADM-srv02"]
    assert "Checkpoint:" not in captured.out + captured.err
    if existing:
        assert checkpoint.read_bytes() == before
    else:
        assert not checkpoint.parent.exists()     # not even the writability probe ran


def test_apply_accounts_checks_the_report_dir_before_writing(workspace, monkeypatch, capsys):
    inp, pwfile = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    blocker = workspace / "not-a-directory"
    blocker.write_text("", encoding="utf-8")
    sia = FakeSIA()
    shared_context(monkeypatch, sia=sia)
    assert run(workspace, "apply", "--accounts", "--yes", "--input", str(inp), "--passwords", str(pwfile),
               "--report-dir", str(blocker / "reports")) == 2
    assert "Cannot save reports in" in capsys.readouterr().err
    assert created_secrets(sia) == [] and not sia.secrets


def test_accounts_rejects_ssh_username_without_protocol_ssh(workspace, monkeypatch, capsys):
    inp, _ = _accounts_workspace(workspace)
    shared_context(monkeypatch)
    assert run(workspace, "plan", "--accounts", "--server", "a.example.com", "--workgroup", "--ssh-username", "u",
               "--input", str(inp)) == 2
    assert "--protocol ssh does not apply with --accounts" in capsys.readouterr().err
    assert all(not ctx.sia.calls and not ctx.uap.calls for ctx in FakeContext.instances)


def test_accounts_follow_first_appearance_in_servers_csv(workspace, monkeypatch, capsys):
    """Neither strong_accounts.csv order (bravo, alpha, then the templated ones) nor alphabetical order."""
    inp, _ = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    (inp / "strong_accounts.csv").write_text(
        "name,type,username\nADM-bravo,credentials,Administrator\nADM-alpha,credentials,Administrator\n", encoding="utf-8")
    (inp / "servers.csv").write_text(
        "fqdn,strong_account,domain_joined\n"
        "srv03.example.com,,no\nsrv04.example.com,ADM-alpha,no\nsrv01.example.com,,no\nsrv02.example.com,ADM-bravo,no\n",
        encoding="utf-8")
    shared_context(monkeypatch)
    expected = ["ADM-srv03", "ADM-alpha", "ADM-srv01", "ADM-bravo"]
    assert run(workspace, "plan", "--accounts", "--input", str(inp), "--json") == 0
    assert [a["name"] for a in json.loads(capsys.readouterr().out)["accounts"]] == expected
    report = next((workspace / "reports").glob("*.csv"))
    assert [row["name"] for row in csv.DictReader(report.read_text().splitlines())] == expected


@pytest.mark.parametrize("as_json", [False, True])
def test_apply_accounts_declined_changes_nothing(workspace, monkeypatch, capsys, as_json):
    inp, pwfile = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    sia = FakeSIA()
    shared_context(monkeypatch, sia=sia)
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    fmt = ["--json"] if as_json else []
    assert run(workspace, "apply", "--accounts", "--input", str(inp), "--passwords", str(pwfile), "--no-report", *fmt) == 2
    captured = capsys.readouterr()
    human = captured.err if as_json else captured.out
    assert "Strong accounts:" in human and "Aborted; nothing changed." in human
    assert created_secrets(sia) == [] and not sia.secrets
    if as_json:
        data = json.loads(captured.out)
        assert data["cancelled"] and data["exit_code"] == 2
        assert data["diagnostics"][0]["code"] == "SIA-CANCELLED" and data["diagnostics"][0]["mutation_state"] == "not_applied"


def test_apply_accounts_previews_the_accounts_before_asking(workspace, monkeypatch, capsys):
    inp, pwfile = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    sia = FakeSIA()
    shared_context(monkeypatch, sia=sia)
    at_prompt = {}

    def answer(prompt=""):
        at_prompt["out"], at_prompt["created"] = capsys.readouterr().out, created_secrets(sia)
        return "yes"

    monkeypatch.setattr("builtins.input", answer)
    assert run(workspace, "apply", "--accounts", "--input", str(inp), "--passwords", str(pwfile), "--no-report") == 0
    preview = at_prompt["out"]
    assert "Scope: strong accounts only" in preview and "Strong accounts:" in preview and "Servers:" not in preview
    assert "Summary: planned=2" in preview and preview.rstrip().endswith("Type 'yes' to apply these changes:")
    assert at_prompt["created"] == []
    assert "Summary: created=2" in capsys.readouterr().out and created_secrets(sia) == ["ADM-srv01", "ADM-srv02"]


def test_accounts_skip_ssh_rows_with_a_warning(workspace, monkeypatch, capsys):
    inp, pwfile = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    (inp / "servers.csv").write_text(
        "fqdn,protocol,ssh_username,domain_joined\nlnx01.example.com,ssh,ec2-user,\nsrv01.example.com,,,no\n",
        encoding="utf-8")
    sia = FakeSIA()
    shared_context(monkeypatch, sia=sia)
    assert run(workspace, "apply", "--accounts", "--yes", "--input", str(inp), "--passwords", str(pwfile),
               "--json", "--no-report") == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    skipped = [w for w in data["warnings"] if w.startswith("1 ssh row(s) skipped")]
    assert skipped == ["1 ssh row(s) skipped: Linux ZSP uses an SSH certificate, not a strong account"]
    assert skipped[0] in captured.err
    assert [(a["name"], a["secret_status"]) for a in data["accounts"]] == [("ADM-srv01", "created")]
    assert created_secrets(sia) == ["ADM-srv01"] and data["failures"] == 0
