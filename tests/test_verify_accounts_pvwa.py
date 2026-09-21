"""Accounts-only verification checks configured Vault accounts without tenant writes."""
import csv
import json
from types import SimpleNamespace

import pytest

import sia_onboard
from sia.config import ConfigError
from sia.http import SIAApiError
from tests.fakes import FakeIdentity, FakePVWA, FakeSIA, FakeUAP
from tests.test_cli import FakeContext, run, workspace  # noqa: F401 - pytest fixture

ACCOUNT = "ADM-web01"
VAULT_NAME = "web01-Administrator"
SAFE = "SIA-LocalAdmins"
SECRET_NAME = f"{VAULT_NAME}_{SAFE}"
SECRET = {"secret_id": "sec-1", "secret_type": "PCloudAccount", "secret_name": SECRET_NAME, "is_active": True}
VAULT_ACCOUNT = {"id": "1_1", "name": VAULT_NAME, "safeName": SAFE}


@pytest.fixture
def vault_input(workspace):
    config = workspace / "config.toml"
    config.write_text(config.read_text().replace(
        'base_url = ""             # e.g. "https://pvwa.corp.example.com"',
        'base_url = "https://pvwa.corp.example.com"'), encoding="utf-8")
    inp = workspace / "vault-input"
    inp.mkdir()
    (inp / "servers.csv").write_text(
        f"fqdn,strong_account,domain_joined\nweb01.example.com,{ACCOUNT},no\n", encoding="utf-8")
    (inp / "strong_accounts.csv").write_text(
        f"name,type,safe,account_name,username\n{ACCOUNT},vault,{SAFE},{VAULT_NAME},Administrator\n", encoding="utf-8")
    return inp


def tenant(monkeypatch, pvwa, *, secret=True):
    state = SimpleNamespace(sia=FakeSIA([SECRET] if secret else []), uap=FakeUAP(), identity=FakeIdentity(), logins=0)

    class Ctx(FakeContext):
        def __init__(self, cfg):
            super().__init__(cfg)
            self.sia, self.uap, self.identity = state.sia, state.uap, state.identity

        def pvwa_client(self):
            state.logins += 1
            return pvwa

    monkeypatch.setattr(sia_onboard, "Context", Ctx)
    monkeypatch.setattr(sia_onboard, "prompt_secret", lambda *_args: pytest.fail("verify prompted for an account password"))
    return state


def assert_account_reads_only(state, pvwa):
    assert state.logins == 1 and pvwa.logged_off
    assert all(name in ("find_secret", "list_secrets") for name, _ in state.sia.calls)
    assert all(name == "find_account" for name, _ in pvwa.calls)
    assert state.uap.calls == [] and state.identity.queries == []


def test_verify_accounts_checks_existing_vault_and_sia_with_csv(workspace, vault_input, monkeypatch, capsys):
    pvwa = FakePVWA([VAULT_ACCOUNT])
    state = tenant(monkeypatch, pvwa)
    target = workspace / "verify.csv"
    assert run(workspace, "verify", "--accounts", "--input", str(vault_input), "--out", str(target), "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert data["mode"] == "verify" and data["ok"] and data["complete"]
    assert data["accounts"][0]["vault_status"] == data["accounts"][0]["secret_status"] == "exists"
    rows = list(csv.DictReader(target.read_text().splitlines()))
    assert rows[0]["vault"] == "exists" and rows[0]["verdict"] == "PASS"
    assert pvwa.calls == [("find_account", (SAFE, VAULT_NAME))]
    assert_account_reads_only(state, pvwa)


@pytest.mark.parametrize("secret", [True, False])
def test_verify_accounts_missing_vault_is_missing_even_with_sia_reference(
        workspace, vault_input, monkeypatch, capsys, secret):
    pvwa = FakePVWA()
    state = tenant(monkeypatch, pvwa, secret=secret)
    assert run(workspace, "verify", "--accounts", "--input", str(vault_input), "--json") == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    account = data["accounts"][0]
    assert not data["ok"] and data["exit_code"] == 1 and "MISSING=1" in captured.err
    assert account["vault_status"] == "planned" and account["secret_status"] == ("exists" if secret else "planned")
    missing = [d for d in data["diagnostics"] if d["code"] == "SIA-MISSING"]
    assert len(missing) == 1 and missing[0]["object_name"] == ACCOUNT and "Vault account" in missing[0]["message"]
    assert_account_reads_only(state, pvwa)


def test_verify_accounts_missing_vault_without_username_keeps_failure(
        workspace, vault_input, monkeypatch, capsys):
    path = vault_input / "strong_accounts.csv"
    path.write_text(path.read_text().replace(",Administrator\n", ",\n"), encoding="utf-8")
    pvwa = FakePVWA()
    state = tenant(monkeypatch, pvwa)
    assert run(workspace, "verify", "--accounts", "--input", str(vault_input), "--json") == 1
    data = json.loads(capsys.readouterr().out)
    assert not data["ok"] and data["accounts"][0]["vault_status"] == "failed"
    assert "no username" in data["accounts"][0]["vault_detail"]
    assert_account_reads_only(state, pvwa)


@pytest.mark.parametrize("malformed", [False, True])
def test_verify_accounts_vault_lookup_errors_never_pass(workspace, vault_input, monkeypatch, capsys, malformed):
    class BadLookup(FakePVWA):
        def find_account(self, safe, name):
            self.calls.append(("find_account", (safe, name)))
            if malformed:
                return {"name": name, "safeName": safe}
            raise SIAApiError("GET", "/PasswordVault/api/Accounts", 403, "Safe permission denied")

    pvwa = BadLookup()
    state = tenant(monkeypatch, pvwa)
    assert run(workspace, "verify", "--accounts", "--input", str(vault_input), "--json") == 1
    data = json.loads(capsys.readouterr().out)
    assert not data["ok"] and data["accounts"][0]["vault_status"] == ("unverified" if malformed else "failed")
    assert data["accounts"][0]["secret_status"] == "blocked"
    assert_account_reads_only(state, pvwa)


@pytest.mark.parametrize("reason", ["disabled", "credentials", "server_mode", "unselected_vault"])
def test_verify_does_not_open_unneeded_vault_session(workspace, vault_input, monkeypatch, capsys, reason):
    pvwa = FakePVWA()
    state = tenant(monkeypatch, pvwa)
    flags = ["--accounts"]
    if reason == "disabled":
        config = workspace / "config.toml"
        config.write_text(config.read_text().replace(
            'base_url = "https://pvwa.corp.example.com"', 'base_url = ""'), encoding="utf-8")
    elif reason in ("credentials", "unselected_vault"):
        path = vault_input / "strong_accounts.csv"
        header = "name,type,safe,account_name,username\n"
        credential = "ADM-local,credentials,,,Administrator\n"
        path.write_text((path.read_text() if reason == "unselected_vault" else header) + credential, encoding="utf-8")
        path = vault_input / "servers.csv"
        path.write_text(path.read_text() + "web02.example.com,ADM-local,no\n", encoding="utf-8")
        if reason == "credentials":
            path.write_text("fqdn,strong_account,domain_joined\nweb02.example.com,ADM-local,no\n", encoding="utf-8")
        else:
            flags += ["--offset", "1", "--limit", "1"]
        state.sia.secrets = [{"secret_id": "sec-2", "secret_type": "ProvisionerUser", "secret_name": "ADM-local", "is_active": True}]
    else:
        flags = []
        path = vault_input / "servers.csv"
        path.write_text(
            f"fqdn,strong_account,domain_joined,principal\nweb01.example.com,{ACCOUNT},no,SIA-Web-Admins\n", encoding="utf-8")
    code = run(workspace, "verify", *flags, "--input", str(vault_input), "--json")
    data = json.loads(capsys.readouterr().out)
    assert code == (1 if reason == "server_mode" else 0)
    assert state.logins == 0 and pvwa.calls == [] and not pvwa.logged_off
    assert data["accounts"][0]["vault_status"] == "n/a"


@pytest.mark.parametrize("interrupted", [False, True])
def test_verify_pvwa_cleanup_error_preserves_results(workspace, vault_input, monkeypatch, capsys, interrupted):
    class BadLogoff(FakePVWA):
        def logoff(self):
            self.logged_off = True
            raise KeyboardInterrupt() if interrupted else RuntimeError("PVWA cleanup failed")

    pvwa = BadLogoff([VAULT_ACCOUNT])
    state = tenant(monkeypatch, pvwa)
    target = workspace / "verify.csv"
    code = run(workspace, "verify", "--accounts", "--input", str(vault_input), "--out", str(target), "--json")
    data = json.loads(capsys.readouterr().out)
    assert code == (130 if interrupted else 1) and data["exit_code"] == code and not data["ok"]
    assert not data["complete"] and data["interrupted"] is interrupted
    assert data["accounts"][0]["vault_status"] == "exists" and data["accounts"][0]["secret_status"] == "exists"
    assert list(csv.DictReader(target.read_text().splitlines()))[0]["verdict"] == "PASS"
    assert any(d["stage"] == "PVWA logoff" and d["mutation_state"] == "not_applied" for d in data["diagnostics"])
    assert_account_reads_only(state, pvwa)


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_verify_closes_pvwa_after_snapshot_failure_and_keeps_original_error(
        workspace, vault_input, monkeypatch, capsys, cleanup_fails):
    class Logoff(FakePVWA):
        def logoff(self):
            self.logged_off = True
            if cleanup_fails:
                raise RuntimeError("secondary cleanup failure")

    pvwa = Logoff()
    state = tenant(monkeypatch, pvwa)

    def bad_snapshot(_name):
        raise SIAApiError("GET", "/api/secrets", 403, "original snapshot failure")

    monkeypatch.setattr(state.sia, "find_secret", bad_snapshot)
    assert run(workspace, "verify", "--accounts", "--input", str(vault_input), "--json") == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert not data["ok"] and "original snapshot failure" in captured.out and "secondary cleanup failure" not in captured.out
    assert_account_reads_only(state, pvwa)


@pytest.mark.parametrize("interrupted", [False, True])
def test_verify_keeps_partial_account_results_after_unexpected_lookup_error(
        workspace, vault_input, monkeypatch, capsys, interrupted):
    class BrokenLookup(FakePVWA):
        def find_account(self, safe, name):
            self.calls.append(("find_account", (safe, name)))
            raise KeyboardInterrupt() if interrupted else RuntimeError("lookup connection failed")

    pvwa = BrokenLookup()
    state = tenant(monkeypatch, pvwa)
    code = run(workspace, "verify", "--accounts", "--input", str(vault_input), "--json")
    data = json.loads(capsys.readouterr().out)
    assert code == (130 if interrupted else 1) and not data["ok"] and not data["complete"]
    assert data["interrupted"] is interrupted and data["accounts"][0]["secret_status"] == "blocked"
    assert data["diagnostics"]
    assert_account_reads_only(state, pvwa)


def test_verify_vault_auth_failure_uses_existing_command_boundary(workspace, vault_input, monkeypatch, capsys):
    state = tenant(monkeypatch, FakePVWA())

    def no_credentials(_ctx):
        raise ConfigError("[pvwa] is configured but PVWA_USER / PVWA_PASSWORD are not set")

    monkeypatch.setattr(sia_onboard.Context, "pvwa_client", no_credentials)
    assert run(workspace, "verify", "--accounts", "--input", str(vault_input), "--json") == 2
    data = json.loads(capsys.readouterr().out)
    assert not data["ok"] and data["diagnostics"][0]["code"] == "SIA-AUTH-MISSING"
    assert state.sia.calls == [] and state.uap.calls == []
