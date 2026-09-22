"""Review fixes for the accounts-only run (--accounts) and the inputs it shares with the server run.

Password-file keys by address, domain accounts behind standalone rows, recovery advice that works with --accounts,
shared local accounts, Vault reasons, unreached accounts in the totals, capped tables, doctor, checkpoints.
"""
import io
import json
import logging
from dataclasses import replace

import pytest

import sia_onboard
from sia.checkpoint import Checkpoint
from sia.config import StrongAccountTemplate
from sia.diagnostics import Diagnostic, for_accounts_scope
from sia.http import SIAApiError
from sia.help import help_text
from sia.inputs import InputError, inline_inputs, load_inputs
from sia.payloads import build_secret_payload
from sia.reconcile import AccountResult, Outcome, RunResult
from sia.runtime import Session
from sia.report import print_summary, result_dict, result_diagnostics
from tests.fakes import FakeIdentity, FakePVWA, FakeSIA
from tests.test_cli import FakeContext, _accounts_workspace, _no_account_env, run, shared_context, workspace  # noqa: F401
from tests.test_resolve_reconcile import ACCOUNT_ROWS, PASSWORDS, make, sa, srv

CREDS_SPEC = StrongAccountTemplate(name="ADM-{hostname}", type="credentials", username="Administrator")
DOMAIN_SPEC = StrongAccountTemplate(name="ADM-{hostname}", type="credentials", username="adm-{hostname}",
                                    account_domain="corp.example.com")


def _actions(diagnostics) -> list[str]:
    return [action for d in diagnostics for action in (d["actions"] if isinstance(d, dict) else d.actions)]


# ---------------------------------------------------------------- password-file keys (address owned by one account)
def test_an_address_several_accounts_carry_is_nobodys_password(tmp_path):
    """Templated per-host domain accounts all carry the AD domain as address; one row keyed by it must not become
    their passwords (nor the declared domain account's, which shares the address)."""
    (tmp_path / "servers.csv").write_text("fqdn,strong_account\nweb01.corp.example.com,SA-corp\n"
                                          "web02.corp.example.com,\nweb03.corp.example.com,\n", encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text(
        "name,type,username,account_domain,address\nSA-corp,credentials,svc-sia,corp.example.com,corp.example.com\n",
        encoding="utf-8")
    inputs = load_inputs(tmp_path, strong_account_template=DOMAIN_SPEC, principal_template="SIA-RDP")
    owners = inputs.address_owners()
    assert owners["corp.example.com"] == ("SA-corp", "ADM-web02", "ADM-web03")
    get = sia_onboard.make_password_source(False, {"corp.example.com": "svc-pw"},
                                           shared_addresses={a for a, n in owners.items() if len(n) > 1})
    assert [get(inputs.strong_accounts[n]) for n in ("SA-corp", "ADM-web02", "ADM-web03")] == [None, None, None]
    assert sia_onboard.make_password_source(False, {"SA-corp": "svc-pw"})(inputs.strong_accounts["SA-corp"]) == "svc-pw"
    warnings = sia_onboard.password_file_warnings({"corp.example.com": "x"}, inputs)
    assert len(warnings) == 1 and "carried as address by several strong accounts" in warnings[0]
    assert "corp.example.com (ADM-web02, ADM-web03, SA-corp)" in warnings[0] and "key those passwords by account name" in warnings[0]


def test_a_single_accounts_address_still_keys_its_password(tmp_path):
    (tmp_path / "servers.csv").write_text("fqdn,strong_account\nweb01.corp.example.com,SA-corp\n", encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text(
        "name,type,username,account_domain,address\nSA-corp,credentials,svc-sia,corp.example.com,corp.example.com\n",
        encoding="utf-8")
    inputs = load_inputs(tmp_path, principal_template="SIA-RDP")
    owners = inputs.address_owners()
    get = sia_onboard.make_password_source(False, {"CORP.example.com": "svc-pw"},
                                           shared_addresses={a for a, n in owners.items() if len(n) > 1})
    assert get(inputs.strong_accounts["SA-corp"]) == "svc-pw"
    assert sia_onboard.password_file_warnings({"CORP.example.com": "svc-pw"}, inputs) == []


def test_apply_never_stores_a_domain_keyed_password_in_per_host_accounts(workspace, monkeypatch, capsys, caplog):
    caplog.set_level(logging.WARNING)
    cfg = workspace / "config.toml"
    cfg.write_text(cfg.read_text().replace('strong_account_type = "vault"', 'strong_account_type = "credentials"')
                   .replace('strong_account_domain = "local"', 'strong_account_domain = "corp.example.com"'), encoding="utf-8")
    inp = workspace / "input"
    inp.mkdir()
    (inp / "servers.csv").write_text("fqdn\nweb02.corp.example.com\nweb03.corp.example.com\n", encoding="utf-8")
    pwfile = workspace / "passwords.csv"
    pwfile.write_text("name,password\ncorp.example.com,domain-pw\n", encoding="utf-8")
    pwfile.chmod(0o600)
    monkeypatch.setattr(sia_onboard, "interactive", lambda: False)
    sia = FakeSIA()
    shared_context(monkeypatch, sia=sia)
    assert run(workspace, "apply", "--accounts", "--yes", "--input", str(inp), "--passwords", str(pwfile),
               "--no-report", "--json") == 1
    data = json.loads(capsys.readouterr().out)
    assert [a["secret_status"] for a in data["accounts"]] == ["failed", "failed"]
    assert "its address 'corp.example.com' is shared with other accounts" in data["accounts"][0]["secret_detail"]
    assert not [c for c in sia.calls if c[0] == "create_secret"]
    assert any("carried as address by several strong accounts" in r.getMessage() for r in caplog.records)


def test_a_listed_server_fqdn_for_a_shared_account_gets_its_own_warning(tmp_path):
    (tmp_path / "servers.csv").write_text("fqdn,strong_account,domain_joined\nsrv01.example.com,LA-shared,no\n"
                                          "srv02.example.com,LA-shared,no\n", encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text("name,type,username\nLA-shared,credentials,Administrator\n", encoding="utf-8")
    inputs = load_inputs(tmp_path, accounts_only=True)
    assert inputs.strong_accounts["LA-shared"].address is None and inputs.shared_local_accounts == {"LA-shared"}
    warnings = sia_onboard.password_file_warnings({"srv02.example.com": "p", "stray": "q"}, inputs)
    assert warnings[0].startswith("password file key(s) name a listed server whose strong account no server FQDN selects")
    assert "srv02.example.com (LA-shared)" in warnings[0]
    assert warnings[1] == "password file lists 1 name(s) that match no strong account name or address: stray"


# ---------------------------------------------------------------- standalone rows that resolve to a domain account
def test_accounts_run_warns_when_a_row_resolves_to_the_domain_account(tmp_path):
    (tmp_path / "servers.csv").write_text("fqdn\nsrv01.example.com\nsrv02.example.com\n", encoding="utf-8")
    (tmp_path / "domains.csv").write_text("domain,strong_account\nexample.com,SA-DOMAIN\n", encoding="utf-8")
    inputs = load_inputs(tmp_path, strong_account_template=CREDS_SPEC, accounts_only=True)
    assert [s.strong_account for s in inputs.servers] == ["SA-DOMAIN", "SA-DOMAIN"]
    warning = next(w for w in inputs.warnings if "--accounts" in w)
    assert "srv01.example.com (servers.csv:2), srv02.example.com (servers.csv:3) not marked domain_joined = no" in warning
    assert "'SA-DOMAIN' (example.com)" in warning and "does not onboard a local administrator" in warning
    # The server run for a domain-joined server is the normal case: no warning.
    assert not load_inputs(tmp_path, strong_account_template=CREDS_SPEC, principal_template="SIA-RDP").warnings
    # Marked standalone, the same rows take their local administrators and nothing is said.
    (tmp_path / "servers.csv").write_text("fqdn,domain_joined\nsrv01.example.com,no\n", encoding="utf-8")
    inputs = load_inputs(tmp_path, strong_account_template=CREDS_SPEC, accounts_only=True)
    assert inputs.servers[0].strong_account == "ADM-srv01" and not inputs.warnings


def test_accounts_run_from_a_build_job_warns_without_workgroup(tmp_path):
    (tmp_path / "domains.csv").write_text("domain,strong_account\nexample.com,SA-DOMAIN\n", encoding="utf-8")
    inputs = inline_inputs(tmp_path, [{"fqdn": "srv09.example.com"}], strong_account_template=CREDS_SPEC, accounts_only=True)
    assert any(w.startswith("--accounts: srv09.example.com not marked domain_joined = no") for w in inputs.warnings)
    inputs = inline_inputs(tmp_path, [{"fqdn": "srv09.example.com", "domain_joined": "no"}],
                           strong_account_template=CREDS_SPEC, accounts_only=True)
    assert not inputs.warnings


@pytest.mark.parametrize("accounts_only", [False, True])
def test_a_workgroup_row_with_a_domain_account_is_flagged_in_both_modes(tmp_path, accounts_only):
    (tmp_path / "servers.csv").write_text("fqdn,domain_joined\nsrv01.example.com,no\n", encoding="utf-8")
    inputs = load_inputs(tmp_path, strong_account_template=DOMAIN_SPEC, accounts_only=accounts_only,
                         principal_template="SIA-RDP")
    assert any("domain_joined = no, but strong account 'ADM-srv01' is a domain account (corp.example.com)" in w
               for w in inputs.warnings)


def test_plan_accounts_shows_the_domain_account_warning(workspace, monkeypatch, capsys):
    inp, pwfile = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    (inp / "servers.csv").write_text("fqdn\nsrv01.example.com\n", encoding="utf-8")
    (inp / "domains.csv").write_text("domain,strong_account\nexample.com,SA-DOMAIN\n", encoding="utf-8")
    shared_context(monkeypatch, sia=FakeSIA(secrets=[{"secret_id": "d1", "secret_name": "SA-DOMAIN",
                                                      "secret_type": "ProvisionerUser", "is_active": True}]))
    assert run(workspace, "plan", "--accounts", "--input", str(inp), "--no-report", "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert [a["name"] for a in data["accounts"]] == ["SA-DOMAIN"]
    assert any("not marked domain_joined = no" in w for w in data["warnings"])


# ---------------------------------------------------------------- recovery advice that works with --accounts
def test_for_accounts_scope_rewrites_recovery_commands_once():
    diagnostic = Diagnostic(code="X", message="m", actions=(
        "Review the partial results and run plan --drift before apply --resume.",
        "Do not repeat the mutation; run `sia plan` to reconcile current tenant state.",
        "Run `sia plan --drift` and confirm the object identifier and requested state.",
        "Correct the reported cause."))
    rewritten = for_accounts_scope(diagnostic)
    assert rewritten.actions == (
        "Review the partial results and run `sia plan --accounts` before `sia apply --accounts`.",
        "Do not repeat the mutation; run `sia plan --accounts` to reconcile current tenant state.",
        "Run `sia plan --accounts` and confirm the object identifier and requested state.",
        "Correct the reported cause.")
    assert for_accounts_scope(rewritten) == rewritten


class _InterruptingSIA(FakeSIA):
    """The second strong-account create is interrupted after its request went out."""
    def create_secret(self, payload):
        if sum(1 for c in self.calls if c[0] == "create_secret") == 1:
            self.calls.append(("create_secret", payload))
            raise KeyboardInterrupt
        return super().create_secret(payload)


def test_interrupted_accounts_apply_advises_plan_accounts_and_counts_every_account():
    rows = replace(ACCOUNT_ROWS, servers=(*ACCOUNT_ROWS.servers, srv("srv03.example.com", "ADM-srv03", [], domain_joined=False)),
                   strong_accounts={**ACCOUNT_ROWS.strong_accounts,
                                    "ADM-srv03": sa("ADM-srv03", "credentials", username="Administrator",
                                                    address="srv03.example.com")})
    rec, _, _, _ = make(rows, sia=_InterruptingSIA(), accounts_only=True, passwords={**PASSWORDS, "ADM-srv03": "pw-3"})
    with pytest.raises(KeyboardInterrupt) as caught:
        rec.run()
    result = caught.value.partial_result
    assert [(a.name, a.secret.status) for a in result.accounts] == [("ADM-srv01", "created"), ("ADM-srv02", "uncertain"),
                                                                   ("ADM-srv03", "blocked")]
    data = result_dict(result)
    assert data["counts"] == {"blocked": 1, "created": 1, "uncertain": 1} and data["failures"] == 2
    codes = [d["code"] for d in data["diagnostics"]]
    assert codes[0] == "SIA-INTERRUPTED" and "SIA-BLOCKED" in codes and "SIA-UNCERTAIN" in codes
    actions = _actions(data["diagnostics"])
    assert any("`sia plan --accounts`" in a for a in actions)
    assert not any("--drift" in a or "--resume" in a or "`sia plan`" in a for a in actions)


def test_interrupted_read_only_run_says_nothing_was_changed():
    class StoppingPVWA(FakePVWA):
        def find_account(self, safe, name):
            raise KeyboardInterrupt

    rec, _, _, _ = make(_vault_rows(), dry_run=True, accounts_only=True, pvwa=StoppingPVWA(), passwords={})
    with pytest.raises(KeyboardInterrupt) as caught:
        rec.run()
    diagnostic = caught.value.partial_result.diagnostics[0]
    assert diagnostic["stage"] == "Reading tenant" and diagnostic["mutation_state"] == "not_applied"
    assert diagnostic["actions"] == ["Nothing was changed; run the command again when ready."]


def test_interrupted_accounts_apply_cli_json(workspace, monkeypatch, capsys):
    inp, pwfile = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    shared_context(monkeypatch, sia=_InterruptingSIA())
    assert run(workspace, "apply", "--accounts", "--yes", "--input", str(inp), "--passwords", str(pwfile),
               "--no-report", "--json") == 130
    data = json.loads(capsys.readouterr().out)
    assert data["scope"] == "accounts" and data["complete"] is False and data["interrupted"] is True
    actions = _actions(data["diagnostics"])
    assert actions and not any("--drift" in a or "--resume" in a for a in actions)
    assert any("`sia plan --accounts`" in a for a in actions)


def test_interrupted_server_verify_gives_read_only_advice(workspace, monkeypatch, capsys):
    from sia import reconcile

    def stop(self, result):
        raise KeyboardInterrupt

    monkeypatch.setattr(reconcile.Reconciler, "_ensure_policies", stop)
    shared_context(monkeypatch)
    assert run(workspace, "verify", "--input", str(sia_onboard.Path(__file__).resolve().parents[1] / "input"), "--json") == 130
    data = json.loads(capsys.readouterr().out)
    assert data["mode"] == "verify" and data["ok"] is False and data["exit_code"] == 130
    interrupted = next(d for d in data["diagnostics"] if d["code"] == "SIA-INTERRUPTED")
    assert interrupted["actions"] == ["Nothing was changed; run the command again when ready."]


# ---------------------------------------------------------------- shared local accounts and the --server path
def _shared_declared(tmp_path, kind="credentials"):
    (tmp_path / "servers.csv").write_text("fqdn,strong_account,domain_joined\nsrv01.example.com,ADM-shared,no\n"
                                          "srv02.example.com,ADM-shared,no\n", encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text(
        f"name,type,safe,account_name,username\nADM-shared,{kind},SIA-LocalAdmins,LocalAdmin,Administrator\n",
        encoding="utf-8")


def test_server_path_does_not_infer_an_address_servers_csv_shares(tmp_path):
    _shared_declared(tmp_path)
    row = {"fqdn": "srv02.example.com", "strong_account": "ADM-shared", "domain_joined": "no"}
    inputs = inline_inputs(tmp_path, [row], accounts_only=True)
    assert inputs.strong_accounts["ADM-shared"].address is None and inputs.shared_local_accounts == {"ADM-shared"}
    get = sia_onboard.make_password_source(False, {"srv02.example.com": "srv02-pw"})
    assert get(inputs.strong_accounts["ADM-shared"]) is None
    # Used by this one server in servers.csv too: inferred as before.
    (tmp_path / "servers.csv").write_text("fqdn,strong_account\nsrv02.example.com,ADM-shared\n", encoding="utf-8")
    inputs = inline_inputs(tmp_path, [row], accounts_only=True)
    assert inputs.strong_accounts["ADM-shared"].address == "srv02.example.com" and inputs.inferred_addresses == {"ADM-shared"}
    # An unreadable servers.csv gives no usage, so nothing is inferred from a partial view.
    (tmp_path / "servers.csv").write_text("fqdn,bogus\nsrv02.example.com,x\n", encoding="utf-8")
    assert inline_inputs(tmp_path, [row], accounts_only=True).strong_accounts["ADM-shared"].address is None


def test_shared_local_account_hint_and_report_address(tmp_path):
    _shared_declared(tmp_path)
    inputs = load_inputs(tmp_path, accounts_only=True)
    result = make(inputs, accounts_only=True, passwords={})[0].run()
    account = result.accounts[0]
    assert account.secret.status == "failed" and account.address == ""
    assert "it is shared by several servers, so no server FQDN selects it" in account.secret.detail


def test_shared_local_vault_account_is_not_onboarded_with_a_guessed_address(tmp_path):
    _shared_declared(tmp_path, kind="vault")
    inputs = load_inputs(tmp_path, accounts_only=True)
    pvwa = FakePVWA()
    result = make(inputs, accounts_only=True, pvwa=pvwa, passwords={"ADM-shared": "pw"})[0].run()
    vault = result.accounts[0].vault
    assert vault.status == "failed" and "Vault address is ambiguous: set address in strong_accounts.csv" in vault.detail
    assert result.accounts[0].secret.status == "blocked" and not [c for c in pvwa.calls if c[0] == "add_account"]
    # Once the operator names the machine, onboarding proceeds with that address in every wave.
    (tmp_path / "strong_accounts.csv").write_text(
        "name,type,safe,account_name,username,address\n"
        "ADM-shared,vault,SIA-LocalAdmins,LocalAdmin,Administrator,srv01.example.com\n", encoding="utf-8")
    inputs = load_inputs(tmp_path, accounts_only=True).window(1, 1)
    result = make(inputs, accounts_only=True, pvwa=pvwa, passwords={"ADM-shared": "pw"})[0].run()
    assert result.accounts[0].vault.status == "created" and pvwa.accounts[0]["address"] == "srv01.example.com"


def test_local_vault_accounts_sharing_one_vault_object_stop_the_run(tmp_path):
    (tmp_path / "servers.csv").write_text("fqdn,domain_joined\nsrv01.example.com,no\nsrv02.example.com,no\n", encoding="utf-8")
    spec = StrongAccountTemplate(name="ADM-{hostname}", type="vault", safe="SIA-LocalAdmins", account_name="Administrator",
                                 username="Administrator")
    with pytest.raises(InputError, match="strong accounts ADM-srv01, ADM-srv02 all reference Vault account 'Administrator' "
                                         "in safe 'SIA-LocalAdmins'.*one Vault account cannot hold them"):
        load_inputs(tmp_path, strong_account_template=spec, accounts_only=True)


def test_domain_vault_accounts_sharing_one_vault_object_only_warn(tmp_path):
    (tmp_path / "servers.csv").write_text("fqdn\nweb01.corp.example.com\nweb02.corp.example.com\n", encoding="utf-8")
    spec = StrongAccountTemplate(name="ADM-{hostname}", type="vault", safe="SIA-Domain", account_name="svc-sia",
                                 username="svc-sia", account_domain="corp.example.com")
    warnings = load_inputs(tmp_path, strong_account_template=spec, principal_template="SIA-RDP").warnings
    assert any(w.startswith("strong accounts ADM-web01, ADM-web02 all reference Vault account 'svc-sia'") for w in warnings)


# ---------------------------------------------------------------- 'local', checkpoints
def test_local_account_domain_is_sent_in_the_documented_spelling(tmp_path):
    """The input keeps the operator's spelling (so checkpoint fingerprints do not move); the payload says 'local'."""
    (tmp_path / "servers.csv").write_text("fqdn,strong_account,domain_joined\nsrv01.example.com,SA-1,no\n", encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text("name,type,username,account_domain\nSA-1,credentials,Administrator,LOCAL\n",
                                                  encoding="utf-8")
    account = load_inputs(tmp_path, accounts_only=True).strong_accounts["SA-1"]
    assert account.account_domain == "LOCAL" and account.is_local
    assert build_secret_payload(account, "pw")["secret_details"]["account_domain"] == "local"
    spec = replace(CREDS_SPEC, account_domain="Local")
    (tmp_path / "strong_accounts.csv").unlink()
    (tmp_path / "servers.csv").write_text("fqdn,domain_joined\nsrv01.example.com,no\n", encoding="utf-8")
    templated = load_inputs(tmp_path, strong_account_template=spec, accounts_only=True).strong_accounts["ADM-srv01"]
    assert build_secret_payload(templated, "pw")["secret_details"]["account_domain"] == "local"
    domain = replace(templated, account_domain="corp.example.com")
    assert build_secret_payload(domain, "pw")["secret_details"]["account_domain"] == "corp.example.com"


def test_an_inferred_address_does_not_invalidate_checkpoint_records(tmp_path):
    """Records written before the address was inferred (address None) still resume."""
    (tmp_path / "servers.csv").write_text("fqdn,strong_account,principal\nsrv01.example.com,SA-local,SIA-Web-Admins\n",
                                          encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text("name,type,username\nSA-local,credentials,Administrator\n", encoding="utf-8")
    inputs = load_inputs(tmp_path)
    assert inputs.inferred_addresses == {"SA-local"} and inputs.strong_accounts["SA-local"].address == "srv01.example.com"
    before = replace(inputs, strong_accounts={"SA-local": replace(inputs.strong_accounts["SA-local"], address=None)},
                     inferred_addresses=frozenset())
    checkpoint = Checkpoint(tmp_path / "cp.jsonl")
    passwords = {"SA-local": "pw"}
    assert make(before, checkpoint=checkpoint, passwords=passwords)[0].run().failures == 0
    resumed = make(inputs, checkpoint=Checkpoint(tmp_path / "cp.jsonl"), resume=True, passwords=passwords)[0].run()
    assert resumed.resumed == 1


# ---------------------------------------------------------------- why a Vault stage has no result
def _vault_rows():
    account = sa("ADM-srv01", "vault", safe="SIA-LocalAdmins", account_name="srv01-Administrator", username="Administrator",
                 address="srv01.example.com")
    return replace(ACCOUNT_ROWS, servers=ACCOUNT_ROWS.servers[:1], strong_accounts={"ADM-srv01": account})


@pytest.mark.parametrize("kwargs, detail", [
    (dict(only="secrets", pvwa_configured=True), "Vault stage not run (--only secrets)"),
    (dict(pvwa_configured=True), "Vault not checked by this command (verify --accounts checks it)"),
    (dict(pvwa_configured=False), "Vault stage off ([pvwa] not configured)"),
])
def test_vault_outcome_gives_the_real_reason(kwargs, detail):
    result = make(_vault_rows(), dry_run=True, accounts_only=True, passwords={}, **kwargs)[0].run()
    assert (result.accounts[0].vault.status, result.accounts[0].vault.detail) == ("n/a", detail)


def test_vault_stage_stopped_early_is_blocked_not_off():
    class StoppingPVWA(FakePVWA):
        def find_account(self, safe, name):
            raise KeyboardInterrupt

    rec, _, _, _ = make(_vault_rows(), accounts_only=True, pvwa=StoppingPVWA(), pvwa_configured=True, passwords={})
    with pytest.raises(KeyboardInterrupt) as caught:
        rec.run()
    account = caught.value.partial_result.accounts[0]
    assert account.vault.status == "blocked" and account.secret.status == "blocked"


def test_only_vault_warning_names_the_real_reason():
    result = make(ACCOUNT_ROWS, accounts_only=True, only="vault", passwords=PASSWORDS, pvwa_configured=True)[0].run()
    assert "no selected strong account is type=vault; the vault stage had nothing to do" in result.warnings
    result = make(_vault_rows(), accounts_only=True, only="vault", passwords=PASSWORDS, pvwa_configured=False)[0].run()
    assert "[pvwa] is not configured; the vault stage cannot run" in result.warnings


def test_plan_accounts_only_secrets_with_pvwa_configured(workspace, monkeypatch, capsys):
    cfg = workspace / "config.toml"
    cfg.write_text(cfg.read_text().replace('base_url = ""', 'base_url = "https://pvwa.example.com"'), encoding="utf-8")
    inp = workspace / "input"
    inp.mkdir()
    (inp / "servers.csv").write_text("fqdn,domain_joined\nsrv01.example.com,no\n", encoding="utf-8")
    FakeContext.pvwa = FakePVWA()
    shared_context(monkeypatch)
    assert run(workspace, "plan", "--accounts", "--only", "secrets", "--input", str(inp), "--no-report", "--json") == 0
    account = json.loads(capsys.readouterr().out)["accounts"][0]
    assert (account["vault_status"], account["vault_detail"]) == ("n/a", "Vault stage not run (--only secrets)")


# ---------------------------------------------------------------- capped tables keep what needs attention
def test_capped_account_table_never_hides_a_failure():
    result = RunResult(mode="apply", accounts_only=True)
    for i in range(12):
        status = "failed" if i >= 10 else "created"
        account = AccountResult(name=f"ADM-s{i:02}", type="credentials", sia_name=f"ADM-s{i:02}", username="Administrator",
                                address=f"s{i}.corp", vault=Outcome("n/a", "type=credentials"),
                                secret=Outcome(status, f"secret {status}"))
        result.accounts.append(account)
        result.secrets[account.name] = account.secret
    out = io.StringIO()
    print_summary(result, out, max_rows=5)
    text = out.getvalue()
    assert "ADM-s10" in text and "ADM-s11" in text and "ADM-s00" in text and "ADM-s03" not in text
    assert "7 more account(s) needing attention or with notes not shown" in text
    assert "ADM-s10: strong account failed" in text


# ---------------------------------------------------------------- doctor
def test_doctor_accounts_online_reports_server_run_checks_as_warnings(workspace, monkeypatch, capsys):
    class DeniedIdentity(FakeIdentity):
        def list_directories(self):
            raise SIAApiError("GET", "https://id/api", 403, "forbidden")

    cfg = workspace / "config.toml"
    cfg.write_text(cfg.read_text().replace('strong_account_type = "vault"', 'strong_account_type = "credentials"'), encoding="utf-8")
    inp = workspace / "input"
    inp.mkdir()
    (inp / "servers.csv").write_text("fqdn,domain_joined\nsrv01.example.com,no\n", encoding="utf-8")
    shared_context(monkeypatch, identity=DeniedIdentity())
    assert run(workspace, "doctor", "--accounts", "--online", "--input", str(inp), "--json") == 0
    identity = next(c for c in json.loads(capsys.readouterr().out)["checks"] if c["name"] == "Identity")
    assert identity["status"] == "warning" and identity["message"].startswith("not used by --accounts")
    assert run(workspace, "doctor", "--online", "--input", str(sia_onboard.Path(__file__).resolve().parents[1] / "input"),
               "--json") == 1


def test_result_diagnostics_use_accounts_commands_for_outcomes():
    result = RunResult(mode="apply", accounts_only=True)
    result.secrets["ADM-s1"] = Outcome("uncertain", "create sent")
    assert _actions(result_diagnostics(result)) == ["Do not repeat the mutation; run `sia plan --accounts` to reconcile "
                                                    "current tenant state."]


# ---------------------------------------------------------------- second review round
def test_server_run_never_keys_a_templated_domain_account_by_its_domain(tmp_path):
    """One --server run sees one per-host domain account, but every host of that domain carries the same address."""
    (tmp_path / "servers.csv").write_text("fqdn\nweb01.corp.example.com\nweb02.corp.example.com\n", encoding="utf-8")
    inputs = inline_inputs(tmp_path, [{"fqdn": "web02.corp.example.com"}], strong_account_template=DOMAIN_SPEC,
                           principal_template="SIA-RDP")
    assert inputs.address_owners() == {"corp.example.com": ("ADM-web02",)}
    assert inputs.shared_addresses() == {"corp.example.com"}
    get = sia_onboard.make_password_source(False, {"corp.example.com": "domain-pw"}, shared_addresses=inputs.shared_addresses())
    assert get(inputs.strong_accounts["ADM-web02"]) is None
    warnings = sia_onboard.password_file_warnings({"corp.example.com": "domain-pw"}, inputs)
    assert len(warnings) == 1 and "a templated domain account's AD domain" in warnings[0]
    result = make(inputs, passwords={})[0].run()
    assert "(its address 'corp.example.com' is shared with other accounts, so it keys no password)" in result.secrets["ADM-web02"].detail


def test_server_path_counts_servers_csv_rows_that_reach_an_account_through_domains_csv(tmp_path):
    (tmp_path / "servers.csv").write_text("fqdn\nsrv01.dmz.example.com\nsrv02.dmz.example.com\n"
                                          "lnx01.dmz.example.com,\n", encoding="utf-8")
    (tmp_path / "domains.csv").write_text("domain,strong_account\ndmz.example.com,SA-dmz\n", encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text("name,type,safe,account_name,username\nSA-dmz,vault,SIA-DMZ,dmz-admin,"
                                                  "Administrator\n", encoding="utf-8")
    inputs = inline_inputs(tmp_path, [{"fqdn": "srv02.dmz.example.com"}], principal_template="SIA-RDP")
    assert inputs.servers[0].strong_account == "SA-dmz" and inputs.strong_accounts["SA-dmz"].address is None
    assert inputs.shared_local_accounts == {"SA-dmz"}
    pvwa = FakePVWA()
    result = make(inputs, pvwa=pvwa, passwords={"SA-dmz": "pw"})[0].run()
    assert result.vault["SA-dmz"].status == "failed" and not [c for c in pvwa.calls if c[0] == "add_account"]


def test_server_path_with_an_unreadable_servers_csv_treats_declared_local_accounts_as_shared(tmp_path):
    (tmp_path / "servers.csv").write_text("fqdn,group\nsrv01.example.com,x\n", encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text("name,type,username\nLA,credentials,Administrator\n", encoding="utf-8")
    inputs = inline_inputs(tmp_path, [{"fqdn": "srv02.example.com", "strong_account": "LA", "domain_joined": "no"}],
                           accounts_only=True)
    assert inputs.strong_accounts["LA"].address is None and inputs.shared_local_accounts == {"LA"}
    assert any(w.startswith("servers.csv could not be read to see which servers share a declared account") for w in inputs.warnings)


def test_accounts_run_warns_for_a_local_account_taken_from_domains_csv(tmp_path):
    (tmp_path / "servers.csv").write_text("fqdn,policy_suffix\nsrv01.dmz.example.com,-a\nsrv01.dmz.example.com,-b\n"
                                          "srv02.dmz.example.com,\n", encoding="utf-8")
    (tmp_path / "domains.csv").write_text("domain,strong_account\ndmz.example.com,SA-dmz\n", encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text("name,type,username\nSA-dmz,credentials,Administrator\n", encoding="utf-8")
    inputs = load_inputs(tmp_path, strong_account_template=CREDS_SPEC, accounts_only=True)
    warning = next(w for w in inputs.warnings if w.startswith("--accounts:"))
    assert ("srv01.dmz.example.com (servers.csv:2), srv02.dmz.example.com (servers.csv:4) not marked domain_joined = no, "
            "so this run uses the domains.csv strong account 'SA-dmz' (local)") in warning


def test_verify_accounts_names_a_shared_local_account_without_an_empty_address(workspace, monkeypatch, capsys):
    cfg = workspace / "config.toml"
    cfg.write_text(cfg.read_text().replace('strong_account_type = "vault"', 'strong_account_type = "credentials"'), encoding="utf-8")
    inp = workspace / "input"
    inp.mkdir()
    (inp / "servers.csv").write_text("fqdn,strong_account,domain_joined\nsrv01.example.com,LA,no\nsrv02.example.com,LA,no\n",
                                     encoding="utf-8")
    (inp / "strong_accounts.csv").write_text("name,type,username\nLA,credentials,Administrator\n", encoding="utf-8")
    shared_context(monkeypatch)
    assert run(workspace, "verify", "--accounts", "--input", str(inp), "--json") == 1
    messages = [d["message"] for d in json.loads(capsys.readouterr().out)["diagnostics"] if d["code"] == "SIA-MISSING"]
    assert messages == ["Missing strong account LA (a local account shared by several servers)."]


def test_server_verify_with_pvwa_configured_says_the_vault_was_not_checked(workspace, monkeypatch, capsys):
    from pathlib import Path
    cfg = workspace / "config.toml"
    cfg.write_text(cfg.read_text().replace('base_url = ""', 'base_url = "https://pvwa.example.com"'), encoding="utf-8")
    shared_context(monkeypatch)
    run(workspace, "verify", "--input", str(Path(__file__).resolve().parents[1] / "input"), "--json")
    accounts = json.loads(capsys.readouterr().out)["accounts"]
    vault = [a["vault_detail"] for a in accounts if a["type"] == "vault"]
    assert vault and set(vault) == {"Vault not checked by this command (verify --accounts checks it)"}


def test_downgraded_doctor_check_is_not_the_last_problem(workspace, monkeypatch, capsys):
    class DeniedIdentity(FakeIdentity):
        def list_directories(self):
            raise SIAApiError("GET", "https://id/api", 403, "forbidden")

    class DeniedUAP(sia_onboard.UAPClient if False else object):
        calls = []

        def list_policies(self, *args, **kwargs):
            raise SIAApiError("GET", "https://uap/api", 403, "forbidden")

    cfg = workspace / "config.toml"
    cfg.write_text(cfg.read_text().replace('strong_account_type = "vault"', 'strong_account_type = "credentials"'), encoding="utf-8")
    inp = workspace / "input"
    inp.mkdir()
    (inp / "servers.csv").write_text("fqdn,domain_joined\nsrv01.example.com,no\n", encoding="utf-8")
    shared_context(monkeypatch, identity=DeniedIdentity(), uap=DeniedUAP())
    session = Session()
    args = sia_onboard.build_parser().parse_args(["--config", str(workspace / "config.toml"), "--env", str(workspace / ".env"),
                                                  "doctor", "--accounts", "--online", "--input", str(inp), "--json"])
    assert sia_onboard.execute(args, session) == 0
    checks = {c["name"]: c for c in json.loads(capsys.readouterr().out)["checks"]}
    assert checks["Policies"]["status"] == "warning" and checks["Identity"]["status"] == "warning"
    assert checks["Identity"]["diagnostic"]["severity"] == "warning" and session.last_diagnostics == []


@pytest.mark.parametrize("argv, expected", [(["plan", "--accounts"], True), (["plan", "--acc"], True), (["plan"], False)])
def test_last_scope_follows_the_parsed_accounts_flag(workspace, monkeypatch, argv, expected):
    inp, _ = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    shared_context(monkeypatch)
    session = Session(last_scope_accounts=not expected)
    args = sia_onboard.build_parser().parse_args(["--config", str(workspace / "config.toml"), "--env", str(workspace / ".env"),
                                                  "--report-dir", str(workspace / "reports"), *argv, "--input", str(inp),
                                                  "--no-report"])
    sia_onboard.execute(args, session)
    assert session.last_scope_accounts is expected


def test_guided_doctor_offers_accounts_after_an_accounts_run(monkeypatch):
    from sia import terminal
    answers = ["/doctor", "", "no"]          # Enter accepts the --accounts default, then no tenant checks
    prompts = []

    def ask(prompt, default=None, **_):
        prompts.append(prompt)
        if not answers:
            raise EOFError                       # the home loop ends the session on EOF
        answer = answers.pop(0)
        return answer if answer else (default or "")

    monkeypatch.setattr(terminal, "ask", ask)
    ran = []
    args = type("A", (), {"input": "input", "verbose": False, "config": "config.toml", "env": ".env"})()
    terminal.home(args, Session(last_scope_accounts=True), lambda argv: ran.append(argv) or 0)
    assert ran == [["doctor", "--input", "input", "--accounts"]]
    assert "Check the input for a strong-accounts-only run (--accounts)?" in prompts


def test_help_accounts_topic_carries_the_corrected_guidance():
    text = help_text("accounts")
    for phrase in ("domain_joined = no", "--adopt-all", "plan --accounts", "445", "doctor --accounts"):
        assert phrase in text, phrase
    assert "WinRM (TCP 5985/5986)" not in text


def test_verify_help_describes_a_read_only_check(capsys):
    with pytest.raises(SystemExit):
        sia_onboard.build_parser().parse_args(["verify", "--help"])
    assert "check only the strong accounts of the listed servers" in capsys.readouterr().out


def test_for_accounts_scope_covers_plan_again_and_doctor():
    rewritten = for_accounts_scope(Diagnostic(code="X", message="m", actions=(
        "Run plan again before applying changes.", "Correct it, then run `sia doctor --online`.", "Run `sia doctor` again.")))
    assert rewritten.actions == ("Run `sia plan --accounts` again before applying changes.",
                                 "Correct it, then run `sia doctor --accounts --online`.", "Run `sia doctor --accounts` again.")
    assert for_accounts_scope(rewritten) == rewritten
