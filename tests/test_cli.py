import csv
import json
from pathlib import Path

import pytest

import sia_onboard
from sia.config import load_config
from sia.http import SIAApiError
from sia.inputs import StrongAccountRow
from sia.redact import register_secret
from tests.fakes import FakeIdentity, FakePVWA, FakeSIA, FakeUAP, group_row

ROOT = Path(__file__).resolve().parents[1]
POLICY_NAMES = ["web01.corp.example.com", "web01.corp.example.com-ops", "web02.corp.example.com", "SIA-RDP-dmz-app01-custom",
                "fs01.corp.example.com", "app-lnx01.corp.example.com"]
SECRET_NAMES = {"web01-Administrator_SIA-LocalAdmins", "web02-Administrator_SIA-LocalAdmins", "SA-dmz-localadmin",
                "svc_sia_rdp_SIA-StrongAccounts"}


class FakeToken:
    def __call__(self, force=False):
        return "eyJhbGciOiJSUzI1NiJ9.eyJzdWJkb21haW4iOiJhY21lIiwidW5pcXVlX25hbWUiOiJzdmNAYWNtZSJ9.sig"

    claims = {"subdomain": "acme", "unique_name": "svc@acme"}


class FakeContext:
    instances: list = []
    pvwa: FakePVWA | None = None

    def __init__(self, cfg):
        self.cfg = cfg
        self.token = FakeToken()
        self.client_id = "svc@acme.cyberark.cloud"
        self.limiter = None
        self.sia, self.uap, self.identity = FakeSIA(), FakeUAP(), FakeIdentity()
        FakeContext.instances.append(self)

    def pvwa_client(self):
        return self.pvwa


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text((ROOT / "config.example.toml").read_text(), encoding="utf-8")
    env = tmp_path / ".env"
    env.write_text("SIA_CLIENT_ID=svc@acme.cyberark.cloud\nSIA_CLIENT_SECRET=pw\nSIA_SA_DMZ_LOCALADMIN_PASSWORD=pw2\n", encoding="utf-8")
    env.chmod(0o600)
    monkeypatch.setattr(sia_onboard, "Context", FakeContext)
    FakeContext.instances.clear()
    FakeContext.pvwa = None
    return tmp_path


def run(workspace, *args):
    return sia_onboard.main(["--config", str(workspace / "config.toml"), "--env", str(workspace / ".env"),
                             "--report-dir", str(workspace / "reports"), *args])


def shared_context(monkeypatch, **fakes):
    class Ctx(FakeContext):
        def __init__(self, cfg):
            super().__init__(cfg)
            for name, fake in fakes.items():
                setattr(self, name, fake)

    monkeypatch.setattr(sia_onboard, "Context", Ctx)


def cp(workspace) -> str:
    return str(workspace / "checkpoint.jsonl")


def test_plan_writes_reports_and_changes_nothing(workspace, capsys):
    code = run(workspace, "plan", "--input", str(ROOT / "input"))
    out = capsys.readouterr().out
    assert code == 0 and "PLAN (dry run" in out and "would create" in out and "Lookup mode: search" in out
    ctx = FakeContext.instances[-1]
    assert not ctx.sia.secrets and not ctx.uap.policies
    reports = sorted((workspace / "reports").iterdir())
    assert [p.suffix for p in reports] == [".csv", ".json"]
    data = json.loads(reports[1].read_text())
    assert data["mode"] == "plan" and data["rows"] == 6 and len(data["servers"]) == 6 and data["failures"] == 0 and data["aborted"] == []
    assert [s["policy_name"] for s in data["servers"]] == POLICY_NAMES
    assert not (ROOT / "input" / ".sia-checkpoint.jsonl").exists()


def test_apply_yes_creates_and_second_apply_is_noop(workspace, capsys, monkeypatch):
    sia, uap = FakeSIA(), FakeUAP()
    shared_context(monkeypatch, sia=sia, uap=uap)
    assert run(workspace, "apply", "--yes", "--input", str(ROOT / "input"), "--checkpoint", cp(workspace)) == 0
    out = capsys.readouterr().out
    assert "== APPLY ==" in out and "created=14" in out and "n/a=1" in out and "Checkpoint:" in out
    assert {s["secret_name"] for s in sia.secrets} == SECRET_NAMES
    assert [p["metadata"]["name"] for p in uap.policies] == POLICY_NAMES
    assert uap.policies[5]["behavior"] == {"connectAs": {"ssh": {"username": "ec2-user"}}}
    assert uap.policies[1]["behavior"]["connectAs"]["rdp"]["localEphemeralUser"]["assignGroups"] == ["Remote Desktop Users"]
    assert [t["name"] for t in sia.target_sets] == ["web01.corp.example.com", "web02.corp.example.com", "dmz-app01.dmz.example.com", "fs01.corp.example.com"]
    assert run(workspace, "apply", "--yes", "--input", str(ROOT / "input"), "--checkpoint", cp(workspace)) == 0
    out2 = capsys.readouterr().out
    assert "exists=14" in out2 and "created" not in out2.split("Summary:")[1]
    assert len(uap.policies) == 6 and len(sia.secrets) == 4
    # --resume skips every finished row without reading the tenant again
    reads = (len(sia.calls), len(uap.calls))
    assert run(workspace, "apply", "--yes", "--resume", "--input", str(ROOT / "input"), "--checkpoint", cp(workspace)) == 0
    out3 = capsys.readouterr().out
    assert "Resumed from checkpoint: 6 row(s)" in out3 and "exists=10" in out3   # 4 target sets + 6 policies; accounts of resumed rows are not re-read
    assert len(sia.calls) == reads[0] and len(uap.calls) == reads[1]


def test_apply_flags_accepted(workspace, capsys):
    code = run(workspace, "plan", "--input", str(ROOT / "input"), "--update", "--drift", "--adopt", "web01.corp.example.com",
               "--adopt", "web02.corp.example.com", "--adopt-all", "--keep-going", "--workers", "4", "--lookup", "list",
               "--progress-every", "1", "--resume", "--checkpoint", cp(workspace))
    assert code == 0 and "PLAN" in capsys.readouterr().out
    assert run(workspace, "plan", "--input", str(ROOT / "input"), "--workers", "99") == 2
    assert "--workers must be between" in capsys.readouterr().err
    # --only policies on an empty tenant: target sets are blocked (no strong accounts) -> exit 1 with the reason shown
    code = run(workspace, "plan", "--input", str(ROOT / "input"), "--only", "policies")
    out = capsys.readouterr().out
    assert code == 1 and "blocked" in out and "strong account" in out


def test_offset_and_limit_select_a_wave(workspace, capsys):
    assert run(workspace, "plan", "--input", str(ROOT / "input"), "--offset", "1", "--limit", "2") == 0
    capsys.readouterr()
    data = json.loads(sorted((workspace / "reports").glob("plan-*.json"))[-1].read_text())
    assert [s["fqdn"] for s in data["servers"]] == ["web02.corp.example.com", "dmz-app01.dmz.example.com"]
    assert run(workspace, "plan", "--input", str(ROOT / "input"), "--offset", "-1") == 2


def test_verify_reports_missing_then_pass(workspace, capsys, monkeypatch):
    sia, uap = FakeSIA(), FakeUAP()
    shared_context(monkeypatch, sia=sia, uap=uap)
    out_csv = workspace / "verify.csv"
    assert run(workspace, "verify", "--input", str(ROOT / "input"), "--out", str(out_csv)) == 1
    out = capsys.readouterr().out
    assert "== VERIFY ==" in out and "MISSING=6" in out and "PASS" not in out.split("Verify:")[1]
    rows = list(csv.DictReader(out_csv.open()))
    assert rows[0]["verdict"] == "MISSING" and rows[0]["policy_name"] == "web01.corp.example.com" and len(rows) == 6
    assert run(workspace, "apply", "--yes", "--input", str(ROOT / "input"), "--checkpoint", cp(workspace)) == 0
    capsys.readouterr()
    assert run(workspace, "verify", "--input", str(ROOT / "input"), "--drift", "--workers", "2") == 0
    assert "PASS=6" in capsys.readouterr().out
    uap.policies[2]["metadata"]["status"] = {"status": "Suspended"}
    assert run(workspace, "verify", "--input", str(ROOT / "input")) == 1
    out = capsys.readouterr().out
    assert "FAIL=1" in out and "status=Suspended" in out


def test_connect_info_exports_user_names_and_rdp_files(workspace, capsys):
    out_csv = workspace / "connect.csv"
    rdp_dir = workspace / "rdp"
    assert run(workspace, "connect-info", "--input", str(ROOT / "input"), "--no-tenant", "--out", str(out_csv), "--rdp-dir", str(rdp_dir)) == 0
    out = capsys.readouterr().out
    assert "6 row(s) for 5 server(s)" in out and "RDP gateway: acme.rdp.cyberark.cloud" in out and "5 .rdp file(s)" in out
    rows = list(csv.DictReader(out_csv.open()))
    assert [r["policy_name"] for r in rows] == POLICY_NAMES
    assert rows[0]["rdp_username"] == "secureaccess /i <user>@acme.cyberark.cloud /s acme /a web01.corp.example.com"
    assert rows[0]["gateway_host"] == "acme.rdp.cyberark.cloud" and rows[0]["portal_url"] == "https://acme.cyberark.cloud/dpa"
    assert rows[3]["rdp_username"].endswith("/a dmz-app01.dmz.example.com /d local")
    assert rows[5]["rdp_username"] == "" and rows[5]["rdp_file"] == "" and rows[0]["policy_status"] == ""
    files = sorted(p.name for p in rdp_dir.iterdir())
    assert files == ["dmz-app01.rdp", "fs01.rdp", "web01-web01.corp.example.com-ops.rdp", "web01-web01.corp.example.com.rdp", "web02.rdp"]
    text = (rdp_dir / "web02.rdp").read_bytes().decode()
    assert "full address:s:web02.corp.example.com\r\n" in text and "gatewayhostname:s:acme.rdp.cyberark.cloud\r\n" in text
    assert "username:s:secureaccess /i <user>@acme.cyberark.cloud /s acme /a web02.corp.example.com\r\n" in text
    # with the tenant: status columns are filled from a dry run; --login-user and --network are honoured
    assert run(workspace, "connect-info", "--input", str(ROOT / "input"), "--out", str(out_csv), "--login-user", "alice", "--network", "dc1") == 0
    out = capsys.readouterr().out
    rows = list(csv.DictReader(out_csv.open()))
    assert rows[0]["policy_status"] == "planned" and rows[0]["rdp_username"] == "secureaccess /i alice@acme.cyberark.cloud /s acme /a web01.corp.example.com /n dc1"
    assert "not fully onboarded yet" in out


def test_apply_prompt_abort(workspace, capsys, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    code = run(workspace, "apply", "--input", str(ROOT / "input"), "--checkpoint", cp(workspace))
    assert code == 2 and "Aborted" in capsys.readouterr().out
    assert not FakeContext.instances[-1].uap.policies


def test_apply_without_tty_aborts_cleanly(workspace, capsys, monkeypatch):
    def no_tty(prompt=""):
        raise EOFError
    monkeypatch.setattr("builtins.input", no_tty)
    code = run(workspace, "apply", "--input", str(ROOT / "input"), "--checkpoint", cp(workspace))
    out = capsys.readouterr().out
    assert code == 2 and "use --yes" in out and "Aborted" in out


def test_missing_config_is_usage_error(tmp_path, capsys):
    code = sia_onboard.main(["--config", str(tmp_path / "nope.toml"), "--env", str(tmp_path / ".env"), "preflight"])
    assert code == 2 and "config file not found" in capsys.readouterr().err


def test_bad_input_is_usage_error(workspace, capsys, tmp_path):
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "servers.csv").write_text("fqdn,strong_account,group\nnot-an-fqdn,SA,G\n", encoding="utf-8")
    (bad / "strong_accounts.csv").write_text("name,type\nSA,existing\n", encoding="utf-8")
    code = run(workspace, "plan", "--input", str(bad))
    assert code == 2 and "not a valid FQDN" in capsys.readouterr().err


def test_preflight_ok(workspace, capsys):
    assert run(workspace, "preflight") == 0
    out = capsys.readouterr().out
    assert "Auth:     OK platform token" in out and "self_hosted_pam=configured" in out
    assert "SIA API:  OK  secrets=public targetsets=legacy (unfiltered listing OK)" in out
    assert "Identity: OK  2 directories (auth=platform_token)" in out and "PVWA:     not configured" in out and "Preflight OK" in out


def test_preflight_settings_forbidden_is_soft_and_pam_incomplete_is_reported(workspace, capsys, monkeypatch):
    sia = FakeSIA()
    sia.raise_on_settings = SIAApiError("GET", "https://acme.dpa.cyberark.cloud/api/settings", 403, "forbidden")
    shared_context(monkeypatch, sia=sia)
    assert run(workspace, "preflight") == 0
    out = capsys.readouterr().out
    assert "Settings: not verified (HTTP 403" in out and "Preflight OK" in out
    sia = FakeSIA()
    sia.settings = {"self_hosted_pam": {"tenant_type": "PCLOUD", "pvwa_base_url": "https://pvwa"}}
    shared_context(monkeypatch, sia=sia)
    assert run(workspace, "preflight") == 0
    out = capsys.readouterr().out
    assert "self_hosted_pam=incomplete" in out and "missing connector_pool_id, service_user_secret_id" in out and "expected tenant_type=SELF_HOSTED" in out
    sia = FakeSIA()
    sia.raise_on_settings = SIAApiError("GET", "https://acme.dpa.cyberark.cloud/api/settings", 500, "boom")
    shared_context(monkeypatch, sia=sia)
    assert run(workspace, "preflight") == 1
    assert "Settings: FAILED" in capsys.readouterr().out


def test_preflight_target_sets_need_account_is_soft(workspace, capsys, monkeypatch):
    sia = FakeSIA()
    sia.capabilities.targetsets_list_unfiltered = False
    shared_context(monkeypatch, sia=sia)
    assert run(workspace, "preflight") == 0
    assert "per-account listing will be used" in capsys.readouterr().out


def test_preflight_identity_rejection_explains_permission_and_context(workspace, capsys, monkeypatch):
    class Ident(FakeIdentity):
        def list_directories(self):
            raise SIAApiError("GET", "https://abc.id.cyberark.cloud/Core/GetDirectoryServices", 403, "denied")
    shared_context(monkeypatch, identity=Ident())
    assert run(workspace, "preflight") == 1
    out = capsys.readouterr().out
    assert "Identity: FAILED" in out and "SIA-PERMISSION" in out and "What to do next" in out


def test_show_policy(workspace, capsys, monkeypatch):
    assert run(workspace, "show-policy", "Nope") == 1
    shared_context(monkeypatch, uap=FakeUAP([{"metadata": {"name": "Ref", "policyId": "p1"}, "targets": {"FQDN/IP": {}}}]))
    capsys.readouterr()
    assert run(workspace, "show-policy", "Ref") == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["metadata"]["policyId"] == "p1" and "targets" in printed
    uap = FakeUAP([{"metadata": {"name": "Ref", "policyId": "p1"}, "targets": {"FQDN/IP": {}}}])
    uap.partial_list = True
    shared_context(monkeypatch, uap=uap)
    assert run(workspace, "show-policy", "Ref", "--from-list") == 0
    printed = json.loads(capsys.readouterr().out)
    assert "targets" not in printed and not [c for c in uap.calls if c[0] == "get_policy"]


def test_vault_stage_runs_when_pvwa_configured(workspace, capsys, monkeypatch):
    text = (workspace / "config.toml").read_text().replace('base_url = ""             # e.g. "https://pvwa.corp.example.com"',
                                                             'base_url = "https://pvwa.corp.example.com"')
    (workspace / "config.toml").write_text(text)
    pvwa = FakePVWA()
    FakeContext.pvwa = pvwa
    pwfile = workspace / "passwords.csv"
    pwfile.write_text("name,password\nADM-web01,pw-web01\nADM-web02,pw-web02\nSA-corp-domain,pw-svc\n", encoding="utf-8")
    pwfile.chmod(0o600)
    assert run(workspace, "apply", "--yes", "--input", str(ROOT / "input"), "--checkpoint", cp(workspace), "--passwords", str(pwfile)) == 0
    out = capsys.readouterr().out
    assert "Vault accounts:" in out and "onboarded Vault account 'web01-Administrator'" in out
    added = [c[1] for c in pvwa.calls if c[0] == "add_account"]
    assert sorted(a["name"] for a in added) == ["svc_sia_rdp", "web01-Administrator", "web02-Administrator"]
    by_name = {a["name"]: a for a in added}
    assert by_name["web01-Administrator"]["address"] == "web01.corp.example.com" and by_name["svc_sia_rdp"]["address"] == "corp.example.com"
    assert pvwa.logged_off and "pw-web01" not in out


def test_unexpected_errors_are_redacted(workspace, capsys, monkeypatch):
    class Boom(FakeContext):
        def __init__(self, cfg):
            register_secret("very-secret-token")
            raise RuntimeError("token very-secret-token leaked")
    monkeypatch.setattr(sia_onboard, "Context", Boom)
    assert run(workspace, "preflight") == 1
    err = capsys.readouterr().err
    assert "SIA-UNKNOWN" in err and "very-secret-token" not in err and "***" in err


def test_real_context_requires_credentials(monkeypatch):
    monkeypatch.setattr(sia_onboard, "interactive", lambda: False)
    monkeypatch.delenv("SIA_CLIENT_ID", raising=False)
    monkeypatch.delenv("SIA_CLIENT_SECRET", raising=False)
    cfg = load_config(ROOT / "config.example.toml")
    with pytest.raises(Exception, match="SIA_CLIENT_ID"):
        sia_onboard.Context(cfg)
    monkeypatch.setenv("SIA_CLIENT_ID", "svc@acme")
    with pytest.raises(Exception, match="SIA_CLIENT_SECRET"):
        sia_onboard.Context(cfg)


def test_real_context_builds_oidc_adapter_and_limiter(monkeypatch, tmp_path):
    monkeypatch.setenv("SIA_CLIENT_ID", "svc@acme")
    monkeypatch.setenv("SIA_CLIENT_SECRET", "pw-1234")
    text = (ROOT / "config.example.toml").read_text().replace('identity_auth = "platform_token"', 'identity_auth = "service_user_oidc"')
    text = text.replace("max_requests_per_second = 0 ", "max_requests_per_second = 5 ")
    (tmp_path / "c.toml").write_text(text)
    ctx = sia_onboard.Context(load_config(tmp_path / "c.toml"))
    assert ctx.identity_token is not ctx.token and ctx.identity_token.name == "service_user_oidc"
    assert ctx.limiter is not None and ctx.limiter.enabled and ctx.client_id == "svc@acme"
    assert ctx.pvwa_client() is None
    ctx2 = sia_onboard.Context(load_config(ROOT / "config.example.toml"))
    assert ctx2.identity_token is ctx2.token and ctx2.limiter is None


def account(name, env):
    return StrongAccountRow(name=name, type="credentials", safe=None, account_name=None, username="adm",
                            account_domain="local", password_env=env, line=1)


def test_password_source_env_then_file_then_prompt(monkeypatch, capsys):
    monkeypatch.setenv("SIA_SA_X_PASSWORD", "from-env")
    for var in ("SIA_SA_Y_PASSWORD", "SIA_SA_Z_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(sia_onboard, "interactive", lambda: True)
    prompts = []
    monkeypatch.setattr("getpass.getpass", lambda prompt: prompts.append(prompt) or "typed-pw")
    get = sia_onboard.make_password_source(allow_prompt=True, file_passwords={"Y": "from-file"}, max_prompts=2)
    assert get(account("X", "SIA_SA_X_PASSWORD")) == "from-env"
    assert get(account("Y", "SIA_SA_Y_PASSWORD")) == "from-file"
    assert get(account("Z", "SIA_SA_Z_PASSWORD")) == "typed-pw" and get(account("Z", "SIA_SA_Z_PASSWORD")) == "typed-pw" and len(prompts) == 1
    assert get(account("W", "SIA_SA_W_PASSWORD")) == "typed-pw" and len(prompts) == 2
    assert get(account("V", "SIA_SA_V_PASSWORD")) is None and len(prompts) == 2      # prompt budget exhausted
    assert "More than 2 passwords are missing" in capsys.readouterr().err
    assert sia_onboard.make_password_source(allow_prompt=False)(account("Z", "SIA_SA_Z_PASSWORD")) is None
    vault = StrongAccountRow(name="ADM-w", type="vault", safe="S", account_name="a", username="u", account_domain="local", password_env=None, line=0)
    assert sia_onboard.make_password_source(allow_prompt=False, file_passwords={"ADM-w": "file-pw"})(vault) == "file-pw"


def test_password_file_flag_feeds_credentials_accounts(workspace, capsys, monkeypatch):
    monkeypatch.delenv("SIA_SA_DMZ_LOCALADMIN_PASSWORD", raising=False)
    (workspace / ".env").write_text("SIA_CLIENT_ID=svc@acme.cyberark.cloud\nSIA_CLIENT_SECRET=pw\n", encoding="utf-8")
    pwfile = workspace / "passwords.csv"
    pwfile.write_text("name,password\nSA-dmz-localadmin,file-pw-123\nSA-unknown,x\n", encoding="utf-8")
    pwfile.chmod(0o600)
    sia = FakeSIA()
    shared_context(monkeypatch, sia=sia)
    assert run(workspace, "apply", "--yes", "--input", str(ROOT / "input"), "--passwords", str(pwfile), "--checkpoint", cp(workspace)) == 0
    created = next(c[1] for c in sia.calls if c[0] == "create_secret" and c[1]["secret_type"] == "ProvisionerUser")
    assert created["secret"]["secret_data"]["password"] == "file-pw-123"
    out = capsys.readouterr().out
    assert "file-pw-123" not in out


# ---------------------------------------------------------------- scripted callers (Ansible)

def _domain_workspace(workspace):
    """A tenant + input directory shaped like the client's: group and strong account derived per domain."""
    cfg = workspace / "config.toml"
    cfg.write_text(cfg.read_text()
                   .replace('group_template = ""', 'group_template = "SIA-{hostname_upper}-RDP"')
                   .replace('target_set_scope = "server"', 'target_set_scope = "auto"'), encoding="utf-8")
    inp = workspace / "input"
    inp.mkdir()
    (inp / "servers.csv").write_text("fqdn\n", encoding="utf-8")
    (inp / "domains.csv").write_text("domain,strong_account,target_set,target_set_type,group_template\n"
                                     "corp.example.com,SA-CORP-SIA,,Domain,\n", encoding="utf-8")
    return inp


def test_apply_single_server_json(workspace, monkeypatch, capsys):
    """The Ansible path: one server, no servers.csv row, machine-readable result on stdout."""
    inp = _domain_workspace(workspace)
    sia = FakeSIA([{"secret_id": "sec-corp", "secret_name": "SA-CORP-SIA", "secret_type": "PCloudAccount"}])
    shared_context(monkeypatch, sia=sia, identity=FakeIdentity([group_row("SIA-WEB09-RDP")]))
    code = run(workspace, "apply", "--input", str(inp), "--server", "web09.corp.example.com", "--yes", "--json",
               "--no-report", "--checkpoint", str(workspace / "ckpt.jsonl"))
    out = capsys.readouterr()
    assert code == 0
    data = json.loads(out.out)                       # stdout is JSON only; the table went to stderr
    assert "Servers:" in out.err
    row = data["servers"][0]
    assert row["fqdn"] == "web09.corp.example.com" and row["target_set_name"] == "corp.example.com"
    assert row["strong_account"] == "SA-CORP-SIA" and row["policy"]["status"] == "created"
    assert data["failures"] == 0
    created = [ts for c in sia.calls if c[0] == "bulk_create_target_sets" for i in c[1] for ts in i["target_sets"]]
    assert [(ts["name"], ts["type"]) for ts in created] == [("corp.example.com", "Domain")]
    assert not (workspace / "reports").exists()      # --no-report


def test_single_server_group_override_and_bad_fqdn(workspace, monkeypatch, capsys):
    inp = _domain_workspace(workspace)
    sia = FakeSIA([{"secret_id": "sec-corp", "secret_name": "SA-CORP-SIA", "secret_type": "PCloudAccount"}])
    shared_context(monkeypatch, sia=sia, identity=FakeIdentity([group_row("Typed-In")]))
    assert run(workspace, "plan", "--input", str(inp), "--server", "web09.corp.example.com", "--group", "Typed-In") == 0
    out = capsys.readouterr().out
    assert "Typed-In" in out and "shared by every server in corp.example.com" in out
    assert run(workspace, "plan", "--input", str(inp), "--server", "not-an-fqdn") == 2
    assert "--server not-an-fqdn" in capsys.readouterr().err


def test_ca_bundle_flag_reaches_the_context(workspace, monkeypatch, capsys):
    bundle = workspace / "corp-ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    shared_context(monkeypatch)
    assert run(workspace, "--ca-bundle", str(bundle), "preflight") == 0
    assert FakeContext.instances[-1].cfg.http.tls_verify == str(bundle)
    assert f"CA bundle {bundle}" in capsys.readouterr().out
    assert run(workspace, "--ca-bundle", str(workspace / "missing.pem"), "preflight") == 2
    assert "does not exist" in capsys.readouterr().err


def test_apply_json_stdout_stays_parseable_without_yes(workspace, monkeypatch, capsys):
    """The confirmation prompt must not land on stdout: --json promises a parseable document there."""
    inp = _domain_workspace(workspace)
    sia = FakeSIA([{"secret_id": "sec-corp", "secret_name": "SA-CORP-SIA", "secret_type": "PCloudAccount"}])
    shared_context(monkeypatch, sia=sia, identity=FakeIdentity([group_row("SIA-WEB09-RDP")]))
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    code = run(workspace, "apply", "--input", str(inp), "--server", "web09.corp.example.com", "--json", "--no-report")
    out = capsys.readouterr()
    data = json.loads(out.out)
    assert code == 2 and data["cancelled"] and data["diagnostics"][0]["mutation_state"] == "not_applied"
    assert "Type 'yes' to apply these changes:" in out.err and "Aborted; nothing changed." in out.err
    assert [c[0] for c in sia.calls if c[0] == "bulk_create_target_sets"] == []


def test_server_only_flags_without_server_are_rejected(workspace, monkeypatch, capsys):
    """--group without --server used to be a silent no-op on a command that writes."""
    inp = _domain_workspace(workspace)
    (inp / "servers.csv").write_text("fqdn\nweb01.corp.example.com\n", encoding="utf-8")
    shared_context(monkeypatch)
    assert run(workspace, "apply", "--input", str(inp), "--group", "SIA-Emergency-Access", "--yes") == 2
    assert "--group only apply together with --server" in capsys.readouterr().err
