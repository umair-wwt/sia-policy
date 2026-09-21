import csv
import json
import logging
from pathlib import Path

import pytest

import sia_onboard
from sia.config import load_config
from sia.http import SIAApiError
from sia.inputs import StrongAccountRow
from sia.redact import register_secret
from tests.fakes import FakeIdentity, FakePVWA, FakeSIA, FakeUAP, group_row, role_row

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
    (bad / "servers.csv").write_text("fqdn,strong_account,principal\nnot-an-fqdn,SA,G\n", encoding="utf-8")
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


def test_show_policy_save_writes_a_scrubbed_fixture(workspace, capsys, monkeypatch, tmp_path):
    policy = {"metadata": {"name": "Ref", "policyId": "p1", "description": "R&D", "policyTags": ["automated"],
                           "createdBy": {"user": "someone@corp", "time": "2025-05-01T10:00:00Z"}},
              "principals": [{"id": "abc-123", "name": "Corp Admins", "type": "GROUP", "sourceDirectoryId": "D-1",
                              "sourceDirectoryName": "corp.example.com"}],
              "targets": {"FQDN/IP": {"fqdnRules": [{"operator": "EXACTLY", "computernamePattern": "web01.corp.example.com",
                                                     "domain": "corp.example.com"}],
                                      "ipRules": [{"operator": "IN_RANGE", "ipAddresses": ["10.20.30.0/24"]}]}},
              "conditions": {"idleTime": 10, "overrideIdleTime": True, "someFutureField": {"x": 1}},
              "behavior": {"connectAs": {"rdp": {"localEphemeralUser": {"assignGroups": ["CORP\\Server Admins"]}}}}}
    shared_context(monkeypatch, uap=FakeUAP([policy]))
    target = tmp_path / "fixtures" / "acme.json"
    assert run(workspace, "show-policy", "Ref", "--save", str(target)) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["metadata"]["name"] == "Ref"                                   # stdout is still the raw policy
    saved = json.loads(target.read_text(encoding="utf-8"))
    assert saved["metadata"]["name"] == "fixture-policy" and saved["metadata"]["policyTags"] == ["automated"]
    assert saved["metadata"]["createdBy"] == {"user": "fixture-user", "time": "2026-01-01T00:00:00Z"}
    principal = saved["principals"][0]
    assert principal == {"id": "principal-1", "name": "fixture-principal-1", "type": "GROUP",
                         "sourceDirectoryId": "directory-1", "sourceDirectoryName": "fixture-directory"}
    rules = saved["targets"]["FQDN/IP"]
    assert rules["fqdnRules"][0] == {"operator": "EXACTLY", "computernamePattern": "host1.fixture.example.com",
                                     "domain": "fixture.example.com"}
    assert rules["ipRules"][0] == {"operator": "IN_RANGE", "ipAddresses": ["10.0.1.0/24"]}
    assert saved["conditions"] == {"idleTime": 10, "overrideIdleTime": True, "someFutureField": {"x": 1}}
    assert saved["behavior"]["connectAs"]["rdp"]["localEphemeralUser"]["assignGroups"] == ["group-1"]


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
                   .replace('principal_template = ""', 'principal_template = "SIA-{hostname_upper}-RDP"')
                   .replace('target_set_scope = "server"', 'target_set_scope = "auto"'), encoding="utf-8")
    inp = workspace / "input"
    inp.mkdir()
    (inp / "servers.csv").write_text("fqdn\n", encoding="utf-8")
    (inp / "domains.csv").write_text("domain,strong_account,target_set,target_set_type,principal_template\n"
                                     "corp.example.com,SA-CORP-SIA,,Domain,\n", encoding="utf-8")
    return inp


def test_apply_single_server_json(workspace, monkeypatch, capsys):
    """The Ansible path: one server, no servers.csv row, machine-readable result on stdout."""
    inp = _domain_workspace(workspace)
    sia = FakeSIA([{"secret_id": "sec-corp", "secret_name": "SA-CORP-SIA", "secret_type": "PCloudAccount"}])
    shared_context(monkeypatch, sia=sia, identity=FakeIdentity(roles=[role_row("SIA-WEB09-RDP")]))
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


def test_single_server_principal_override_and_bad_fqdn(workspace, monkeypatch, capsys):
    inp = _domain_workspace(workspace)
    sia = FakeSIA([{"secret_id": "sec-corp", "secret_name": "SA-CORP-SIA", "secret_type": "PCloudAccount"}])
    shared_context(monkeypatch, sia=sia, identity=FakeIdentity(roles=[role_row("Typed-In")]))
    assert run(workspace, "plan", "--input", str(inp), "--server", "web09.corp.example.com", "--principal", "Typed-In") == 0
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
    shared_context(monkeypatch, sia=sia, identity=FakeIdentity(roles=[role_row("SIA-WEB09-RDP")]))
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    code = run(workspace, "apply", "--input", str(inp), "--server", "web09.corp.example.com", "--json", "--no-report")
    out = capsys.readouterr()
    data = json.loads(out.out)
    assert code == 2 and data["cancelled"] and data["diagnostics"][0]["mutation_state"] == "not_applied"
    assert "Type 'yes' to apply these changes:" in out.err and "Aborted; nothing changed." in out.err
    assert [c[0] for c in sia.calls if c[0] == "bulk_create_target_sets"] == []


def test_server_only_flags_without_server_are_rejected(workspace, monkeypatch, capsys):
    """--principal without --server used to be a silent no-op on a command that writes."""
    inp = _domain_workspace(workspace)
    (inp / "servers.csv").write_text("fqdn\nweb01.corp.example.com\n", encoding="utf-8")
    shared_context(monkeypatch)
    assert run(workspace, "apply", "--input", str(inp), "--principal", "SIA-Emergency-Access", "--yes") == 2
    assert "--principal only apply together with --server" in capsys.readouterr().err


def test_legacy_group_flag_and_key_are_rejected_with_rename_hints(workspace, monkeypatch, capsys):
    inp = _domain_workspace(workspace)
    shared_context(monkeypatch)
    assert run(workspace, "plan", "--input", str(inp), "--server", "web09.corp.example.com", "--group", "Typed-In") == 2
    err = capsys.readouterr().err
    assert "--group was renamed to --principal" in err and 'principal_type = "group"' in err
    cfg = workspace / "config.toml"
    cfg.write_text(cfg.read_text().replace('principal_template = "SIA-{hostname_upper}-RDP"',
                                           'group_template = "SIA-{hostname_upper}-RDP"'), encoding="utf-8")
    assert run(workspace, "plan", "--input", str(inp), "--server", "web09.corp.example.com") == 2
    err = capsys.readouterr().err
    assert "unknown key(s): group_template" in err and "'group_template' was renamed to 'principal_template'" in err


def test_group_principals_still_work_when_configured(workspace, monkeypatch, capsys):
    inp = _domain_workspace(workspace)
    cfg = workspace / "config.toml"
    cfg.write_text(cfg.read_text().replace('principal_type = "role"', 'principal_type = "group"'), encoding="utf-8")
    sia = FakeSIA([{"secret_id": "sec-corp", "secret_name": "SA-CORP-SIA", "secret_type": "PCloudAccount"}])
    uap = FakeUAP()
    shared_context(monkeypatch, sia=sia, uap=uap, identity=FakeIdentity(groups=[group_row("Typed-In")], roles=[]))
    assert run(workspace, "apply", "--input", str(inp), "--server", "web09.corp.example.com", "--principal", "Typed-In",
               "--yes", "--no-report", "--checkpoint", str(workspace / "ckpt.jsonl")) == 0
    principal = uap.policies[0]["principals"][0]
    assert principal["type"] == "GROUP" and principal["id"].startswith("id-Typed-In")
    assert "Typed-In" in capsys.readouterr().out


def test_groups_csv_with_role_principals_warns(workspace, monkeypatch, capsys, caplog):
    inp = _domain_workspace(workspace)
    (inp / "groups.csv").write_text("name,directory\nSIA-WEB09-RDP,CyberArk Cloud Directory\n", encoding="utf-8")
    sia = FakeSIA([{"secret_id": "sec-corp", "secret_name": "SA-CORP-SIA", "secret_type": "PCloudAccount"}])
    shared_context(monkeypatch, sia=sia, identity=FakeIdentity(roles=[role_row("SIA-WEB09-RDP")]))
    caplog.set_level(logging.WARNING, logger="sia")
    assert run(workspace, "plan", "--input", str(inp), "--server", "web09.corp.example.com") == 0
    captured = capsys.readouterr()
    assert 'groups.csv is only used when [defaults] principal_type = "group"' in caplog.text + captured.err


# ---------------------------------------------------------------- accounts-only onboarding (--accounts)

def _accounts_workspace(workspace):
    """Standalone servers: an FQDN-only list whose local administrators are stored in SIA (type=credentials)."""
    cfg = workspace / "config.toml"
    cfg.write_text(cfg.read_text()
                   .replace('strong_account_type = "vault"', 'strong_account_type = "credentials"')
                   .replace('principal_template = ""', 'principal_template = "SIA-{hostname_upper}-RDP"'), encoding="utf-8")
    inp = workspace / "input"
    inp.mkdir()
    (inp / "servers.csv").write_text("fqdn,domain_joined\nsrv01.example.com,no\nsrv02.example.com,no\n", encoding="utf-8")
    pwfile = workspace / "passwords.csv"
    pwfile.write_text("name,password\nSRV01.example.com,pw-1\nADM-srv02,pw-2\nunrelated,x\n", encoding="utf-8")
    pwfile.chmod(0o600)
    return inp, pwfile


def _no_account_env(monkeypatch):
    for var in ("SIA_SA_ADM_SRV01_PASSWORD", "SIA_SA_ADM_SRV02_PASSWORD", "SIA_SA_ADM_SRV09_PASSWORD"):
        monkeypatch.delenv(var, raising=False)


def test_plan_accounts_reads_secrets_only_and_writes_account_reports(workspace, monkeypatch, capsys):
    inp, pwfile = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    sia = FakeSIA()
    shared_context(monkeypatch, sia=sia)
    assert run(workspace, "plan", "--input", str(inp), "--accounts", "--passwords", str(pwfile)) == 0
    out = capsys.readouterr().out
    assert "PLAN (dry run" in out and "Scope: strong accounts only" in out and "Strong accounts:" in out and "Servers:" not in out
    assert "Account" in out and "SIA status" in out and "srv01.example.com" in out and "Summary: planned=2" in out
    ctx = FakeContext.instances[-1]
    assert ctx.uap.calls == [] and ctx.identity.queries == []
    assert [c[0] for c in sia.calls] == ["find_secret", "find_secret", "list_secrets"]   # search, then one confirming listing
    reports = sorted((workspace / "reports").iterdir())
    assert [p.name.startswith("plan-accounts-") for p in reports] == [True, True]
    data = json.loads(next(p for p in reports if p.suffix == ".json").read_text())
    assert data["scope"] == "accounts" and data["rows"] == 2 and data["mode"] == "plan" and data["failures"] == 0
    assert [a["name"] for a in data["accounts"]] == ["ADM-srv01", "ADM-srv02"] and data["accounts"][0]["secret_status"] == "planned"
    assert data["accounts"][0]["address"] == "srv01.example.com" and data["accounts"][0]["sia_name"] == "ADM-srv01"
    assert data["accounts"][0]["vault_status"] == "n/a" and data["servers"] == []
    csv_lines = next(p for p in reports if p.suffix == ".csv").read_text().splitlines()
    assert csv_lines[0] == "name,type,sia_name,username,address,vault_status,vault_detail,secret_status,secret_detail,secret_id"
    assert len(csv_lines) == 3 and csv_lines[1].startswith("ADM-srv01,credentials,ADM-srv01,Administrator,srv01.example.com,n/a,")
    assert not list(inp.glob(".sia-checkpoint*"))


def test_apply_accounts_creates_then_exists_then_server_apply_sees_it(workspace, monkeypatch, capsys, caplog):
    inp, pwfile = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    caplog.set_level(logging.INFO)
    sia = FakeSIA()
    identity = FakeIdentity(roles=[role_row("SIA-SRV01-RDP", "r1"), role_row("SIA-SRV02-RDP", "r2")])
    shared_context(monkeypatch, sia=sia, identity=identity)
    code = run(workspace, "apply", "--accounts", "--yes", "--input", str(inp), "--passwords", str(pwfile), "--json", "--no-report",
               "--checkpoint", cp(workspace))
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert code == 0 and data["scope"] == "accounts" and data["failures"] == 0
    assert [a["secret_status"] for a in data["accounts"]] == ["created", "created"]
    created = [c[1] for c in sia.calls if c[0] == "create_secret"]
    assert [c["secret"]["secret_data"] for c in created] == [{"username": "Administrator", "password": "pw-1"},
                                                              {"username": "Administrator", "password": "pw-2"}]
    assert all(c["secret_details"] == {"account_domain": "local", "ephemeral_domain_user_data": {}} for c in created)
    assert "pw-1" not in captured.out + captured.err + caplog.text and "pw-2" not in captured.out + captured.err
    assert not Path(cp(workspace)).exists()
    warnings = [r.getMessage() for r in caplog.records if "password file lists" in r.getMessage()]
    assert warnings == ["password file lists 1 name(s) that match no strong account name or server FQDN: unrelated"]
    # Second run: everything exists, nothing is created.
    assert run(workspace, "apply", "--accounts", "--yes", "--input", str(inp), "--passwords", str(pwfile), "--no-report",
               "--checkpoint", cp(workspace)) == 0
    out = capsys.readouterr().out
    assert "Summary: exists=2" in out and len([c for c in sia.calls if c[0] == "create_secret"]) == 2
    # The later server run finds the accounts and adds only target sets and policies.
    assert run(workspace, "apply", "--yes", "--input", str(inp), "--passwords", str(pwfile), "--no-report", "--checkpoint", cp(workspace)) == 0
    out = capsys.readouterr().out
    assert "Summary: created=4, exists=2" in out and len(sia.secrets) == 2 and Path(cp(workspace)).exists()


def test_apply_accounts_without_password_fails_where_plan_only_plans(workspace, monkeypatch, capsys):
    inp, _ = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    monkeypatch.setattr(sia_onboard, "interactive", lambda: False)
    shared_context(monkeypatch)
    assert run(workspace, "plan", "--accounts", "--input", str(inp), "--no-report") == 0
    assert "planned" in capsys.readouterr().out
    assert run(workspace, "apply", "--accounts", "--yes", "--input", str(inp), "--no-report", "--json") == 1
    data = json.loads(capsys.readouterr().out)
    assert data["failures"] == 2 and all(a["secret_status"] == "failed" for a in data["accounts"])
    assert "server FQDN" in data["accounts"][0]["secret_detail"]


def test_accounts_single_server_from_a_build_job(workspace, monkeypatch, capsys):
    inp, _ = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    monkeypatch.setenv("SIA_SA_ADM_SRV09_PASSWORD", "pw-9")
    sia = FakeSIA()
    shared_context(monkeypatch, sia=sia)
    code = run(workspace, "apply", "--accounts", "--server", "srv09.example.com", "--workgroup", "--yes", "--json", "--no-report",
               "--input", str(inp))
    data = json.loads(capsys.readouterr().out)
    assert code == 0 and data["rows"] == 1 and data["accounts"][0]["name"] == "ADM-srv09"
    assert data["accounts"][0]["address"] == "srv09.example.com" and data["accounts"][0]["secret_status"] == "created"
    assert sia.secrets[0]["secret_name"] == "ADM-srv09"
    assert run(workspace, "apply", "--accounts", "--server", "srv09.example.com", "--principal", "X", "--yes", "--input", str(inp)) == 2
    assert "--principal do not apply with --accounts" in capsys.readouterr().err


@pytest.mark.parametrize("argv, fragment", [
    (["plan", "--accounts", "--update"], "--update do not apply with --accounts"),
    (["plan", "--accounts", "--drift"], "--drift do not apply with --accounts"),
    (["plan", "--accounts", "--adopt", "x"], "--adopt do not apply"),
    (["plan", "--accounts", "--adopt-all"], "--adopt-all do not apply"),
    (["apply", "--accounts", "--resume", "--yes"], "--resume do not apply"),
    (["plan", "--accounts", "--only", "policies"], "--only policies do not apply"),
    (["plan", "--accounts", "--update", "--set-policy-status", "Active"], "--update, --set-policy-status do not apply"),
    (["plan", "--accounts", "--server", "a.b.c", "--protocol", "ssh", "--ssh-username", "u"], "--protocol ssh does not apply"),
    (["verify", "--accounts", "--drift"], "--drift do not apply"),
    (["connect-info", "--accounts"], "unrecognized arguments"),
])
def test_accounts_rejected_flag_combinations(workspace, monkeypatch, capsys, argv, fragment):
    inp, _ = _accounts_workspace(workspace)
    shared_context(monkeypatch)
    assert run(workspace, *argv, "--input", str(inp)) == 2
    assert fragment in capsys.readouterr().err


def test_accounts_accepts_the_account_stages_and_waves(workspace, monkeypatch, capsys):
    inp, pwfile = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    shared_context(monkeypatch)
    assert run(workspace, "plan", "--accounts", "--only", "secrets", "--input", str(inp), "--no-report") == 0
    assert run(workspace, "plan", "--accounts", "--only", "vault", "--input", str(inp), "--no-report") == 0
    capsys.readouterr()
    assert run(workspace, "plan", "--accounts", "--offset", "1", "--limit", "1", "--input", str(inp), "--json", "--no-report") == 0
    data = json.loads(capsys.readouterr().out)
    assert [a["name"] for a in data["accounts"]] == ["ADM-srv02"] and data["rows"] == 1


def test_verify_accounts_missing_then_pass_then_inactive(workspace, monkeypatch, capsys):
    inp, pwfile = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    sia = FakeSIA()
    shared_context(monkeypatch, sia=sia)
    out_csv = workspace / "verify.csv"
    assert run(workspace, "verify", "--accounts", "--input", str(inp), "--out", str(out_csv)) == 1
    out = capsys.readouterr().out
    assert "== VERIFY ==" in out and "Scope: strong accounts only" in out and "MISSING=2 (accounts=2)" in out
    assert "Missing strong account ADM-srv01 for srv01.example.com" in out and "Servers" not in out.split("Details:")[0].split("\n")[3]
    lines = out_csv.read_text().splitlines()
    assert lines[0] == "name,type,sia_name,username,address,vault,secret,verdict,secret_id,detail" and ",MISSING," in lines[1]
    assert run(workspace, "apply", "--accounts", "--yes", "--input", str(inp), "--passwords", str(pwfile), "--no-report") == 0
    capsys.readouterr()
    assert run(workspace, "verify", "--accounts", "--input", str(inp)) == 0
    assert "PASS=2 (accounts=2)" in capsys.readouterr().out
    sia.secrets[0]["is_active"] = False
    assert run(workspace, "verify", "--accounts", "--input", str(inp), "--json") == 1
    data = json.loads(capsys.readouterr().out)
    assert data["mode"] == "verify" and data["scope"] == "accounts" and not data["ok"] and data["exit_code"] == 1
    assert [a["secret_status"] for a in data["accounts"]] == ["inactive", "exists"]


def test_password_file_keys_by_fqdn_as_well_as_name(monkeypatch):
    monkeypatch.delenv("SIA_SA_ADM_W2_PASSWORD", raising=False)
    local = StrongAccountRow(name="ADM-w2", type="credentials", safe=None, account_name=None, username="u",
                             account_domain="local", password_env="SIA_SA_ADM_W2_PASSWORD", line=0, address="srv01.example.com")
    get = sia_onboard.make_password_source(allow_prompt=False, file_passwords={"SRV01.Example.com": "by-fqdn", "adm-w2": "by-name"})
    assert get(local) == "by-name"          # the account name wins over the address, both case-insensitively
    assert sia_onboard.make_password_source(allow_prompt=False, file_passwords={"SRV01.Example.com": "by-fqdn"})(local) == "by-fqdn"
    assert sia_onboard.make_password_source(allow_prompt=False, file_passwords={"other.example.com": "x"})(local) is None
    monkeypatch.setenv("SIA_SA_ADM_W2_PASSWORD", "by-env")
    assert get(local) == "by-env"


@pytest.mark.parametrize("kind", ["credentials", "vault"])
@pytest.mark.parametrize("accounts_only", [False, True])
def test_explicit_account_uses_fqdn_password_without_address(workspace, monkeypatch, capsys, caplog, kind, accounts_only):
    inp, pwfile = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    (inp / "servers.csv").write_text("fqdn,strong_account,domain_joined\nSRV01.example.com,adm-srv01,no\n", encoding="utf-8")
    (inp / "strong_accounts.csv").write_text(
        "name,type,safe,account_name,username,account_domain\n"
        f"ADM-srv01,{kind},Safe,AdminAccount,Administrator,local\n", encoding="utf-8")
    pwfile.write_text("name,password\nSrV01.Example.COM,fqdn-password\n", encoding="utf-8")

    class PasswordCapturingPVWA(FakePVWA):
        password = None

        def add_account(self, payload):
            self.password = payload["secret"]
            return super().add_account(payload)

    pvwa = PasswordCapturingPVWA()
    if kind == "vault":
        cfg = workspace / "config.toml"
        cfg.write_text(cfg.read_text().replace('base_url = ""', 'base_url = "https://pvwa.example.com"'), encoding="utf-8")
        FakeContext.pvwa = pvwa
    sia = FakeSIA()
    shared_context(monkeypatch, sia=sia, identity=FakeIdentity(roles=[role_row("SIA-SRV01-RDP")]))
    scope = ["--accounts"] if accounts_only else []
    assert run(workspace, "apply", *scope, "--yes", "--input", str(inp), "--passwords", str(pwfile),
               "--checkpoint", cp(workspace), "--json", "--no-report") == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["accounts"][0]["address"] == "srv01.example.com"
    assert data["accounts"][0]["secret_status"] == "created"
    if kind == "vault":
        assert pvwa.password == "fqdn-password" and pvwa.accounts[0]["address"] == "srv01.example.com"
        assert pvwa.logged_off
    else:
        payload = next(payload for action, payload in sia.calls if action == "create_secret")
        assert payload["secret"]["secret_data"]["password"] == "fqdn-password"
    assert not any("match no strong account" in record.getMessage() for record in caplog.records)
    assert "fqdn-password" not in captured.out + captured.err + caplog.text


@pytest.mark.parametrize("inline", [False, True])
def test_accounts_workgroup_ignores_matching_domain_account(workspace, monkeypatch, capsys, inline):
    inp, pwfile = _accounts_workspace(workspace)
    _no_account_env(monkeypatch)
    (inp / "servers.csv").write_text("fqdn,domain_joined\nsrv01.example.com,no\n", encoding="utf-8")
    (inp / "domains.csv").write_text("domain,strong_account\nexample.com,SA-DOMAIN\n", encoding="utf-8")
    domain_secret = {"secret_id": "domain-secret", "secret_name": "SA-DOMAIN",
                     "secret_type": "ProvisionerUser", "is_active": True}
    sia = FakeSIA(secrets=[domain_secret])
    shared_context(monkeypatch, sia=sia)
    source = ["--server", "srv01.example.com", "--workgroup"] if inline else []
    assert run(workspace, "apply", "--accounts", "--yes", "--input", str(inp), *source,
               "--passwords", str(pwfile), "--json", "--no-report") == 0
    data = json.loads(capsys.readouterr().out)
    assert [(a["name"], a["secret_status"]) for a in data["accounts"]] == [("ADM-srv01", "created")]
    assert {s["secret_name"] for s in sia.secrets} == {"SA-DOMAIN", "ADM-srv01"}
    assert sia.secrets[0] == domain_secret
    ctx = FakeContext.instances[-1]
    assert not ctx.uap.calls and not ctx.identity.queries and not sia.target_sets


def test_shared_account_does_not_pick_a_password_by_wave(workspace, monkeypatch, capsys):
    inp, pwfile = _accounts_workspace(workspace)
    monkeypatch.delenv("SIA_SA_ADM_SHARED_PASSWORD", raising=False)
    monkeypatch.setattr(sia_onboard, "interactive", lambda: False)
    (inp / "servers.csv").write_text(
        "fqdn,strong_account,domain_joined\nsrv01.example.com,ADM-shared,no\nsrv02.example.com,ADM-shared,no\n",
        encoding="utf-8")
    (inp / "strong_accounts.csv").write_text(
        "name,type,username\nADM-shared,credentials,Administrator\n", encoding="utf-8")
    pwfile.write_text("name,password\nsrv01.example.com,first-password\nsrv02.example.com,second-password\n", encoding="utf-8")
    sia = FakeSIA()
    shared_context(monkeypatch, sia=sia)
    for offset in ("0", "1"):
        assert run(workspace, "apply", "--accounts", "--yes", "--input", str(inp), "--passwords", str(pwfile),
                   "--offset", offset, "--limit", "1", "--json", "--no-report") == 1
        data = json.loads(capsys.readouterr().out)
        assert data["accounts"][0]["secret_status"] == "failed"
        assert not sia.secrets
    pwfile.write_text("name,password\nADM-shared,shared-password\n", encoding="utf-8")
    assert run(workspace, "apply", "--accounts", "--yes", "--input", str(inp), "--passwords", str(pwfile),
               "--offset", "1", "--limit", "1", "--json", "--no-report") == 0
    payload = next(payload for action, payload in sia.calls if action == "create_secret")
    assert payload["secret"]["secret_data"]["password"] == "shared-password"
