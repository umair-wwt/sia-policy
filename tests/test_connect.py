from pathlib import Path

import pytest

from sia.config import Config, ConfigError, ConnectConfig, Defaults, StrongAccountTemplate, TenantConfig
from sia.connect import (CONNECT_COLUMNS, build_rows, gateway_host, login_suffix, portal_url, rdp_file_text, write_connect_csv,
                         write_rdp_files, zsp_username)
from sia.inputs import load_inputs
from sia.payloads import policy_name_for
from sia.reconcile import Outcome, ServerResult

ROOT = Path(__file__).resolve().parents[1]
CFG = Config(tenant=TenantConfig("acme", "https://abc.id.cyberark.cloud"))
SPEC = StrongAccountTemplate(name="ADM-{hostname}", type="vault", safe="S", account_name="{hostname}-Administrator", username="Administrator")


def test_gateway_portal_and_login_suffix():
    assert gateway_host(CFG) == "acme.rdp.cyberark.cloud"
    assert portal_url(CFG) == "https://acme.cyberark.cloud/dpa"
    custom = Config(tenant=TenantConfig("acme", "https://abc.id.cyberark.cloud", root_domain="cyberark.eu"),
                    connect=ConnectConfig(gateway_host="gw.example.com", login_suffix="corp.example.com"))
    assert gateway_host(custom) == "gw.example.com" and login_suffix(custom, "svc@acme.cyberark.cloud") == "corp.example.com"
    assert login_suffix(CFG, "svc@acme.cyberark.cloud") == "acme.cyberark.cloud"
    assert login_suffix(CFG) == "acme.cyberark.cloud" and login_suffix(CFG, "svc-without-at") == "acme.cyberark.cloud"


def test_zsp_username_formats():
    assert zsp_username("alice", "acme.cyberark.cloud", "acme", "web01.corp.example.com") == \
        "secureaccess /i alice@acme.cyberark.cloud /s acme /a web01.corp.example.com"
    assert zsp_username("alice@other.suffix", "acme.cyberark.cloud", "acme", "w.corp") == "secureaccess /i alice@other.suffix /s acme /a w.corp"
    assert zsp_username("alice", "s", "acme", "w.corp", domain_joined=False).endswith("/a w.corp /d local")
    assert zsp_username("alice", "s", "acme", "w.corp", network="dc1").endswith("/a w.corp /n dc1")
    assert zsp_username("alice", "s", "acme", "w.corp", domain_joined=False, network="dc1").endswith("/d local /n dc1")


def test_rdp_file_text_is_static_and_secret_free():
    text = rdp_file_text("web01.corp.example.com", "acme.rdp.cyberark.cloud", "secureaccess /i a@b /s acme /a web01.corp.example.com")
    lines = text.split("\r\n")
    assert lines[0] == "full address:s:web01.corp.example.com" and "gatewayhostname:s:acme.rdp.cyberark.cloud" in lines
    assert "gatewayusagemethod:i:1" in lines and "gatewayaccesstoken:s:secureaccess" in lines and "gatewaycredentialssource:i:5" in lines
    assert "username:s:secureaccess /i a@b /s acme /a web01.corp.example.com" in lines and text.endswith("\r\n")
    assert "password" not in text.lower() and "token" not in text.replace("gatewayaccesstoken", "").lower()


@pytest.mark.parametrize("field,value", [
    ("user", "alice\nredirectclipboard:i:1"),
    ("user", "alice /s other"),
    ("network", "net\npromptcredentialonce:i:0"),
    ("network", "net /d local"),
    ("suffix", "good.example\rredirectclipboard:i:1"),
])
def test_zsp_username_rejects_control_and_argument_injection(field, value):
    kwargs = {"user": "alice", "suffix": "good.example", "subdomain": "acme", "fqdn": "web.good.example",
              "network": ""}
    kwargs[field] = value
    with pytest.raises(ConfigError):
        zsp_username(**kwargs)


@pytest.mark.parametrize("fqdn,gateway,username", [
    ("web.good.example\nredirectclipboard:i:1", "gw.good.example", "secureaccess /i a@good.example"),
    ("web.good.example", "gw.good.example\rpromptcredentialonce:i:0", "secureaccess /i a@good.example"),
    ("web.good.example", "gw.good.example", "secureaccess /i a@good.example\naudiocapturemode:i:1"),
])
def test_rdp_file_boundary_rejects_directive_injection(fqdn, gateway, username):
    with pytest.raises(ConfigError):
        rdp_file_text(fqdn, gateway, username)


def test_programmatic_connection_config_is_validated_at_use_boundary():
    bad_gateway = Config(tenant=CFG.tenant, connect=ConnectConfig(gateway_host="good.example\nredirectclipboard:i:1"))
    with pytest.raises(ConfigError, match="gateway"):
        gateway_host(bad_gateway)
    bad_suffix = Config(tenant=CFG.tenant, connect=ConnectConfig(login_suffix="good.example\npromptcredentialonce:i:0"))
    with pytest.raises(ConfigError, match="suffix"):
        login_suffix(bad_suffix)


@pytest.mark.parametrize(("user", "network"), [
    ("alice\nredirectclipboard:i:1", ""),
    ("alice", "net\npromptcredentialonce:i:0"),
])
def test_build_rows_rejects_cli_connection_injection_even_for_ssh_only(tmp_path, user, network):
    servers = tmp_path / "servers.csv"
    servers.write_text(
        "fqdn,protocol,principal,strong_account,domain_joined,ssh_username\n"
        "linux.good.example,ssh,SIA-Linux,,,admin\n",
        encoding="utf-8",
    )
    inputs = load_inputs(tmp_path)
    names = {(server.fqdn, server.line): server.fqdn for server in inputs.servers}
    with pytest.raises(ConfigError):
        build_rows(inputs, CFG, names, None, user=user, network=network)


def test_build_rows_and_files(tmp_path):
    inputs = load_inputs(ROOT / "input", strong_account_template=SPEC)
    defaults = Defaults()
    names = {(s.fqdn, s.line): policy_name_for(s, defaults) for s in inputs.servers}
    statuses = {("web01.corp.example.com", "web01.corp.example.com"): ServerResult(
        fqdn="web01.corp.example.com", strong_account="ADM-web01", policy_name="web01.corp.example.com",
        secret=Outcome("exists"), target_set=Outcome("exists"), policy=Outcome("exists", "ok", "pol-1"))}
    rows = build_rows(inputs, CFG, names, statuses, user="alice", suffix="acme.cyberark.cloud", rdp_dir=tmp_path / "rdp")
    assert len(rows) == 6 and [r.policy_name for r in rows][:2] == ["web01.corp.example.com", "web01.corp.example.com-ops"]
    assert rows[0].policy_status == "exists" and rows[0].policy_id == "pol-1" and rows[1].policy_status == ""
    assert rows[0].rdp_username == "secureaccess /i alice@acme.cyberark.cloud /s acme /a web01.corp.example.com"
    assert rows[0].rdp_file.endswith("web01-web01.corp.example.com.rdp") and rows[1].rdp_file.endswith("web01-web01.corp.example.com-ops.rdp")
    assert rows[2].rdp_file.endswith("web02.rdp") and rows[3].rdp_username.endswith("/d local")
    assert rows[5].protocol == "ssh" and rows[5].rdp_username == "" and rows[5].rdp_file == "" and rows[5].strong_account == "-"
    assert rows[0].principals == "SIA-Web-Admins" and rows[0].gateway_host == "acme.rdp.cyberark.cloud" and rows[0].as_list()[0] == "web01.corp.example.com"
    path = write_connect_csv(rows, tmp_path / "out" / "connect.csv")
    header = path.read_text(encoding="utf-8").splitlines()[0]
    assert header == ",".join(CONNECT_COLUMNS)
    written = write_rdp_files(rows)
    assert len(written) == 5 and all(p.suffix == ".rdp" for p in written)
    assert "full address:s:dmz-app01.dmz.example.com" in (tmp_path / "rdp" / "dmz-app01.rdp").read_text()
    rows = build_rows(inputs, CFG, names, None, user="<user>", suffix="s", network="net1")
    assert rows[0].rdp_username.endswith("/n net1") and rows[0].rdp_file == "" and write_rdp_files(rows) == []
