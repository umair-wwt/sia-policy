from pathlib import Path

import pytest

from sia.config import StrongAccountTemplate
from sia.inputs import InputError, effective_policy_name, load_inputs

ROOT = Path(__file__).resolve().parents[1]

SERVERS_HDR = "fqdn,strong_account,group,policy_name,assign_groups,domain,description\n"
ACCOUNTS_HDR = "name,type,safe,account_name,username,account_domain,password_env\n"
VAULT_SPEC = StrongAccountTemplate(name="ADM-{hostname}", type="vault", safe="SIA-LocalAdmins",
                                   account_name="{hostname}-Administrator", username="Administrator")


def make_inputs(tmp_path: Path, servers: str, accounts: str, groups: str | None = None, servers_hdr: str = SERVERS_HDR) -> Path:
    (tmp_path / "servers.csv").write_text(servers_hdr + servers, encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text(ACCOUNTS_HDR + accounts, encoding="utf-8")
    if groups is not None:
        (tmp_path / "groups.csv").write_text("name,directory\n" + groups, encoding="utf-8")
    return tmp_path


def test_example_inputs_load():
    inputs = load_inputs(ROOT / "input", strong_account_template=VAULT_SPEC)
    assert [s.fqdn for s in inputs.servers] == [
        "web01.corp.example.com", "web01.corp.example.com", "web02.corp.example.com", "dmz-app01.dmz.example.com",
        "fs01.corp.example.com", "app-lnx01.corp.example.com"]
    assert inputs.unique_fqdns == ("web01.corp.example.com", "web02.corp.example.com", "dmz-app01.dmz.example.com",
                                   "fs01.corp.example.com", "app-lnx01.corp.example.com")
    first, second = inputs.rows_for("web01.corp.example.com")
    assert first.strong_account == second.strong_account == "ADM-web01"
    assert first.groups == ("SIA-Web-Admins",) and first.policy_suffix is None and first.domain_joined is True
    assert second.groups == ("SIA-Platform-Ops",) and second.policy_suffix == "-ops" and second.assign_groups == ("Remote Desktop Users",)
    adm = inputs.strong_accounts["ADM-web01"]
    assert adm.type == "vault" and adm.safe == "SIA-LocalAdmins" and adm.account_name == "web01-Administrator"
    assert adm.username == "Administrator" and adm.sia_name == "web01-Administrator_SIA-LocalAdmins"
    assert adm.address == "web01.corp.example.com" and adm.is_local and adm.line == 0 and adm.secret_type == "PCloudAccount"
    dmz = inputs.servers[3]
    assert dmz.policy_name == "SIA-RDP-dmz-app01-custom" and dmz.dns_domain == "dmz.example.com" and dmz.domain_joined is False
    fs = inputs.servers[4]
    assert fs.strong_account == "SA-corp-domain" and fs.hostname == "fs01"
    shared = inputs.strong_accounts["SA-corp-domain"]
    assert shared.type == "vault" and shared.account_domain == "corp.example.com" and shared.address == "corp.example.com" and not shared.is_local
    lnx = inputs.servers[5]
    assert lnx.is_ssh and lnx.strong_account is None and lnx.ssh_username == "ec2-user" and lnx.groups == ("SIA-Linux-Admins",)
    dmz_sa = inputs.strong_accounts["SA-dmz-localadmin"]
    assert dmz_sa.secret_type == "ProvisionerUser" and dmz_sa.password_env == "SIA_SA_DMZ_LOCALADMIN_PASSWORD"
    assert inputs.strong_accounts["SA-legacy"].secret_type is None
    assert inputs.pinned_directory("SIA-Platform-Ops") == "CyberArk Cloud Directory"
    assert inputs.pinned_directory("SIA-Web-Admins") is None
    assert {sa.name for sa in inputs.referenced_strong_accounts} == {"ADM-web01", "ADM-web02", "SA-dmz-localadmin", "SA-corp-domain"}
    assert [s.fqdn for s in inputs.target_rows] == ["web01.corp.example.com", "web02.corp.example.com",
                                                    "dmz-app01.dmz.example.com", "fs01.corp.example.com"]
    assert inputs.referenced_groups == ["SIA-Web-Admins", "SIA-Platform-Ops", "SIA-DMZ-Admins", "SIA-Linux-Admins"]
    assert inputs.warnings == ()
    wave = inputs.window(1, 2)
    assert [s.fqdn for s in wave.servers] == ["web02.corp.example.com", "dmz-app01.dmz.example.com"]
    assert wave.strong_accounts is inputs.strong_accounts
    first_wave = inputs.window(0, 1)
    assert first_wave.unique_fqdns == ("web01.corp.example.com",) and len(first_wave.servers) == 2
    assert len(inputs.window(4).servers) == 1 and inputs.window(99).servers == ()
    with pytest.raises(InputError, match="strong_account is required"):
        load_inputs(ROOT / "input")  # the example relies on the template in config.toml


def test_fqdn_normalized_and_bom_tolerated(tmp_path):
    (tmp_path / "servers.csv").write_bytes(b"\xef\xbb\xbffqdn,strong_account,group\nWEB01.Corp.Example.COM., SA1 , Admins \n\n")
    (tmp_path / "strong_accounts.csv").write_text("name,type\nSA1,existing\n", encoding="utf-8")
    inputs = load_inputs(tmp_path)
    assert inputs.servers[0].fqdn == "web01.corp.example.com"
    assert inputs.servers[0].strong_account == "SA1"
    assert inputs.servers[0].groups == ("Admins",)
    assert inputs.servers[0].assign_groups is None


def test_default_password_env_derived(tmp_path):
    make_inputs(tmp_path, "s1.corp.local,SA local,G\n", "SA local,credentials,,,admin,,\n")
    sa = load_inputs(tmp_path).strong_accounts["SA local"]
    assert sa.password_env == "SIA_SA_SA_LOCAL_PASSWORD" and sa.account_domain == "local"


@pytest.mark.parametrize("servers, accounts, fragment", [
    ("web01,SA1,G\n", "SA1,existing,,,,,\n", "not a valid FQDN"),
    ("10.0.0.1,SA1,G\n", "SA1,existing,,,,,\n", "not a valid FQDN"),
    ("a.b.c,SA1,G\na.b.c,SA1,G\n", "SA1,existing,,,,,\n", "collides with line 2"),
    ("a.b.c,SA1,G\na.b.c,SA2,G,P2\n", "SA1,existing,,,,,\nSA2,existing,,,,,\n", "strong_account 'SA2' conflicts with line 2"),
    ("a.b.c,SA1,G\na.b.c,SA1,G,P2,,other.dom\n", "SA1,existing,,,,,\n", "domain 'other.dom' conflicts"),
    ("a.b.c,SA1,\n", "SA1,existing,,,,,\n", "group is required"),
    ("a.b.c,,G\n", "SA1,existing,,,,,\n", "strong_account is required"),
    ("a.b.c,SA-missing,G\n", "SA1,existing,,,,,\n", "not defined in strong_accounts.csv"),
    ("a.b.c,SA1,G\n", "SA1,bogus,,,,,\n", "type must be one of"),
    ("a.b.c,SA1,G\n", "SA1,vault,,,,,\n", "requires safe and account_name"),
    ("a.b.c,SA1,G\n", "SA1,credentials,,,,,\n", "requires username"),
    ("a.b.c,SA1,G\n", "SA1,existing,Safe1,,,,\n", "must not set"),
    ("a.b.c,SA1,G\n", "SA1,existing,,,,,\nsa1,vault,S,A,,,\n", "duplicate strong account"),
    ("a.b.c,SA1,G," + "x" * 201 + "\n", "SA1,existing,,,,,\n", "must be 1..200 characters"),
])
def test_validation_errors(tmp_path, servers, accounts, fragment):
    make_inputs(tmp_path, servers, accounts)
    with pytest.raises(InputError, match=fragment):
        load_inputs(tmp_path)


def test_all_problems_reported_together(tmp_path):
    make_inputs(tmp_path, "bad,SA1,G\nalso-bad,SA2,\n", "SA1,existing,,,,,\n")
    with pytest.raises(InputError) as exc:
        load_inputs(tmp_path)
    text = str(exc.value)
    assert "servers.csv:2" in text and "servers.csv:3" in text
    assert "SA2" in text and "group is required" in text


def test_missing_and_unknown_columns(tmp_path):
    (tmp_path / "servers.csv").write_text("fqdn,strong_account,groups\n", encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text("name,type\n", encoding="utf-8")
    with pytest.raises(InputError) as exc:
        load_inputs(tmp_path)
    assert "missing required column(s): group" in str(exc.value)
    assert "unknown column(s): groups" in str(exc.value)


def test_missing_files(tmp_path):
    with pytest.raises(InputError, match="servers.csv.*not found"):
        load_inputs(tmp_path)


def test_groups_csv_duplicates(tmp_path):
    make_inputs(tmp_path, "a.b.c,SA1,G\n", "SA1,existing,,,,,\n", groups="G,\nG,CyberArk Cloud Directory\n")
    with pytest.raises(InputError, match="duplicate group"):
        load_inputs(tmp_path)


@pytest.mark.parametrize("domain, ok", [("corp.example.com", True), ("corp", True), ("bad_domain.com", False), ("-x.com", False)])
def test_domain_column_validation(tmp_path, domain, ok):
    make_inputs(tmp_path, f"a.b.c,SA1,G,,,{domain},\n", "SA1,existing,,,,,\n")
    if ok:
        assert load_inputs(tmp_path).servers[0].dns_domain == domain
    else:
        with pytest.raises(InputError, match="not a valid DNS name"):
            load_inputs(tmp_path)


def test_ssh_rows(tmp_path):
    make_inputs(tmp_path, "", "SA1,existing,,,,,\n")
    (tmp_path / "servers.csv").write_text(
        "fqdn,strong_account,group,policy_name,assign_groups,domain,description,protocol,ssh_username\n"
        "lnx1.corp.local,SA1,G,,,,,ssh,ec2-user\nlnx2.corp.local,,G,,Administrators,,,SSH,\n", encoding="utf-8")
    inputs = load_inputs(tmp_path, ssh_username_default="root")
    lnx1, lnx2 = inputs.servers
    assert lnx1.is_ssh and lnx1.strong_account is None and lnx1.ssh_username == "ec2-user"
    assert lnx2.is_ssh and lnx2.ssh_username is None and lnx2.assign_groups is None
    assert any("strong_account 'SA1' ignored for protocol=ssh" in w for w in inputs.warnings)
    assert any("assign_groups ignored for protocol=ssh" in w for w in inputs.warnings)
    assert inputs.referenced_strong_accounts == [] and inputs.target_rows == ()
    with pytest.raises(InputError, match="protocol=ssh needs ssh_username"):
        load_inputs(tmp_path)  # no default username


def test_protocol_validation_and_rdp_ignores_ssh_username(tmp_path):
    (tmp_path / "servers.csv").write_text(
        "fqdn,strong_account,group,protocol,ssh_username\nw1.corp.local,SA1,G,telnet,\nw2.corp.local,SA1,G,rdp,root\n", encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text("name,type\nSA1,existing\n", encoding="utf-8")
    with pytest.raises(InputError, match="protocol must be one of rdp, ssh"):
        load_inputs(tmp_path)
    (tmp_path / "servers.csv").write_text(
        "fqdn,strong_account,group,protocol,ssh_username\nw2.corp.local,SA1,G,rdp,root\n", encoding="utf-8")
    inputs = load_inputs(tmp_path)
    assert inputs.servers[0].ssh_username is None and any("ssh_username ignored for protocol=rdp" in w for w in inputs.warnings)


def test_strong_account_template_string_keeps_lookup_only_behaviour(tmp_path):
    (tmp_path / "servers.csv").write_text("fqdn,strong_account,group\nweb01.corp.local,,G\nweb02.corp.local,SA-explicit,G\n", encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text("name,type\nSA-explicit,existing\n", encoding="utf-8")
    inputs = load_inputs(tmp_path, strong_account_template="ADM-{hostname}")
    assert inputs.servers[0].strong_account == "ADM-web01"
    implicit = inputs.strong_accounts["ADM-web01"]
    assert implicit.type == "existing" and implicit.sia_name == "ADM-web01" and implicit.line == 0
    assert {a.name for a in inputs.referenced_strong_accounts} == {"ADM-web01", "SA-explicit"}
    with pytest.raises(InputError, match="strong_account is required .*strong_account_template"):
        load_inputs(tmp_path)  # no template configured
    (tmp_path / "servers.csv").write_text("fqdn,strong_account,group\nweb03.corp.local,ADM-typo,G\n", encoding="utf-8")
    with pytest.raises(InputError, match="not defined in strong_accounts.csv"):
        load_inputs(tmp_path, strong_account_template="ADM-{hostname}")  # explicit names must still be declared


def test_templated_vault_and_credentials_accounts(tmp_path):
    (tmp_path / "servers.csv").write_text("fqdn,strong_account,group\nweb01.corp.local,,G\nweb01.corp.local,,G2\nweb02.corp.local,,G\n", encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text("name,type\n", encoding="utf-8")
    with pytest.raises(InputError, match="collides"):
        load_inputs(tmp_path, strong_account_template=VAULT_SPEC)  # two rows for web01 need distinct policy names
    (tmp_path / "servers.csv").write_text("fqdn,strong_account,group,policy_suffix\nweb01.corp.local,,G,\nweb01.corp.local,,G2,-ops\nweb02.corp.local,,G,\n", encoding="utf-8")
    inputs = load_inputs(tmp_path, strong_account_template=VAULT_SPEC)
    assert [s.strong_account for s in inputs.servers] == ["ADM-web01", "ADM-web01", "ADM-web02"]
    assert {a.name for a in inputs.referenced_strong_accounts} == {"ADM-web01", "ADM-web02"}
    adm = inputs.strong_accounts["ADM-web02"]
    assert (adm.type, adm.safe, adm.account_name, adm.username, adm.address) == ("vault", "SIA-LocalAdmins", "web02-Administrator", "Administrator", "web02.corp.local")
    creds = StrongAccountTemplate(name="ADM-{hostname}", type="credentials", username="siaadmin-{hostname}")
    inputs = load_inputs(tmp_path, strong_account_template=creds)
    adm = inputs.strong_accounts["ADM-web01"]
    assert adm.type == "credentials" and adm.username == "siaadmin-web01" and adm.password_env == "SIA_SA_ADM_WEB01_PASSWORD"
    assert adm.secret_type == "ProvisionerUser" and adm.address == "web01.corp.local"
    long_user = StrongAccountTemplate(name="ADM-{hostname}", type="credentials", username="administrator-{fqdn}")
    inputs = load_inputs(tmp_path, strong_account_template=long_user)
    assert any("longer than 20 characters" in w for w in inputs.warnings)
    domain_spec = StrongAccountTemplate(name="SVC-{domain}", type="vault", safe="S", account_name="svc-{domain}", username="svc", account_domain="corp.local")
    inputs = load_inputs(tmp_path, strong_account_template=domain_spec)
    assert {a.name for a in inputs.referenced_strong_accounts} == {"SVC-corp.local"}  # one shared account for the domain
    assert inputs.strong_accounts["SVC-corp.local"].address == "corp.local"
    # an explicit row wins over the template
    (tmp_path / "strong_accounts.csv").write_text("name,type\nADM-web02,existing\n", encoding="utf-8")
    inputs = load_inputs(tmp_path, strong_account_template=VAULT_SPEC)
    assert inputs.strong_accounts["ADM-web02"].type == "existing" and inputs.strong_accounts["ADM-web01"].type == "vault"


def test_policy_names_per_row(tmp_path):
    hdr = "fqdn,strong_account,group,policy_name,policy_suffix\n"
    make_inputs(tmp_path, "web01.corp.local,SA1,G,,\nweb01.corp.local,SA1,G2,,-ops\nweb01.dmz.local,SA1,G,,\n", "SA1,existing,,,,,\n", servers_hdr=hdr)
    inputs = load_inputs(tmp_path)
    assert [effective_policy_name("{fqdn}", s.fqdn, s.dns_domain, s.policy_name, s.policy_suffix) for s in inputs.servers] == [
        "web01.corp.local", "web01.corp.local-ops", "web01.dmz.local"]
    assert [s.fqdn for s in inputs.target_rows] == ["web01.corp.local", "web01.dmz.local"]
    with pytest.raises(InputError, match=r"collides with line 2 \(web01.corp.local\); use \{fqdn\}"):
        load_inputs(tmp_path, policy_name_template="{hostname}")   # the DMZ host collides with the corp host
    with pytest.raises(InputError, match="policy_name_template '{host}' is invalid"):
        load_inputs(tmp_path, policy_name_template="{host}")
    make_inputs(tmp_path, "web01.corp.local,SA1,G,Custom,-ignored\n", "SA1,existing,,,,,\n", servers_hdr=hdr)
    inputs = load_inputs(tmp_path)
    assert inputs.servers[0].policy_suffix is None and any("policy_suffix '-ignored' ignored" in w for w in inputs.warnings)
    assert effective_policy_name("SIA-RDP-{hostname}", "a.b.c", "b.c", None, None) == "SIA-RDP-a"


def test_domain_joined_and_address_columns(tmp_path):
    hdr = "fqdn,strong_account,group,domain_joined\n"
    make_inputs(tmp_path, "a.b.c,SA1,G,no\nd.b.c,SA1,G,YES\ne.b.c,SA1,G,\n", "SA1,existing,,,,,\n", servers_hdr=hdr)
    inputs = load_inputs(tmp_path)
    assert [s.domain_joined for s in inputs.servers] == [False, True, True]
    make_inputs(tmp_path, "a.b.c,SA1,G,maybe\n", "SA1,existing,,,,,\n", servers_hdr=hdr)
    with pytest.raises(InputError, match="domain_joined must be yes or no"):
        load_inputs(tmp_path)
    (tmp_path / "servers.csv").write_text("fqdn,strong_account,group\na.b.c,SA1,G\n", encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text("name,type,safe,account_name,username,address\nSA1,vault,S,acc,svc,corp.local\n", encoding="utf-8")
    assert load_inputs(tmp_path).strong_accounts["SA1"].address == "corp.local"
    (tmp_path / "strong_accounts.csv").write_text("name,type,address\nSA1,existing,corp.local\n", encoding="utf-8")
    with pytest.raises(InputError, match="must not set"):
        load_inputs(tmp_path)
