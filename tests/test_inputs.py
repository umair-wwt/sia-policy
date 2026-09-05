from pathlib import Path

import pytest

from sia.config import StrongAccountTemplate
from sia.inputs import InputError, effective_policy_name, inline_inputs, load_inputs

ROOT = Path(__file__).resolve().parents[1]

SERVERS_HDR = "fqdn,strong_account,group,policy_name,assign_groups,domain,description\n"
ACCOUNTS_HDR = "name,type,safe,account_name,username,account_domain,password_env\n"
VAULT_SPEC = StrongAccountTemplate(name="ADM-{hostname}", type="vault", safe="SIA-LocalAdmins",
                                   account_name="{hostname}-Administrator", username="Administrator")


DOMAINS_HDR = "domain,strong_account,target_set,target_set_type,group_template\n"


def make_inputs(tmp_path: Path, servers: str, accounts: str, groups: str | None = None, servers_hdr: str = SERVERS_HDR,
                domains: str | None = None) -> Path:
    (tmp_path / "servers.csv").write_text(servers_hdr + servers, encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text(ACCOUNTS_HDR + accounts, encoding="utf-8")
    if groups is not None:
        (tmp_path / "groups.csv").write_text("name,directory\n" + groups, encoding="utf-8")
    if domains is not None:
        (tmp_path / "domains.csv").write_text(DOMAINS_HDR + domains, encoding="utf-8")
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


def test_unknown_column(tmp_path):
    """`group` is optional now (group_template can derive it), so a typo is caught as an unknown column."""
    (tmp_path / "servers.csv").write_text("fqdn,strong_account,groups\n", encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text("name,type\n", encoding="utf-8")
    with pytest.raises(InputError) as exc:
        load_inputs(tmp_path)
    assert "unknown column(s): groups" in str(exc.value)


def test_missing_required_column(tmp_path):
    (tmp_path / "servers.csv").write_text("strong_account,group\n", encoding="utf-8")
    (tmp_path / "strong_accounts.csv").write_text("name,type\n", encoding="utf-8")
    with pytest.raises(InputError, match=r"missing required column\(s\): fqdn"):
        load_inputs(tmp_path)


def test_missing_files(tmp_path):
    with pytest.raises(InputError, match="servers.csv.*not found"):
        load_inputs(tmp_path)


def test_servers_csv_requires_data_and_unambiguous_headers(tmp_path):
    (tmp_path / "servers.csv").write_text("fqdn,strong_account,group\n", encoding="utf-8")
    with pytest.raises(InputError, match="no data rows found"):
        load_inputs(tmp_path)
    (tmp_path / "servers.csv").write_text("fqdn,group,group\na.b.c,G,G2\n", encoding="utf-8")
    with pytest.raises(InputError, match="duplicate column.*group"):
        load_inputs(tmp_path)
    (tmp_path / "servers.csv").write_text("fqdn,,group\na.b.c,SA1,G\n", encoding="utf-8")
    with pytest.raises(InputError, match="blank column name"):
        load_inputs(tmp_path)


def test_malformed_csv_has_file_and_line(tmp_path):
    (tmp_path / "servers.csv").write_text('fqdn,strong_account,group\n"a.b.c,SA1,G\n', encoding="utf-8")
    with pytest.raises(InputError, match=r"servers\.csv:\d+: invalid CSV"):
        load_inputs(tmp_path)
    (tmp_path / "servers.csv").write_bytes(b"fqdn,strong_account,group\na.b.c,SA1,\xff\n")
    with pytest.raises(InputError, match="must be UTF-8"):
        load_inputs(tmp_path)


def test_groups_csv_duplicates(tmp_path):
    make_inputs(tmp_path, "a.b.c,SA1,G\n", "SA1,existing,,,,,\n", groups="G,\nG,CyberArk Cloud Directory\n")
    with pytest.raises(InputError, match="duplicate group"):
        load_inputs(tmp_path)


def test_password_env_names_and_collisions_are_rejected(tmp_path):
    make_inputs(tmp_path, "a.b.c,SA-one,G\nd.b.c,SA-two,G\n",
                "SA-one,credentials,,,admin,,BAD-NAME\nSA-two,credentials,,,admin,,BAD-NAME\n")
    with pytest.raises(InputError) as exc:
        load_inputs(tmp_path)
    assert "not a valid environment variable name" in str(exc.value)
    (tmp_path / "strong_accounts.csv").write_text(
        ACCOUNTS_HDR + "SA-one,credentials,,,admin,,SHARED_PASSWORD\n"
        + "SA-two,credentials,,,admin,,shared_password\n", encoding="utf-8")
    with pytest.raises(InputError, match="collides with account 'SA-one'"):
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


# --------------------------------------------------------------------------- domains.csv, group and target-set scope

SERVERS_MIN = "fqdn,strong_account,group,domain_joined\n"


def test_domains_csv_supplies_group_strong_account_and_target_set(tmp_path):
    """The client's model: one row per server, everything else derived from its AD domain."""
    path = make_inputs(
        tmp_path,
        "web01.corp.example.com,,,\nweb02.corp.example.com,,,\napp01.lab.example.com,,,\n", "",
        servers_hdr=SERVERS_MIN,
        domains="corp.example.com,SA-CORP-SIA,,Domain,\nlab.example.com,SA-LAB-SIA,,Domain,SIA-{hostname_upper}-LAB\n")
    inputs = load_inputs(path, group_template="SIA-{hostname_upper}-RDP", target_set_scope="auto")
    web01, web02, app01 = inputs.servers
    assert web01.groups == ("SIA-WEB01-RDP",) and web02.groups == ("SIA-WEB02-RDP",)
    assert app01.groups == ("SIA-APP01-LAB",)                        # the domain's template wins over [defaults]
    assert web01.strong_account == web02.strong_account == "SA-CORP-SIA"
    assert app01.strong_account == "SA-LAB-SIA"
    # both corp servers share one Domain target set; the lab server has its own
    assert web01.target_set_key == web02.target_set_key == "corp.example.com"
    assert web01.target_set_type == "Domain" and web01.shares_target_set
    assert app01.target_set_key == "lab.example.com"
    # the domain accounts are declared implicitly, as pre-existing accounts scoped to their domain
    corp = inputs.strong_accounts["SA-CORP-SIA"]
    assert corp.type == "existing" and corp.account_domain == "corp.example.com" and not corp.is_local


def test_strong_accounts_csv_is_optional(tmp_path):
    """Minimum viable input: an fqdn column plus domains.csv."""
    (tmp_path / "servers.csv").write_text("fqdn\nweb01.corp.example.com\n", encoding="utf-8")
    (tmp_path / "domains.csv").write_text(DOMAINS_HDR + "corp.example.com,SA-CORP-SIA,,Domain,\n", encoding="utf-8")
    inputs = load_inputs(tmp_path, group_template="SIA-{hostname_upper}-RDP", target_set_scope="auto")
    assert inputs.servers[0].strong_account == "SA-CORP-SIA" and inputs.servers[0].groups == ("SIA-WEB01-RDP",)


def test_strong_account_precedence(tmp_path):
    """Explicit cell beats domains.csv beats the per-host template."""
    path = make_inputs(
        tmp_path,
        "web01.corp.example.com,SA-explicit,G,\nweb02.corp.example.com,,G,\nlone01.other.example.com,,G,\n",
        "SA-explicit,existing,,,,,\n", servers_hdr=SERVERS_MIN,
        domains="corp.example.com,SA-CORP-SIA,,Domain,\n")
    inputs = load_inputs(path, strong_account_template="ADM-{hostname}", target_set_scope="auto")
    explicit, from_domain, templated = inputs.servers
    assert explicit.strong_account == "SA-explicit"
    assert from_domain.strong_account == "SA-CORP-SIA"
    assert templated.strong_account == "ADM-lone01"
    # only the row that took its account from domains.csv shares that domain's target set
    assert not explicit.shares_target_set and explicit.target_set_key == "web01.corp.example.com"
    assert from_domain.shares_target_set
    assert not templated.shares_target_set


def test_workgroup_rows_keep_their_own_local_account_and_target_set(tmp_path):
    """Domain-joined and workgroup servers coexist in one file."""
    path = make_inputs(
        tmp_path, "web01.corp.example.com,,G,yes\ndmz01.corp.example.com,,G,no\n", "",
        servers_hdr=SERVERS_MIN, domains="corp.example.com,SA-CORP-SIA,,Domain,\n")
    inputs = load_inputs(path, strong_account_template="ADM-{hostname}", target_set_scope="auto")
    joined, workgroup = inputs.servers
    assert joined.strong_account == "SA-CORP-SIA" and joined.target_set_key == "corp.example.com"
    assert workgroup.strong_account == "ADM-dmz01" and workgroup.target_set_key == "dmz01.corp.example.com"
    assert workgroup.target_set_type == "Target" and not workgroup.shares_target_set
    assert inputs.strong_accounts["ADM-dmz01"].is_local


def test_target_set_scope_server_keeps_one_set_per_server(tmp_path):
    """The default: domains.csv still supplies the account, but every server gets its own Target set."""
    path = make_inputs(tmp_path, "web01.corp.example.com,,G,\nweb02.corp.example.com,,G,\n", "",
                       servers_hdr=SERVERS_MIN, domains="corp.example.com,SA-CORP-SIA,,Domain,\n")
    inputs = load_inputs(path)          # target_set_scope defaults to "server"
    assert [s.target_set_key for s in inputs.servers] == ["web01.corp.example.com", "web02.corp.example.com"]
    assert all(s.target_set_type == "Target" and not s.shares_target_set for s in inputs.servers)
    assert all(s.strong_account == "SA-CORP-SIA" for s in inputs.servers)


def test_target_set_scope_domain_requires_a_domains_row(tmp_path):
    path = make_inputs(tmp_path, "web01.nowhere.example.com,,G,\n", "", servers_hdr=SERVERS_MIN,
                       domains="corp.example.com,SA-CORP-SIA,,Domain,\n")
    with pytest.raises(InputError) as exc:
        load_inputs(path, strong_account_template="ADM-{hostname}", target_set_scope="domain")
    assert "'nowhere.example.com' has no row in domains.csv" in str(exc.value)
    # "auto" falls back to the per-host template instead of failing
    inputs = load_inputs(path, strong_account_template="ADM-{hostname}", target_set_scope="auto")
    assert inputs.servers[0].strong_account == "ADM-web01"


def test_custom_target_set_name_and_type(tmp_path):
    path = make_inputs(tmp_path, "web01.corp.example.com,,G,\n", "", servers_hdr=SERVERS_MIN,
                       domains="corp.example.com,SA-CORP-SIA,example.com,Suffix,\n")
    inputs = load_inputs(path, target_set_scope="auto")
    assert inputs.servers[0].target_set_name == "example.com" and inputs.servers[0].target_set_type == "Suffix"


def test_group_is_required_without_a_template(tmp_path):
    path = make_inputs(tmp_path, "web01.corp.example.com,SA1,,\n", "SA1,existing,,,,,\n", servers_hdr=SERVERS_MIN)
    with pytest.raises(InputError) as exc:
        load_inputs(path)
    assert "group is required" in str(exc.value) and "group_template" in str(exc.value)


def test_group_template_may_produce_several_groups(tmp_path):
    path = make_inputs(tmp_path, "web01.corp.example.com,SA1,,\n", "SA1,existing,,,,,\n", servers_hdr=SERVERS_MIN)
    inputs = load_inputs(path, group_template="SIA-{hostname}-RDP;SIA-{domain}-ALL")
    assert inputs.servers[0].groups == ("SIA-web01-RDP", "SIA-corp.example.com-ALL")


def test_explicit_group_cell_beats_the_template(tmp_path):
    path = make_inputs(tmp_path, "web01.corp.example.com,SA1,Typed-In,\n", "SA1,existing,,,,,\n", servers_hdr=SERVERS_MIN)
    assert load_inputs(path, group_template="SIA-{hostname}").servers[0].groups == ("Typed-In",)


def test_strong_account_domain_may_be_templated(tmp_path):
    """strong_account_domain = "{domain}" turns the per-host template into a per-domain one."""
    path = make_inputs(tmp_path, "web01.corp.example.com,,G,\n", "", servers_hdr=SERVERS_MIN)
    spec = StrongAccountTemplate(name="SA-{domain}", type="existing", account_domain="{domain}")
    account = load_inputs(path, strong_account_template=spec).strong_accounts["SA-corp.example.com"]
    assert account.account_domain == "corp.example.com" and not account.is_local


def test_domains_csv_validation(tmp_path):
    path = make_inputs(
        tmp_path, "web01.corp.example.com,SA1,G,\n", "SA1,existing,,,,,\n", servers_hdr=SERVERS_MIN,
        domains=("not a domain,SA-X,,Domain,\n"
                 "corp.example.com,SA-CORP,,Nonsense,\n"
                 "corp.example.com,SA-OTHER,,Domain,\n"
                 "lab.example.com,SA-LAB,shared.example.com,Domain,\n"
                 "qa.example.com,SA-QA,shared.example.com,Domain,\n"))
    with pytest.raises(InputError) as exc:
        load_inputs(path)
    text = str(exc.value)
    assert "'not a domain' is not a valid DNS name" in text
    assert "target_set_type must be one of" in text
    assert "duplicate domain 'corp.example.com'" in text
    assert "shares target set 'shared.example.com'" in text and "only hold one strong account" in text


def test_unknown_strong_account_names_domains_csv_in_the_hint(tmp_path):
    path = make_inputs(tmp_path, "web01.corp.example.com,SA-typo,G,\n", "SA1,existing,,,,,\n", servers_hdr=SERVERS_MIN)
    with pytest.raises(InputError, match="not defined in strong_accounts.csv or domains.csv"):
        load_inputs(path)


def test_rows_of_one_server_must_agree_on_their_target_set(tmp_path):
    """A second policy for the same server may not quietly land in a different target set."""
    path = make_inputs(
        tmp_path, "web01.corp.example.com,,G1,\nweb01.corp.example.com,SA-explicit,G2,\n",
        "SA-explicit,existing,,,,,\n", servers_hdr=SERVERS_MIN, domains="corp.example.com,SA-CORP-SIA,,Domain,\n")
    with pytest.raises(InputError) as exc:
        load_inputs(path, target_set_scope="auto", policy_name_template="{fqdn}-{hostname}")
    assert "strong_account" in str(exc.value) and "target set" in str(exc.value)


def test_inline_inputs_match_the_csv_path(tmp_path):
    """--server rows resolve their group, account and target set exactly as servers.csv rows would."""
    (tmp_path / "domains.csv").write_text(DOMAINS_HDR + "corp.example.com,SA-CORP-SIA,,Domain,\n", encoding="utf-8")
    inputs = inline_inputs(tmp_path, [{"fqdn": "WEB01.corp.example.com"}],
                           group_template="SIA-{hostname_upper}-RDP", target_set_scope="auto")
    row = inputs.servers[0]
    assert row.fqdn == "web01.corp.example.com" and row.groups == ("SIA-WEB01-RDP",)
    assert row.strong_account == "SA-CORP-SIA" and row.target_set_key == "corp.example.com"


def test_inline_inputs_report_problems_with_the_server_name(tmp_path):
    (tmp_path / "domains.csv").write_text(DOMAINS_HDR, encoding="utf-8")
    with pytest.raises(InputError) as exc:
        inline_inputs(tmp_path, [{"fqdn": "not-an-fqdn", "group": "G", "strong_account": "SA1"}])
    assert "--server not-an-fqdn" in str(exc.value)


def test_missing_strong_account_hint_fits_the_row(tmp_path):
    """A workgroup server can never use its domain's account, so its error must not point at domains.csv."""
    path = make_inputs(tmp_path, "web01.corp.example.com,,G,yes\ndmz01.corp.example.com,,G,no\n", "",
                       servers_hdr=SERVERS_MIN)
    with pytest.raises(InputError) as exc:
        load_inputs(path)
    joined, workgroup = str(exc.value).splitlines()
    assert "add 'corp.example.com' to domains.csv" in joined
    assert "domains.csv" not in workgroup and "strong_account_template" in workgroup


def test_a_domain_target_set_may_not_collide_with_a_server_of_its_own(tmp_path):
    """domains.csv pointing a whole domain at one host's target set must not silently retarget that host."""
    path = make_inputs(
        tmp_path, "web01.lab.example.com,,G,\njump01.lab.example.com,SA-JUMP,G,\n", "SA-JUMP,existing,,,,,\n",
        servers_hdr=SERVERS_MIN, domains="lab.example.com,SA-LAB,jump01.lab.example.com,Target,\n")
    with pytest.raises(InputError) as exc:
        load_inputs(path, target_set_scope="auto")
    text = str(exc.value)
    assert "shares target set 'jump01.lab.example.com'" in text
    assert "'SA-JUMP'" in text and "'SA-LAB'" in text and "holds exactly one strong account" in text


def test_domain_wide_target_set_may_not_be_typed_target(tmp_path):
    """A Target set scopes to one machine, so naming it after a domain would match nothing at connect time."""
    path = make_inputs(tmp_path, "web01.corp.example.com,,G,\n", "", servers_hdr=SERVERS_MIN,
                       domains="corp.example.com,SA-CORP-SIA,,Target,\n")
    with pytest.raises(InputError) as exc:
        load_inputs(path, target_set_scope="auto")
    assert "target_set_type = Target names a single machine" in str(exc.value)


def test_generated_account_name_collision_reports_conflicting_operational_fields(tmp_path):
    make_inputs(tmp_path, "web01.corp.example.com,,G\nweb02.corp.example.com,,G\n", "")
    spec = StrongAccountTemplate(
        name="SHARED", type="vault", safe="SIA", account_name="{hostname}-Administrator",
        username="Administrator", account_domain="local",
    )
    with pytest.raises(InputError) as caught:
        load_inputs(tmp_path, strong_account_template=spec)
    message = str(caught.value)
    assert "generated strong account 'SHARED' conflicts" in message
    assert "servers.csv:2" in message and "servers.csv:3" in message
    assert "account_name" in message and "address" in message


def test_identical_generated_shared_account_definition_is_allowed(tmp_path):
    make_inputs(tmp_path, "web01.corp.example.com,,G\nweb02.corp.example.com,,G\n", "")
    spec = StrongAccountTemplate(
        name="SHARED-{domain}", type="vault", safe="SIA", account_name="Domain-Administrator",
        username="Administrator", account_domain="{domain}",
    )
    inputs = load_inputs(tmp_path, strong_account_template=spec)
    assert set(inputs.strong_accounts) == {"SHARED-corp.example.com"}
    assert all(row.strong_account == "SHARED-corp.example.com" for row in inputs.servers)


def test_account_and_group_pins_are_case_insensitive(tmp_path):
    make_inputs(
        tmp_path, "web01.corp.example.com,sa-one,team-ops\n", "SA-One,existing,,,,,\n",
        groups="Team-Ops,CyberArk Cloud Directory\n",
    )
    inputs = load_inputs(tmp_path)
    assert inputs.servers[0].strong_account == "SA-One"
    assert inputs.strong_account_for(inputs.servers[0]).name == "SA-One"
    assert inputs.pinned_directory("TEAM-OPS") == "CyberArk Cloud Directory"


def test_repeated_server_rows_accept_case_variants_of_the_same_account(tmp_path):
    make_inputs(
        tmp_path,
        "web01.corp.example.com,sa-one,Team,,\nweb01.corp.example.com,SA-ONE,Other,,-ops\n",
        "SA-One,existing,,,,,\n",
        servers_hdr="fqdn,strong_account,group,policy_name,policy_suffix\n",
    )
    inputs = load_inputs(tmp_path)
    assert [row.strong_account for row in inputs.servers] == ["SA-One", "SA-One"]


def test_groups_reject_case_only_duplicates(tmp_path):
    make_inputs(tmp_path, "web01.corp.example.com,SA1,G\n", "SA1,existing,,,,,\n",
                groups="Team,CyberArk Cloud Directory\nteam,corp.example.com\n")
    with pytest.raises(InputError, match="duplicate group"):
        load_inputs(tmp_path)


def test_target_mapping_must_name_the_consuming_server_exactly(tmp_path):
    path = make_inputs(
        tmp_path, "web01.corp.example.com,,G,\n", "", servers_hdr=SERVERS_MIN,
        domains="corp.example.com,SA-CORP,other.corp.example.com,Target,\n",
    )
    with pytest.raises(InputError) as caught:
        load_inputs(path, target_set_scope="auto")
    assert "Target must name this exact server 'web01.corp.example.com'" in str(caught.value)


def test_dns_total_length_and_template_operators_are_rejected(tmp_path):
    overlong = ".".join(["a" * 63] * 4)
    make_inputs(tmp_path, f"{overlong},SA1,G\n", "SA1,existing,,,,,\n")
    with pytest.raises(InputError, match="not a valid FQDN"):
        load_inputs(tmp_path)
    make_inputs(tmp_path, "web01.corp.example.com,SA1,G\n", "SA1,existing,,,,,\n")
    with pytest.raises(InputError, match="format specifications are not supported"):
        load_inputs(tmp_path, policy_name_template="{hostname:>20}")
