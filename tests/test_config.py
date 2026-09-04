import os
from pathlib import Path

import pytest

from sia.config import ConfigError, env_var_for_password, load_config, load_dotenv, load_password_file
from sia.redact import redact

ROOT = Path(__file__).resolve().parents[1]

TENANT = '[tenant]\nsubdomain = "acme"\nidentity_url = "https://abc1234.id.cyberark.cloud"\n'
REQUIRED_DEFAULTS = 'days_of_week = [0, 1, 2, 3, 4, 5, 6]\nfrom_hour = ""\nto_hour = ""\ntarget_set_cert_validation = false\n'


def make(tmp_path: Path, defaults_extra: str = "", other_sections: str = "", defaults: str = REQUIRED_DEFAULTS) -> Path:
    p = tmp_path / "config.toml"
    p.write_text(TENANT + "\n[defaults]\n" + defaults + defaults_extra + "\n" + other_sections, encoding="utf-8")
    return p


def test_example_config_loads():
    cfg = load_config(ROOT / "config.example.toml")
    assert cfg.tenant.dpa_url == "https://acme.dpa.cyberark.cloud"
    assert cfg.tenant.uap_url == "https://acme.uap.cyberark.cloud"
    assert cfg.tenant.portal_url == "https://acme.cyberark.cloud"
    assert cfg.defaults.policy_name_template == "{fqdn}"
    assert cfg.defaults.assign_local_groups == ("Administrators",)
    assert cfg.defaults.owner_tag == "sia-policy-automation"
    assert cfg.defaults.max_session_hours == 2 and cfg.defaults.idle_minutes == 10 and cfg.defaults.enable_reconnect is False
    assert cfg.auth.identity_auth == "platform_token" and cfg.auth.oidc_application == "__idaptive_cybr_user_oidc"
    assert cfg.auth.password_file == "" and cfg.defaults.ssh_username == ""
    spec = cfg.defaults.strong_account_spec
    assert cfg.defaults.strong_account_template == "ADM-{hostname}" and cfg.defaults.strong_account_type == "vault"
    assert spec is not None and (spec.name, spec.type, spec.safe, spec.account_name, spec.username, spec.account_domain) == (
        "ADM-{hostname}", "vault", "SIA-LocalAdmins", "{hostname}-Administrator", "Administrator", "local")
    assert cfg.http.max_retries == 4 and cfg.http.status_polls == 1
    assert cfg.http.max_requests_per_second == 0 and cfg.http.lookup_search_max_rows == 2000
    assert cfg.http.secrets_api == "auto" and cfg.http.targetsets_api == "auto"
    assert cfg.defaults.description_template == "Automated: {protocol} ZSP access to {fqdn}"
    assert cfg.connect.login_suffix == "" and cfg.connect.gateway_host == "" and cfg.connect.network == ""
    assert cfg.pvwa.enabled is False and cfg.pvwa.platform_id == "WinServerLocal" and cfg.pvwa.cpm_managed is True


def test_minimal_config_uses_defaults(tmp_path):
    cfg = load_config(make(tmp_path))
    assert cfg.defaults.time_zone == "GMT" and cfg.defaults.max_session_hours == 2
    assert cfg.defaults.days_of_week == (0, 1, 2, 3, 4, 5, 6) and cfg.defaults.target_set_cert_validation is False
    assert cfg.defaults.strong_account_spec is None and cfg.defaults.policy_name_template == "{fqdn}"
    assert cfg.pvwa.enabled is False


def test_access_window_and_cert_validation_must_be_explicit(tmp_path):
    with pytest.raises(ConfigError, match="must set days_of_week, from_hour, to_hour, target_set_cert_validation explicitly"):
        load_config(make(tmp_path, defaults=""))
    with pytest.raises(ConfigError, match="must set target_set_cert_validation explicitly"):
        load_config(make(tmp_path, defaults='days_of_week = [1]\nfrom_hour = ""\nto_hour = ""\n'))


REQUIRED = {"days_of_week": "[0, 1, 2, 3, 4, 5, 6]", "from_hour": '""', "to_hour": '""', "target_set_cert_validation": "false"}


def defaults_table(**overrides) -> str:
    merged = {**REQUIRED, **overrides}
    return "".join(f"{k} = {v}\n" for k, v in merged.items())


@pytest.mark.parametrize("overrides, fragment", [
    ({"from_hour": '"9:00"', "to_hour": '"17:00"'}, "HH:MM"),
    ({"from_hour": '"09:00"'}, "both be set"),
    ({"max_session_hours": "25"}, "max_session_hours"),
    ({"idle_minutes": "0"}, "idle_minutes"),
    ({"days_of_week": "[1, 7]"}, "days_of_week"),
    ({"days_of_week": "[1, 1]"}, "duplicates"),
    ({"unknown_key": "1"}, "unknown key"),
    ({"provision_format": '"eph_<session-guid>"'}, "<user>"),
    ({"policy_name_template": '"SIA-{host}"'}, "policy_name_template"),
    ({"policy_name_template": '""'}, "must not be empty"),
    ({"owner_tag": '"has space"'}, "owner_tag"),
    ({"assign_local_groups": "[]"}, "assign_local_groups"),
    ({"strong_account_template": '"ADM-{host}"'}, "strong_account_template"),
    ({"strong_account_type": '"bogus"'}, "strong_account_type must be one of"),
    ({"strong_account_type": '"vault"'}, "needs strong_account_template"),
    ({"strong_account_template": '"ADM-{hostname}"', "strong_account_type": '"vault"'}, "strong_account_safe_template"),
    ({"strong_account_template": '"ADM-{hostname}"', "strong_account_type": '"credentials"'}, "strong_account_username_template"),
    ({"strong_account_safe_template": '"{safe}"'}, "strong_account_safe_template"),
    ({"strong_account_domain": '""'}, "strong_account_domain"),
    ({"description_template": '"{proto}"'}, "description_template"),
])
def test_invalid_defaults_rejected(tmp_path, overrides, fragment):
    with pytest.raises(ConfigError, match=fragment):
        load_config(make(tmp_path, defaults=defaults_table(**overrides)))


def test_templated_strong_account_config(tmp_path):
    cfg = load_config(make(tmp_path, defaults=defaults_table(
        strong_account_template='"ADM-{hostname}"', strong_account_type='"credentials"', strong_account_username_template='"siaadmin"',
        strong_account_domain='"corp.example.com"')))
    spec = cfg.defaults.strong_account_spec
    assert spec.type == "credentials" and spec.username == "siaadmin" and spec.account_domain == "corp.example.com" and spec.safe == ""


def test_other_sections(tmp_path):
    with pytest.raises(ConfigError, match="unknown section"):
        load_config(make(tmp_path, other_sections="[other]\nx = 1\n"))
    with pytest.raises(ConfigError, match="identity_auth must be one of"):
        load_config(make(tmp_path, other_sections='[auth]\nidentity_auth = "bogus"\n'))
    with pytest.raises(ConfigError, match="oidc_application"):
        load_config(make(tmp_path, other_sections='[auth]\noidc_application = ""\n'))
    cfg = load_config(make(tmp_path, other_sections='[auth]\nidentity_auth = "service_user_oidc"\npassword_file = "/secure/pw.csv"\n'))
    assert cfg.auth.identity_auth == "service_user_oidc" and cfg.auth.password_file == "/secure/pw.csv"
    with pytest.raises(ConfigError, match="status_polls"):
        load_config(make(tmp_path, other_sections="[http]\nstatus_polls = 0\n"))
    with pytest.raises(ConfigError, match="max_requests_per_second"):
        load_config(make(tmp_path, other_sections="[http]\nmax_requests_per_second = -1\n"))
    with pytest.raises(ConfigError, match="secrets_api must be one of"):
        load_config(make(tmp_path, other_sections='[http]\nsecrets_api = "v3"\n'))
    with pytest.raises(ConfigError, match="targetsets_api must be one of"):
        load_config(make(tmp_path, other_sections='[http]\ntargetsets_api = "old"\n'))
    with pytest.raises(ConfigError, match="lookup_search_max_rows"):
        load_config(make(tmp_path, other_sections="[http]\nlookup_search_max_rows = -5\n"))
    cfg = load_config(make(tmp_path, other_sections='[http]\nmax_requests_per_second = 12.5\nsecrets_api = "public"\ntargetsets_api = "discovery"\n'))
    assert cfg.http.max_requests_per_second == 12.5 and cfg.http.secrets_api == "public" and cfg.http.targetsets_api == "discovery"


def test_connect_and_pvwa_sections(tmp_path):
    cfg = load_config(make(tmp_path, other_sections='[connect]\nlogin_suffix = "acme.cyberark.cloud"\ngateway_host = "acme.rdp.cyberark.cloud"\nnetwork = "dc1"\n'
                                                    '[pvwa]\nbase_url = "https://pvwa.corp.example.com"\nauth_type = "ldap"\nplatform_id = "WinLocal"\ncpm_managed = false\n'))
    assert cfg.connect.login_suffix == "acme.cyberark.cloud" and cfg.connect.gateway_host == "acme.rdp.cyberark.cloud" and cfg.connect.network == "dc1"
    assert cfg.pvwa.enabled and cfg.pvwa.base_url == "https://pvwa.corp.example.com" and cfg.pvwa.auth_type == "ldap"
    assert cfg.pvwa.platform_id == "WinLocal" and cfg.pvwa.cpm_managed is False
    with pytest.raises(ConfigError, match=r"\[pvwa\] base_url"):
        load_config(make(tmp_path, other_sections='[pvwa]\nbase_url = "http://pvwa/"\n'))
    with pytest.raises(ConfigError, match="auth_type"):
        load_config(make(tmp_path, other_sections='[pvwa]\nbase_url = "https://pvwa"\nauth_type = "radius"\n'))
    with pytest.raises(ConfigError, match="platform_id"):
        load_config(make(tmp_path, other_sections='[pvwa]\nplatform_id = ""\n'))
    with pytest.raises(ConfigError, match="gateway_host"):
        load_config(make(tmp_path, other_sections='[connect]\ngateway_host = "https://x/"\n'))
    with pytest.raises(ConfigError, match="login_suffix"):
        load_config(make(tmp_path, other_sections='[connect]\nlogin_suffix = "@acme"\n'))


def test_bad_subdomain_rejected(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text('[tenant]\nsubdomain = "acme.cyberark.cloud"\nidentity_url = "https://x.id.cyberark.cloud"\n[defaults]\n' + REQUIRED_DEFAULTS)
    with pytest.raises(ConfigError, match="subdomain"):
        load_config(p)


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.toml")


def test_dotenv_parsing(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text(
        "# comment\n\nSIA_CLIENT_ID=svc@acme.cyberark.cloud\nexport SIA_CLIENT_SECRET='p@ss word'\n"
        'QUOTED="a=b"\nINLINE=value # trailing comment\n',
        encoding="utf-8",
    )
    for key in ("SIA_CLIENT_ID", "SIA_CLIENT_SECRET", "QUOTED", "INLINE"):
        monkeypatch.delenv(key, raising=False)
    loaded = load_dotenv(env)
    assert loaded == {"SIA_CLIENT_ID": "svc@acme.cyberark.cloud", "SIA_CLIENT_SECRET": "p@ss word",
                      "QUOTED": "a=b", "INLINE": "value"}
    assert os.environ["SIA_CLIENT_SECRET"] == "p@ss word"


def test_dotenv_does_not_override_existing(tmp_path, monkeypatch):
    monkeypatch.setenv("SIA_CLIENT_ID", "from-shell")
    (tmp_path / ".env").write_text("SIA_CLIENT_ID=from-file\n", encoding="utf-8")
    load_dotenv(tmp_path / ".env")
    assert os.environ["SIA_CLIENT_ID"] == "from-shell"


def test_dotenv_missing_file_ok(tmp_path):
    assert load_dotenv(tmp_path / ".env") == {}


def test_dotenv_bad_line(tmp_path):
    (tmp_path / ".env").write_text("not a pair\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="KEY=VALUE"):
        load_dotenv(tmp_path / ".env")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_dotenv_permission_warning(tmp_path, caplog):
    env = tmp_path / ".env"
    env.write_text("X_TEST_KEY=1\n", encoding="utf-8")
    env.chmod(0o644)
    with caplog.at_level("WARNING", logger="sia.config"):
        load_dotenv(env)
    assert "readable by other users" in caplog.text and "chmod 600" in caplog.text
    caplog.clear()
    env.chmod(0o600)
    with caplog.at_level("WARNING", logger="sia.config"):
        load_dotenv(env)
    assert "readable by other users" not in caplog.text


def test_env_var_for_password():
    assert env_var_for_password("SA-dmz localadmin") == "SIA_SA_SA_DMZ_LOCALADMIN_PASSWORD"
    assert env_var_for_password("svc_rdp") == "SIA_SA_SVC_RDP_PASSWORD"


def test_password_file(tmp_path, caplog):
    pw = tmp_path / "passwords.csv"
    pw.write_text("name,password\nSA-dmz,s3cret-value\n\nSA-other,\"with,comma\"\n", encoding="utf-8")
    pw.chmod(0o600)
    loaded = load_password_file(pw)
    assert loaded == {"SA-dmz": "s3cret-value", "SA-other": "with,comma"}
    assert redact("leak s3cret-value") == "leak ***"
    pw.write_text("name,password\nSA-dmz,a\nSA-dmz,b\nSA-x,\n", encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        load_password_file(pw)
    assert "duplicate name 'SA-dmz'" in str(exc.value) and "password for 'SA-x' is empty" in str(exc.value)
    pw.write_text("account,secret\nSA-dmz,a\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="name,password"):
        load_password_file(pw)
    with pytest.raises(ConfigError, match="not found"):
        load_password_file(tmp_path / "missing.csv")
    if os.name != "nt":
        pw.write_text("name,password\nSA-dmz,a\n", encoding="utf-8")
        pw.chmod(0o644)
        with caplog.at_level("WARNING", logger="sia.config"):
            load_password_file(pw)
        assert "readable by other users" in caplog.text


def test_group_template_and_target_set_scope(tmp_path):
    cfg = load_config(make(tmp_path, 'group_template = "SIA-{hostname_upper}-RDP"\ntarget_set_scope = "auto"\n'))
    assert cfg.defaults.group_template == "SIA-{hostname_upper}-RDP" and cfg.defaults.target_set_scope == "auto"
    assert load_config(make(tmp_path)).defaults.target_set_scope == "server"      # unchanged default
    assert load_config(make(tmp_path)).defaults.group_template == ""


@pytest.mark.parametrize("defaults_extra, fragment", [
    ('target_set_scope = "everything"\n', "target_set_scope must be one of"),
    ('group_template = "SIA-{server}"\n', "group_template may only use"),
    ('strong_account_domain = "{nope}"\n', "strong_account_domain may only use"),
])
def test_new_defaults_validation(tmp_path, defaults_extra, fragment):
    with pytest.raises(ConfigError, match=fragment):
        load_config(make(tmp_path, defaults_extra))


def test_ca_bundle_and_verify(tmp_path):
    bundle = tmp_path / "corp-ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    assert load_config(make(tmp_path)).http.tls_verify is True                    # default: certifi
    assert load_config(make(tmp_path, other_sections=f'[http]\nca_bundle = "{bundle}"\n')).http.tls_verify == str(bundle)
    assert load_config(make(tmp_path, other_sections="[http]\nverify = false\n")).http.tls_verify is False
    with pytest.raises(ConfigError, match="does not exist"):
        load_config(make(tmp_path, other_sections='[http]\nca_bundle = "/no/such/bundle.pem"\n'))
    with pytest.raises(ConfigError, match="verify = false; pick one"):
        load_config(make(tmp_path, other_sections=f'[http]\nca_bundle = "{bundle}"\nverify = false\n'))


def test_policy_status(tmp_path):
    assert load_config(make(tmp_path)).defaults.policy_status == "Active"
    assert load_config(make(tmp_path, 'policy_status = "Suspended"\n')).defaults.policy_status == "Suspended"
    with pytest.raises(ConfigError, match="policy_status must be one of Active, Suspended"):
        load_config(make(tmp_path, 'policy_status = "Validating"\n'))
