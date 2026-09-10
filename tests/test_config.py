import codecs
import os
from pathlib import Path

import pytest

from sia.config import (ConfigError, ConfigValidationError, env_var_for_password, load_config, load_dotenv,
                        load_password_file, read_dotenv, resolve_env, suggest_https_base_url, toml_error_hint)
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
    assert cfg.http.max_retries == 4 and cfg.http.status_polls == 5
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
    ({"principal_type": '"user"'}, "principal_type must be one of role, group"),
    ({"group_template": '""'}, r"unknown key\(s\): group_template \('group_template' was renamed to 'principal_template'"),
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
    secure = tmp_path / "secure" / "pw.csv"     # an absolute path on every platform; TOML basic strings want forward slashes
    cfg = load_config(make(tmp_path, other_sections=f'[auth]\nidentity_auth = "service_user_oidc"\npassword_file = "{secure.as_posix()}"\n'))
    assert cfg.auth.identity_auth == "service_user_oidc" and cfg.auth.password_file == str(secure)
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


def test_subdomain_and_connection_components_reject_injection(tmp_path):
    with pytest.raises(ConfigError, match="subdomain"):
        load_config(_write_config(tmp_path / "bad-subdomain.toml", 'subdomain = "acme-"'))
    for setting in (
        'gateway_host = "good.example\\nredirectclipboard:i:1"',
        'login_suffix = "good.example\\npromptcredentialonce:i:0"',
        'network = "net\\npromptcredentialonce:i:0"',
        'network = "net /d local"',
    ):
        with pytest.raises(ConfigError, match=r"\[connect\]"):
            load_config(make(tmp_path, other_sections=f"[connect]\n{setting}\n"))


def _write_config(path: Path, tenant_subdomain_line: str) -> Path:
    path.write_text('[tenant]\n' + tenant_subdomain_line
                    + '\nidentity_url = "https://abc.id.cyberark.cloud"\n[defaults]\n' + REQUIRED_DEFAULTS,
                    encoding="utf-8")
    return path


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
        # Register an undo value even when the real process variable was
        # initially absent; load_dotenv mutates os.environ outside monkeypatch.
        monkeypatch.setenv(key, "test-placeholder")
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


def test_dotenv_rejects_nonregular_path_instead_of_treating_it_as_missing(tmp_path):
    directory = tmp_path / "credentials"
    directory.mkdir()
    with pytest.raises(ConfigError, match="must be a regular file"):
        read_dotenv(directory)

    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "credentials.pipe"
        os.mkfifo(fifo)
        with pytest.raises(ConfigError, match="must be a regular file"):
            read_dotenv(fifo)


def test_dotenv_rejects_broken_symlink(tmp_path):
    path = tmp_path / ".env"
    try:
        path.symlink_to(tmp_path / "missing-target")
    except OSError:
        pytest.skip("Symlinks are unavailable on this system")
    with pytest.raises(ConfigError, match="broken symbolic link"):
        read_dotenv(path)


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


def test_principal_template_and_target_set_scope(tmp_path):
    cfg = load_config(make(tmp_path, 'principal_template = "SIA-{hostname_upper}-RDP"\ntarget_set_scope = "auto"\n'))
    assert cfg.defaults.principal_template == "SIA-{hostname_upper}-RDP" and cfg.defaults.target_set_scope == "auto"
    assert load_config(make(tmp_path)).defaults.target_set_scope == "server"      # unchanged default
    assert load_config(make(tmp_path)).defaults.principal_template == ""
    assert load_config(make(tmp_path)).defaults.principal_type == "role"                       # roles by default
    assert load_config(make(tmp_path, 'principal_type = "group"\n')).defaults.principal_type == "group"


@pytest.mark.parametrize("defaults_extra, fragment", [
    ('target_set_scope = "everything"\n', "target_set_scope must be one of"),
    ('principal_template = "SIA-{server}"\n', "principal_template may only use"),
    ('strong_account_domain = "{nope}"\n', "strong_account_domain may only use"),
])
def test_new_defaults_validation(tmp_path, defaults_extra, fragment):
    with pytest.raises(ConfigError, match=fragment):
        load_config(make(tmp_path, defaults_extra))


def test_ca_bundle_and_verify(tmp_path):
    bundle = tmp_path / "corp-ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    assert load_config(make(tmp_path)).http.tls_verify is True                    # default: certifi
    assert load_config(make(tmp_path, other_sections=f'[http]\nca_bundle = "{bundle.as_posix()}"\n')).http.tls_verify == str(bundle)
    assert load_config(make(tmp_path, other_sections="[http]\nverify = false\n")).http.tls_verify is False
    with pytest.raises(ConfigError, match="does not exist"):
        load_config(make(tmp_path, other_sections='[http]\nca_bundle = "/no/such/bundle.pem"\n'))
    with pytest.raises(ConfigError, match="verify = false; pick one"):
        load_config(make(tmp_path, other_sections=f'[http]\nca_bundle = "{bundle.as_posix()}"\nverify = false\n'))


def test_windows_path_in_a_quoted_value_explains_itself(tmp_path):
    """Pasting C:\\certs\\ca.pem into a double-quoted TOML value is the usual Windows first attempt."""
    with pytest.raises(ConfigError, match="forward slashes") as caught:
        load_config(make(tmp_path, other_sections='[http]\nca_bundle = "C:\\certs\\corp-root.pem"\n'))
    assert "invalid TOML" in str(caught.value)
    # a single-quoted (literal) Windows path parses, so the hint must not fire for it
    cfg_text = "[http]\nca_bundle = 'C:\\certs\\corp-root.pem'\n"
    assert toml_error_hint(cfg_text) == ""
    # and a valid config never triggers the hint either
    assert toml_error_hint('[http]\nca_bundle = "C:/certs/corp-root.pem"\n') == ""


def test_trust_source_precedence(tmp_path):
    """Explicit settings win: verify = false, then ca_bundle, then the system trust store."""
    bundle = tmp_path / "corp-ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    assert load_config(make(tmp_path)).http.system_trust is True                  # on by default
    assert load_config(make(tmp_path)).http.trust_source == "system"
    assert load_config(make(tmp_path, other_sections="[http]\nsystem_trust = false\n")).http.trust_source == "certifi"
    # a bundle is an explicit choice, so it wins over the system store without an error
    both = load_config(make(tmp_path, other_sections=f'[http]\nca_bundle = "{bundle.as_posix()}"\nsystem_trust = true\n'))
    assert both.http.trust_source == "ca_bundle" and both.http.tls_verify == str(bundle)
    off = load_config(make(tmp_path, other_sections="[http]\nverify = false\nsystem_trust = true\n"))
    assert off.http.trust_source == "disabled" and off.http.tls_verify is False


def test_policy_status(tmp_path):
    assert load_config(make(tmp_path)).defaults.policy_status == "Active"
    assert load_config(make(tmp_path, 'policy_status = "Suspended"\n')).defaults.policy_status == "Suspended"
    with pytest.raises(ConfigError, match="policy_status must be one of Active, Suspended"):
        load_config(make(tmp_path, 'policy_status = "Validating"\n'))


@pytest.mark.parametrize("section, setting, fragment", [
    ("http", 'verify = "false"', "verify must be a boolean"),
    ("http", "timeout_seconds = true", "timeout_seconds must be an integer"),
    ("http", "max_requests_per_second = false", "max_requests_per_second must be a number"),
    ("defaults", 'days_of_week = [0, "1"]', "days_of_week must be a list of integers"),
    ("defaults", 'policy_tags = "automated"', "policy_tags must be a list of strings"),
    ("pvwa", 'cpm_managed = 1', "cpm_managed must be a boolean"),
])
def test_config_types_are_strict(tmp_path, section, setting, fragment):
    if section == "defaults":
        key, value = setting.split("=", 1)
        key = key.strip()
        path = (make(tmp_path, defaults=defaults_table(**{key: value.strip()})) if key in REQUIRED
                else make(tmp_path, defaults_extra=setting + "\n"))
    else:
        path = make(tmp_path, other_sections=f"[{section}]\n{setting}\n")
    with pytest.raises(ConfigError, match=fragment):
        load_config(path)


def test_urls_time_zone_and_stray_template_braces_are_validated(tmp_path):
    with pytest.raises(ConfigError, match="recognized IANA time zone"):
        load_config(make(tmp_path, 'time_zone = "Central-ish"\n'))
    with pytest.raises(ConfigError, match="no path"):
        load_config(make(tmp_path, other_sections='[pvwa]\nbase_url = "https://pvwa.example/path"\n'))
    with pytest.raises(ConfigError, match="not a valid URL"):
        load_config(make(tmp_path, other_sections='[pvwa]\nbase_url = "https://[broken"\n'))
    with pytest.raises(ConfigError, match="whitespace or control characters"):
        load_config(make(tmp_path, other_sections='[pvwa]\nbase_url = "https://bad host:443"\n'))
    with pytest.raises(ConfigError, match="control characters"):
        load_config(make(tmp_path, other_sections='[pvwa]\nbase_url = "https://good.example\\nignored.example"\n'))
    assert load_config(make(tmp_path, other_sections='[pvwa]\nbase_url = "https://pvwa:8443"\n')).pvwa.enabled
    with pytest.raises(ConfigError, match="not a valid template"):
        load_config(make(tmp_path, 'principal_template = "SIA-{hostname}}"\n'))


def test_config_relative_file_paths_resolve_beside_config(tmp_path):
    config_dir = tmp_path / "project"
    config_dir.mkdir()
    (config_dir / "certs").mkdir()
    config_path = config_dir / "config.toml"
    config_path.write_text(
        TENANT + "\n[defaults]\n" + REQUIRED_DEFAULTS
        + '\n[auth]\npassword_file = "private/passwords.csv"\n'
        + '\n[http]\nca_bundle = "certs"\n', encoding="utf-8")
    cfg = load_config(config_path)
    assert cfg.auth.password_file == str(config_dir / "private" / "passwords.csv")
    assert cfg.http.ca_bundle == str(config_dir / "certs")


def test_read_dotenv_is_non_mutating_and_reports_source(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text('ONLY_FILE="value with spaces"\nSHARED=from-file\n', encoding="utf-8")
    monkeypatch.delenv("ONLY_FILE", raising=False)
    monkeypatch.setenv("SHARED", "from-shell")
    values = read_dotenv(env)
    assert values["ONLY_FILE"] == "value with spaces"
    assert "ONLY_FILE" not in os.environ
    assert resolve_env("ONLY_FILE", values).source == "dotenv"
    assert resolve_env("SHARED", values).value == "from-shell"
    assert resolve_env("SHARED", values).source == "environment"
    assert resolve_env("ABSENT", values).source == "missing"


def test_dotenv_rejects_duplicates_and_bad_quotes(tmp_path):
    env = tmp_path / ".env"
    env.write_text("KEY=first\nKEY=second\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="duplicate key 'KEY'.*line 1"):
        read_dotenv(env)
    env.write_text('KEY="unterminated\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="unterminated double-quoted"):
        read_dotenv(env)
    env.write_text("KEY='ok' unexpected\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="text after the closing"):
        read_dotenv(env)


def test_password_file_rejects_duplicate_and_blank_headers(tmp_path):
    password_file = tmp_path / "passwords.csv"
    password_file.write_text("name,password,password\na,b,c\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="duplicate column"):
        load_password_file(password_file)
    password_file.write_text("name,,password\na,b,c\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="blank column"):
        load_password_file(password_file)
    password_file.write_text('name,password\nSA-one,"unterminated\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid CSV"):
        load_password_file(password_file)


def test_validation_collects_all_issues_with_repair_keys(tmp_path):
    path = make(
        tmp_path,
        defaults=defaults_table(from_hour='"9:00"', to_hour='""', max_session_hours="25", idle_minutes="0"),
    )
    text = path.read_text(encoding="utf-8").replace('subdomain = "acme"', 'subdomain = "Bad."')
    text = text.replace(
        'identity_url = "https://abc1234.id.cyberark.cloud"',
        'identity_url = "https://abc1234.id.cyberark.cloud/path"',
    )
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigValidationError) as caught:
        load_config(path)
    keys = {key for issue in caught.value.issues for key in issue.dotted_keys}
    assert {"tenant.subdomain", "tenant.identity_url", "defaults.from_hour",
            "defaults.to_hour", "defaults.max_session_hours", "defaults.idle_minutes"} <= keys
    assert len(caught.value.issues) >= 5


@pytest.mark.parametrize("raw, expected", [
    ("tenant.id.cyberark.cloud", "https://tenant.id.cyberark.cloud"),
    ("http://tenant.id.cyberark.cloud/", "https://tenant.id.cyberark.cloud"),
    ("https://tenant.id.cyberark.cloud/path?q=1#part", "https://tenant.id.cyberark.cloud"),
    ("https://tenant.id.cyberark.cloud:8443/", "https://tenant.id.cyberark.cloud:8443"),
])
def test_safe_https_base_url_suggestions_preserve_authority(raw, expected):
    assert suggest_https_base_url(raw) == expected


@pytest.mark.parametrize("raw", [
    "https://user:password@tenant.example",
    "https://bad host.example",
    "ftp://tenant.example",
    "https://tenant.example:0",
    "https://tenant.example:70000",
])
def test_unsafe_https_base_urls_have_no_suggestion(raw):
    assert suggest_https_base_url(raw) is None


@pytest.mark.parametrize("url", [
    "https://tenant.id.cyberark.cloud?",
    "https://tenant.id.cyberark.cloud#",
    "https://tenant.id.cyberark.cloud/",
    "https://tenant.id.cyberark.cloud:0",
])
def test_identity_url_rejects_empty_delimiters_trailing_slash_and_bad_port(tmp_path, url):
    path = make(tmp_path)
    path.write_text(path.read_text(encoding="utf-8").replace(
        "https://abc1234.id.cyberark.cloud", url), encoding="utf-8")
    with pytest.raises(ConfigError, match="identity_url"):
        load_config(path)


@pytest.mark.parametrize("extra, fragment", [
    ('principal_template = "{hostname!r}"\n', "conversions"),
    ('principal_template = "{hostname:>20}"\n', "format specifications"),
    ("policy_tags = [" + ", ".join(f'\"tag{i}\"' for i in range(20)) + "]\n", "maximum is 20"),
])
def test_template_operators_and_effective_tag_limit_are_rejected(tmp_path, extra, fragment):
    with pytest.raises(ConfigError, match=fragment):
        load_config(make(tmp_path, defaults_extra=extra))


def test_non_finite_numbers_and_overlong_dns_names_are_rejected(tmp_path):
    with pytest.raises(ConfigError, match="finite number"):
        load_config(make(tmp_path, other_sections="[http]\nmax_requests_per_second = nan\n"))
    with pytest.raises(ConfigError, match="finite number"):
        load_config(make(tmp_path, other_sections=f"[http]\nmax_requests_per_second = {10 ** 400}\n"))
    overlong = ".".join(["a" * 63] * 4)
    path = make(tmp_path)
    path.write_text(path.read_text(encoding="utf-8").replace(
        'identity_url = "https://abc1234.id.cyberark.cloud"',
        f'identity_url = "https://abc1234.id.cyberark.cloud"\nroot_domain = "{overlong}"'), encoding="utf-8")
    with pytest.raises(ConfigError, match="root_domain"):
        load_config(path)


def test_dotenv_treats_quotes_as_literal_so_a_backslash_needs_no_escaping(tmp_path):
    """The reported bug: quoting a credential must not reinterpret its backslashes."""
    env = tmp_path / ".env"
    for form in ('SIA_CLIENT_SECRET={}', "SIA_CLIENT_SECRET='{}'", 'SIA_CLIENT_SECRET="{}"'):
        for value in (r"p@ss\word", r"DOMAIN\svc", r"C:\Users\svc", r"abc\tdef", r"a\new", "abc\\"):
            env.write_text(form.format(value) + "\n", encoding="utf-8")
            assert read_dotenv(env)["SIA_CLIENT_SECRET"] == value, form.format(value)


def test_dotenv_doubled_quote_is_the_only_escape(tmp_path):
    env = tmp_path / ".env"
    for line, expected in [
        ('K="he said ""hi"""', 'he said "hi"'), ("K='it''s'", "it's"),
        ('K="a\'b"', "a'b"), ("K='a\"b'", 'a"b'), ('K=""', ""), ("K=''", ""),
        ('K="  padded  "', "  padded  "), ('K="v" # note', "v"),
    ]:
        env.write_text(line + "\n", encoding="utf-8")
        assert read_dotenv(env)["K"] == expected, line


def test_dotenv_warns_once_when_a_legacy_escape_is_now_literal(tmp_path, caplog):
    env = tmp_path / ".env"
    env.write_text('SIA_CLIENT_SECRET="abc\\\\def"\n', encoding="utf-8")
    with caplog.at_level("WARNING", logger="sia.config"):
        assert read_dotenv(env)["SIA_CLIENT_SECRET"] == r"abc\\def"
    assert "SIA_CLIENT_SECRET" in caplog.text and "Settings > Credentials" in caplog.text
    assert r"abc\\def" not in caplog.text
    caplog.clear()
    with caplog.at_level("WARNING", logger="sia.config"):
        read_dotenv(env)
    assert "Settings > Credentials" not in caplog.text


def test_dotenv_warns_when_an_unquoted_credential_loses_characters(tmp_path, caplog):
    truncated = tmp_path / "truncated.env"
    truncated.write_text("SIA_CLIENT_SECRET=abc #def\n", encoding="utf-8")
    with caplog.at_level("WARNING", logger="sia.config"):
        assert read_dotenv(truncated)["SIA_CLIENT_SECRET"] == "abc"
    assert "read as a comment" in caplog.text and "abc #def" not in caplog.text

    caplog.clear()
    padded = tmp_path / "padded.env"
    padded.write_text("SIA_CLIENT_SECRET=  abc  \n", encoding="utf-8")
    with caplog.at_level("WARNING", logger="sia.config"):
        assert read_dotenv(padded)["SIA_CLIENT_SECRET"] == "abc"
    assert "spaces around its value were removed" in caplog.text

    caplog.clear()
    quoted = tmp_path / "quoted.env"
    quoted.write_text("SIA_CLIENT_SECRET='  abc  '\n", encoding="utf-8")
    with caplog.at_level("WARNING", logger="sia.config"):
        assert read_dotenv(quoted)["SIA_CLIENT_SECRET"] == "  abc  "
    assert "spaces around" not in caplog.text


def test_dotenv_relaxed_mode_keeps_syntax_checks_but_tolerates_undecodable_values(tmp_path):
    env = tmp_path / ".env"
    env.write_text('OTHER="ok" then junk\nKEY=fine\n', encoding="utf-8")
    assert read_dotenv(env, strict=False)["KEY"] == "fine"
    env.write_text('KEY="unterminated\n', encoding="utf-8")
    assert read_dotenv(env, strict=False)["KEY"] == '"unterminated'
    env.write_text("KEY=1\nKEY=2\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="duplicate key"):
        read_dotenv(env, strict=False)
    env.write_text("not a pair\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="KEY=VALUE"):
        read_dotenv(env, strict=False)


def test_dotenv_and_config_accept_a_notepad_byte_order_mark(tmp_path):
    env = tmp_path / ".env"
    env.write_bytes("\ufeffSIA_CLIENT_ID=svc@acme\nSIA_CLIENT_SECRET=pw\n".encode("utf-8"))
    assert read_dotenv(env) == {"SIA_CLIENT_ID": "svc@acme", "SIA_CLIENT_SECRET": "pw"}
    config = tmp_path / "config.toml"
    config.write_bytes(("\ufeff" + TENANT + "\n[defaults]\n" + REQUIRED_DEFAULTS).encode("utf-8"))
    assert load_config(config).tenant.subdomain == "acme"


def test_dotenv_and_config_name_the_fix_for_powershell_utf16(tmp_path):
    env = tmp_path / ".env"
    env.write_bytes("SIA_CLIENT_ID=svc\n".encode("utf-16"))
    with pytest.raises(ConfigError, match="UTF-16 text and SIA reads UTF-8.*Set-Content -Encoding utf8"):
        read_dotenv(env)
    config = tmp_path / "config.toml"
    config.write_bytes(codecs.BOM_UTF16_BE + (TENANT + "\n[defaults]\n" + REQUIRED_DEFAULTS).encode("utf-16-be"))
    with pytest.raises(ConfigError, match="UTF-16 text and SIA reads UTF-8"):
        load_config(config)
