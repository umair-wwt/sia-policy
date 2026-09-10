import os
from dataclasses import fields

import pytest

from sia.config import (AuthConfig, ConfigError, ConnectConfig, Defaults, HttpConfig, PVWAConfig,
                        TenantConfig, read_dotenv)
from sia.settings import (SettingsConflictError, descriptor_for, dotenv_digest, open_settings,
                          parse_setting_value, setting_descriptors, update_dotenv, validate_setting_value)


TENANT = '[tenant]\nsubdomain = "acme"\nidentity_url = "https://abc1234.id.cyberark.cloud"\n'
REQUIRED = ('[defaults]\ndays_of_week = [0, 1, 2, 3, 4, 5, 6]\nfrom_hour = ""\n'
            'to_hour = ""\ntarget_set_cert_validation = false\n')


def test_descriptor_registry_covers_every_config_field():
    descriptors = setting_descriptors()
    expected = {
        (section, item.name)
        for section, cls in (("tenant", TenantConfig), ("defaults", Defaults), ("auth", AuthConfig),
                             ("http", HttpConfig), ("connect", ConnectConfig), ("pvwa", PVWAConfig))
        for item in fields(cls)
    }
    assert {(item.section, item.key) for item in descriptors} == expected
    assert all(item.label and item.help and item.kind for item in descriptors)
    assert all(item.basic for item in setting_descriptors(include_advanced=False))
    assert descriptor_for("defaults", "policy_status").help.startswith("Status used only when a policy is created")
    with pytest.raises(ConfigError, match="unknown setting"):
        descriptor_for("bad", "key")


def test_parse_setting_value_is_typed_and_clear():
    assert parse_setting_value(descriptor_for("http", "verify"), "yes") is True
    assert parse_setting_value(descriptor_for("http", "timeout_seconds"), "30") == 30
    assert parse_setting_value(descriptor_for("http", "max_requests_per_second"), "2.5") == 2.5
    assert parse_setting_value(descriptor_for("defaults", "days_of_week"), "0, 2, 6") == [0, 2, 6]
    assert parse_setting_value(descriptor_for("defaults", "policy_tags"), '["one", "two"]') == ["one", "two"]
    assert parse_setting_value(descriptor_for("defaults", "policy_status"), "suspended") == "Suspended"
    assert parse_setting_value(descriptor_for("defaults", "principal_type"), "Group") == "group"
    with pytest.raises(ConfigError, match="must be true or false"):
        parse_setting_value(descriptor_for("http", "verify"), "perhaps")


def test_create_edit_validate_and_save_settings(tmp_path):
    path = tmp_path / "nested" / "config.toml"
    settings = open_settings(path, create=True)
    assert settings.config is None and settings.original_digest is None
    settings.set("tenant", "subdomain", "acme")
    settings.set("tenant", "identity_url", "https://abc1234.id.cyberark.cloud")
    cfg = settings.save()
    assert path.is_file() and cfg.tenant.subdomain == "acme"
    reopened = open_settings(path)
    assert reopened.config is not None
    value = next(item for item in reopened.values() if item.descriptor.dotted_key == "tenant.subdomain")
    assert value.value == "acme" and value.source == "config file"


def test_open_invalid_values_allows_repair_and_preserves_comments(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED + '\n[http]\n# keep this explanation\nverify = "false"\n', encoding="utf-8")
    settings = open_settings(path)
    assert settings.config is None and "verify must be a boolean" in settings.validation_error
    settings.set("http", "verify", False)
    settings.save()
    text = path.read_text(encoding="utf-8")
    assert "# keep this explanation" in text and "verify = false" in text


def test_setting_values_identify_tool_defaults(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED, encoding="utf-8")
    values = {item.descriptor.dotted_key: item for item in open_settings(path).values()}
    assert values["tenant.subdomain"].source == "config file"
    assert values["defaults.max_session_hours"].source == "tool default"
    assert values["defaults.max_session_hours"].value == 2


def test_settings_refuse_to_overwrite_external_edits(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED, encoding="utf-8")
    settings = open_settings(path)
    path.write_text(TENANT + REQUIRED + "# edited elsewhere\n", encoding="utf-8")
    settings.set("defaults", "max_session_hours", 4)
    with pytest.raises(SettingsConflictError, match="changed after settings were opened"):
        settings.save()
    assert "edited elsewhere" in path.read_text(encoding="utf-8")


def test_update_dotenv_preserves_unrelated_content_and_quotes_safely(tmp_path):
    path = tmp_path / ".env"
    path.write_text("# credentials\nUNKNOWN=leave-me\nexport SECRET=old  # keep note\nREMOVE=gone\n", encoding="utf-8")
    digest = dotenv_digest(path)
    new_digest = update_dotenv(path, {"SECRET": 'new value # with "quotes"', "REMOVE": None, "ADDED": "a=b"},
                               expected_digest=digest)
    text = path.read_text(encoding="utf-8")
    assert "# credentials" in text and "UNKNOWN=leave-me" in text and "# keep note" in text
    assert "REMOVE=" not in text
    assert read_dotenv(path)["SECRET"] == 'new value # with "quotes"'
    assert read_dotenv(path)["ADDED"] == "a=b"
    assert new_digest == dotenv_digest(path)
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600


def test_update_dotenv_detects_conflicts_duplicates_and_bad_keys(tmp_path):
    path = tmp_path / ".env"
    path.write_text("ONE=1\n", encoding="utf-8")
    digest = dotenv_digest(path)
    path.write_text("ONE=changed\n", encoding="utf-8")
    with pytest.raises(SettingsConflictError):
        update_dotenv(path, {"ONE": "new"}, expected_digest=digest)
    path.write_text("ONE=1\nONE=2\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="duplicate key"):
        update_dotenv(path, {"ONE": "new"})
    with pytest.raises(ConfigError, match="invalid environment variable"):
        update_dotenv(path, {"BAD-NAME": "value"})


def test_update_dotenv_detects_file_created_after_missing_snapshot(tmp_path):
    path = tmp_path / ".env"
    assert dotenv_digest(path) is None
    path.write_text("EXTERNAL=value\n", encoding="utf-8")
    with pytest.raises(SettingsConflictError):
        update_dotenv(path, {"NEW": "value"}, expected_digest=None)


@pytest.mark.parametrize("text", ['[true]', '[1.0]', '["1.0"]', "true,2"])
def test_integer_lists_reject_booleans_and_fractional_values(text):
    with pytest.raises(ConfigError, match="must contain integers"):
        parse_setting_value(descriptor_for("defaults", "days_of_week"), text)


@pytest.mark.parametrize("text", ["nan", "inf", "-inf"])
def test_number_editor_rejects_non_finite_values(text):
    with pytest.raises(ConfigError, match="finite number"):
        parse_setting_value(descriptor_for("http", "max_requests_per_second"), text)


def test_immediate_field_validation_ignores_dependent_combinations():
    identity = descriptor_for("tenant", "identity_url")
    issues = validate_setting_value(identity, "http://tenant.example/path")
    assert len(issues) == 1 and issues[0].dotted_keys == ("tenant.identity_url",)
    account_type = descriptor_for("defaults", "strong_account_type")
    assert validate_setting_value(account_type, "vault") == ()


def test_settings_issues_identify_every_repair_field(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED + "max_session_hours = 99\nidle_minutes = 0\n", encoding="utf-8")
    issues = open_settings(path).issues()
    assert {item.dotted_keys for item in issues} >= {
        ("defaults.max_session_hours",), ("defaults.idle_minutes",),
    }


def test_rebase_merges_non_overlapping_edits_and_preserves_latest_comments(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED, encoding="utf-8")
    settings = open_settings(path)
    settings.set("defaults", "max_session_hours", 4)
    path.write_text(TENANT + REQUIRED + "# external note\nidle_minutes = 25\n", encoding="utf-8")
    assert settings.rebase() == ()
    assert "# external note" in settings.preview()
    assert settings.document["defaults"]["max_session_hours"] == 4
    assert settings.document["defaults"]["idle_minutes"] == 25
    saved = settings.save()
    assert saved.defaults.max_session_hours == 4 and saved.defaults.idle_minutes == 25


def test_rebase_requires_explicit_choice_for_overlapping_field(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED + "max_session_hours = 2\n", encoding="utf-8")
    settings = open_settings(path)
    settings.set("defaults", "max_session_hours", 4)
    path.write_text(TENANT + REQUIRED + "# disk wins only if selected\nmax_session_hours = 8\n", encoding="utf-8")
    conflicts = settings.rebase()
    assert len(conflicts) == 1
    assert (conflicts[0].dotted_key, conflicts[0].base, conflicts[0].disk, conflicts[0].draft) == (
        "defaults.max_session_hours", 2, 8, 4)
    with pytest.raises(SettingsConflictError, match="resolve overlapping"):
        settings.save()
    repeated = settings.rebase()
    assert len(repeated) == 1 and repeated[0].draft == 4
    settings.resolve_conflict("defaults", "max_session_hours", use="draft")
    assert settings.save().defaults.max_session_hours == 4
    assert "# disk wins" in path.read_text(encoding="utf-8")


def test_malformed_section_shape_can_be_inspected_and_repaired(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('http = "not a table"\n' + TENANT + REQUIRED, encoding="utf-8")
    settings = open_settings(path)
    assert settings.config is None
    type_issue = next(issue for issue in settings.issues() if "must be a TOML table" in issue.message)
    assert ("http", "verify") in type_issue.keys and ("http", "timeout_seconds") in type_issue.keys
    assert any(item.descriptor.dotted_key == "http.verify" for item in settings.values())
    settings.set("http", "verify", True)
    assert settings.save().http.verify is True


def test_external_malformed_known_table_keeps_draft_and_remains_repairable(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED, encoding="utf-8")
    settings = open_settings(path)
    settings.set("tenant", "subdomain", "draft")
    path.write_text('http = "wrong shape"\n# latest comment\n' + TENANT + REQUIRED, encoding="utf-8")
    assert settings.rebase() == ()
    assert settings.document["tenant"]["subdomain"] == "draft"
    assert "# latest comment" in settings.preview()
    assert any("[http] must be a TOML table" in issue.message for issue in settings.issues())
    settings.set("http", "verify", True)
    saved = settings.save()
    assert saved.tenant.subdomain == "draft" and saved.http.verify is True


def test_rebase_after_external_deletion_retains_complete_draft(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED, encoding="utf-8")
    settings = open_settings(path)
    settings.set("tenant", "subdomain", "draft")
    path.unlink()
    assert settings.rebase() == ()
    assert settings.document["tenant"]["identity_url"] == "https://abc1234.id.cyberark.cloud"
    assert settings.save().tenant.subdomain == "draft"


def test_rebase_after_external_truncation_retains_complete_draft(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED, encoding="utf-8")
    settings = open_settings(path)
    settings.set("tenant", "subdomain", "draft")
    path.write_text("", encoding="utf-8")
    assert settings.rebase() == ()
    assert settings.document["tenant"]["identity_url"] == "https://abc1234.id.cyberark.cloud"
    assert settings.save().tenant.subdomain == "draft"


def test_settings_atomic_write_rechecks_digest_immediately_before_replace(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED, encoding="utf-8")
    settings = open_settings(path)
    settings.set("tenant", "subdomain", "draft")
    original_fsync = os.fsync
    changed = False

    def race(descriptor):
        nonlocal changed
        original_fsync(descriptor)
        if not changed:
            changed = True
            path.write_text(TENANT + REQUIRED + "# external during staging\n", encoding="utf-8")

    monkeypatch.setattr("sia.settings.os.fsync", race)
    with pytest.raises(SettingsConflictError, match="while the replacement file was being staged"):
        settings.save()
    assert "external during staging" in path.read_text(encoding="utf-8")
    assert settings.document["tenant"]["subdomain"] == "draft"


def test_dotenv_atomic_write_rechecks_digest_immediately_before_replace(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text("ONE=original\n", encoding="utf-8")
    digest = dotenv_digest(path)
    original_fsync = os.fsync
    changed = False

    def race(descriptor):
        nonlocal changed
        original_fsync(descriptor)
        if not changed:
            changed = True
            path.write_text("ONE=external\n", encoding="utf-8")

    monkeypatch.setattr("sia.settings.os.fsync", race)
    with pytest.raises(SettingsConflictError, match="while the replacement file was being staged"):
        update_dotenv(path, {"ONE": "draft"}, expected_digest=digest)
    assert path.read_text(encoding="utf-8") == "ONE=external\n"


# Values whose serialized form must read back byte-identically. A credential is arbitrary text, so
# backslashes, both quote characters, `#`, edge whitespace and `=` all have to survive the round trip.
ENV_ROUND_TRIP = [
    r"p@ss\word", r"DOMAIN\svc_sia", r"C:\Users\svc", r"abc\tdef", "abc\\", "\\",
    'a"b', "a'b", """a'b"c""", '"quoted-looking"', "'quoted-looking'",
    'secret # with "quotes"', "a  #  b", "#hash", "}brace", "]brack",
    "p@ss word", " lead", "trail ", "\xa0nbsp", "nbsp\xa0", "\u3000ideographic",
    "a=b", "=x", "export FOO=bar", "plain", "café", "日本", "[1,2]", "{x", "", "''", '""',
]


@pytest.mark.parametrize("value", ENV_ROUND_TRIP)
def test_update_dotenv_round_trips_every_credential_shape(tmp_path, value):
    path = tmp_path / ".env"
    update_dotenv(path, {"SIA_CLIENT_SECRET": value})
    text = path.read_text(encoding="utf-8")
    assert len(text.splitlines()) == 1, "the value tore its line"
    assert read_dotenv(path)["SIA_CLIENT_SECRET"] == value


def test_update_dotenv_stores_a_backslash_secret_verbatim(tmp_path):
    """The reported bug: a stored secret must not need -- or show -- any escaping."""
    path = tmp_path / ".env"
    update_dotenv(path, {"SIA_CLIENT_SECRET": r"p@ss\word", "PVWA_USER": r"ACME\svc_sia"})
    assert path.read_text(encoding="utf-8") == "SIA_CLIENT_SECRET=p@ss\\word\nPVWA_USER=ACME\\svc_sia\n"


def test_update_dotenv_serializes_predictably(tmp_path):
    for value, expected in [
        (r"p@ss\word", "K=p@ss\\word\n"), ("a=b", "K=a=b\n"), ("#x", "K='#x'\n"),
        ("a b", "K=a b\n"), ('a"b', "K='a\"b'\n"), (" x ", "K=' x '\n"),
        ('secret # with "quotes"', "K='secret # with \"quotes\"'\n"),
        ("a'b", 'K="a\'b"\n'), ("""a'b"c""", 'K="a\'b""c"\n'), ("", "K=''\n"),
    ]:
        path = tmp_path / f".env-{abs(hash(value))}"
        update_dotenv(path, {"K": value})
        assert path.read_text(encoding="utf-8") == expected, value


def test_update_dotenv_refuses_values_that_cannot_survive_a_line(tmp_path):
    path = tmp_path / ".env"
    # \x85, \u2028 and \u2029 matter because str.splitlines() breaks on them while the JSON
    # quoting this replaced left them raw, tearing the line on the next read.
    for value in ("a\tb", "a\x00b", "a\x0bb", "a\x7fb", "a\x85b", "a\u2028b", "a\u2029b", "a\nb"):
        with pytest.raises(ConfigError, match="one line with no control characters"):
            update_dotenv(path, {"SIA_CLIENT_SECRET": value})
    assert not path.exists()


def test_update_dotenv_preserves_comments_across_every_quoting_form(tmp_path):
    for value in (r"p@ss\word", "needs 'quoting'", 'has "both" and \'one\''):
        path = tmp_path / f".env-{abs(hash(value))}"
        path.write_text("export SIA_CLIENT_SECRET=old  # keep note\n", encoding="utf-8")
        update_dotenv(path, {"SIA_CLIENT_SECRET": value})
        text = path.read_text(encoding="utf-8")
        assert "# keep note" in text and text.startswith("export SIA_CLIENT_SECRET=")
        assert read_dotenv(path)["SIA_CLIENT_SECRET"] == value


def test_update_dotenv_preserves_crlf_line_endings(tmp_path):
    path = tmp_path / ".env"
    path.write_bytes(b"# note\r\nUNKNOWN=keep\r\nSIA_CLIENT_SECRET=old\r\n")
    update_dotenv(path, {"SIA_CLIENT_SECRET": r"p@ss\word", "ADDED": "x"})
    data = path.read_bytes()
    assert data == b"# note\r\nUNKNOWN=keep\r\nSIA_CLIENT_SECRET=p@ss\\word\r\nADDED=x\r\n"
    assert read_dotenv(path)["SIA_CLIENT_SECRET"] == r"p@ss\word"


def test_update_dotenv_saves_despite_an_undecodable_unrelated_line(tmp_path):
    """One unrepairable line must not lock an operator out of saving a credential."""
    path = tmp_path / ".env"
    path.write_text('OTHER="ok" then junk\nSIA_CLIENT_ID=svc\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="text after the closing"):
        read_dotenv(path)
    update_dotenv(path, {"SIA_CLIENT_SECRET": r"p@ss\word"})
    assert 'OTHER="ok" then junk' in path.read_text(encoding="utf-8")
    assert read_dotenv(path, strict=False)["SIA_CLIENT_SECRET"] == r"p@ss\word"


def test_update_dotenv_repairs_a_notepad_byte_order_mark_without_duplicating_keys(tmp_path):
    path = tmp_path / ".env"
    path.write_bytes("\ufeffSIA_CLIENT_ID=svc\n".encode("utf-8"))
    assert read_dotenv(path) == {"SIA_CLIENT_ID": "svc"}
    update_dotenv(path, {"SIA_CLIENT_ID": "svc2"})
    assert path.read_bytes() == b"SIA_CLIENT_ID=svc2\n"
    assert read_dotenv(path) == {"SIA_CLIENT_ID": "svc2"}
