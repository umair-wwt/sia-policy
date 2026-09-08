from __future__ import annotations

from types import SimpleNamespace

import pytest

from sia.config import ValidationIssue, load_config, read_dotenv
from sia.redact import redact
from sia.runtime import Session
from sia.settings import open_settings, update_dotenv as real_update_dotenv
from sia import terminal


TENANT = '[tenant]\nsubdomain = "acme"\nidentity_url = "https://abc1234.id.cyberark.cloud"\n'
REQUIRED = ('[defaults]\ndays_of_week = [0, 1, 2, 3, 4, 5, 6]\nfrom_hour = ""\n'
            'to_hour = ""\ntarget_set_cert_validation = false\n')


def args_for(tmp_path, **overrides):
    values = {
        "config": str(tmp_path / "config.toml"),
        "env": str(tmp_path / ".env"),
        "input": str(tmp_path / "input"),
        "report_dir": str(tmp_path / "reports"),
        "ca_bundle": None,
        "json": False,
        "verbose": False,
        "show": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def answers(monkeypatch, values):
    iterator = iter(values)
    def read(prompt=""):
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError from None
    monkeypatch.setattr("builtins.input", read)


def terminal_answers(monkeypatch, values):
    iterator = iter(values)
    def read(*args, **kwargs):
        try:
            value = next(iterator)
        except StopIteration:
            raise EOFError from None
        if isinstance(value, BaseException):
            raise value
        return value
    monkeypatch.setattr(terminal, "read_input", read)


TERMINAL_EXITS = [
    pytest.param("/cancel", 2, id="cancel"),
    pytest.param(EOFError(), 2, id="eof"),
    pytest.param(KeyboardInterrupt(), 130, id="ctrl-c"),
]


def test_show_settings_reports_effective_sources_without_secret_values(tmp_path, capsys):
    config = tmp_path / "config.toml"
    (tmp_path / "certs").mkdir()
    config.write_text(TENANT + REQUIRED + '\n[auth]\npassword_file = "private/passwords.csv"\n'
                      + '\n[http]\nca_bundle = "certs"\n', encoding="utf-8")
    env = tmp_path / ".env"
    env.write_text("SIA_CLIENT_ID=file-id\nSIA_CLIENT_SECRET=file-secret\n", encoding="utf-8")
    env.chmod(0o600)
    session = Session(shell_env={"SIA_CLIENT_ID": "shell-id", "SIA_CLIENT_SECRET": "shell-secret"})
    data = terminal.show_settings(args_for(tmp_path), session)
    output = capsys.readouterr().out
    assert "file-secret" not in output and "shell-secret" not in output
    credentials = {item["key"]: item for item in data["credentials"]}
    assert credentials["SIA_CLIENT_SECRET"] == {
        "key": "SIA_CLIENT_SECRET", "status": "set", "source": "shell", "file_shadowed": True,
    }
    password_file = next(item for item in data["settings"]
                         if item["section"] == "auth" and item["key"] == "password_file")
    assert password_file["value"] == "private/passwords.csv"
    assert password_file["effective_value"] == str(tmp_path / "private" / "passwords.csv")


def test_guided_setup_creates_valid_config_and_existing_values_are_defaults(tmp_path, monkeypatch):
    args = args_for(tmp_path)
    # Tenant values, review defaults, save, skip credentials.
    answers(monkeypatch, ["acme", "https://abc1234.id.cyberark.cloud", "continue", "yes", "no"])
    assert terminal.setup(args, Session(shell_env={})) == 0
    assert load_config(args.config).tenant.subdomain == "acme"

    # Reopening setup accepts the current required values with Enter instead of forcing them to be retyped.
    original = (tmp_path / "config.toml").read_text(encoding="utf-8")
    answers(monkeypatch, ["", "", "continue", "no", "/cancel"])
    assert terminal.setup(args, Session(shell_env={})) == 2
    assert (tmp_path / "config.toml").read_text(encoding="utf-8") == original


def test_settings_cancel_returns_without_writing_the_file(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED, encoding="utf-8")
    original = path.read_bytes()
    # Common settings -> first field -> cancel that edit -> leave settings.
    answers(monkeypatch, ["tenant", "1", "/cancel"])
    assert terminal.settings(args_for(tmp_path), Session(shell_env={})) == 2
    assert path.read_bytes() == original


@pytest.mark.parametrize("event, expected", [
    pytest.param("/back", 0, id="back"),
    *TERMINAL_EXITS,
])
def test_settings_top_level_exit_semantics_retain_home_draft(tmp_path, monkeypatch, event, expected):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED)
    session = Session(shell_env={}, in_home=True)
    draft = terminal._open_draft(args_for(tmp_path), session, flow="settings")
    draft.document.set("tenant", "subdomain", "pending")
    terminal_answers(monkeypatch, [event])
    assert terminal.settings(args_for(tmp_path), session) == expected
    assert session.pending_drafts()
    assert load_config(path).tenant.subdomain == "acme"


def test_setup_cancellation_after_save_reports_retained_settings(tmp_path, monkeypatch, capsys):
    args = args_for(tmp_path)
    answers(monkeypatch, ["acme", "https://abc1234.id.cyberark.cloud", "continue", "yes", "/cancel"])
    assert terminal.setup(args, Session(shell_env={})) == 2
    assert load_config(args.config).tenant.subdomain == "acme"
    assert "Configuration remains saved" in capsys.readouterr().out


@pytest.mark.parametrize("event, expected", TERMINAL_EXITS)
def test_setup_exit_semantics_at_first_tenant_field(tmp_path, monkeypatch, event, expected):
    session = Session(shell_env={}, in_home=True)
    terminal_answers(monkeypatch, [event])
    assert terminal.setup(args_for(tmp_path), session) == expected
    assert not session.pending_drafts()


@pytest.mark.parametrize("event, expected", TERMINAL_EXITS)
def test_setup_exit_semantics_at_identity_field_retain_first_answer(tmp_path, monkeypatch, event, expected):
    session = Session(shell_env={}, in_home=True)
    terminal_answers(monkeypatch, ["acme", event])
    assert terminal.setup(args_for(tmp_path), session) == expected
    draft = session.config_drafts[str((tmp_path / "config.toml").resolve())]
    assert terminal._table_value(draft.document, "tenant", "subdomain") == "acme"


@pytest.mark.parametrize("event, expected", TERMINAL_EXITS)
def test_setup_exit_semantics_at_review_retain_both_answers(tmp_path, monkeypatch, event, expected):
    session = Session(shell_env={}, in_home=True)
    terminal_answers(monkeypatch, ["acme", "https://abc1234.id.cyberark.cloud", event])
    assert terminal.setup(args_for(tmp_path), session) == expected
    assert session.pending_drafts()


@pytest.mark.parametrize("event, expected", TERMINAL_EXITS)
def test_setup_exit_semantics_after_config_save_keep_saved_file(tmp_path, monkeypatch, event, expected):
    session = Session(shell_env={}, in_home=True)
    terminal_answers(monkeypatch, ["acme", "https://abc1234.id.cyberark.cloud", "continue", "yes", event])
    assert terminal.setup(args_for(tmp_path), session) == expected
    assert load_config(tmp_path / "config.toml").tenant.subdomain == "acme"
    assert not session.pending_drafts()


def test_setup_back_from_each_screen_moves_to_previous_answer(tmp_path, monkeypatch):
    session = Session(shell_env={}, in_home=True)
    # Identity -> subdomain; review -> identity; then cancel while preserving all answers.
    terminal_answers(monkeypatch, ["first", "/back", "second", "https://one.example", "/back",
                                   "https://two.example", "/cancel"])
    assert terminal.setup(args_for(tmp_path), session) == 2
    draft = session.config_drafts[str((tmp_path / "config.toml").resolve())]
    assert terminal._table_value(draft.document, "tenant", "subdomain") == "second"
    assert terminal._table_value(draft.document, "tenant", "identity_url") == "https://two.example"


def test_standalone_credentials_do_not_offer_ephemeral_storage(tmp_path, monkeypatch, capsys):
    session = Session(shell_env={})
    answers(monkeypatch, ["1", "test-user", "0"])
    terminal.credentials(args_for(tmp_path), session)
    output = capsys.readouterr().out
    assert "1. Keep for" not in output and "start sia" in output
    assert not session.secrets and not (tmp_path / ".env").exists()


def test_credentials_can_stay_in_session_and_report_shell_shadowing(tmp_path, monkeypatch, capsys):
    session = Session(shell_env={"SIA_CLIENT_ID": "exported-id"}, in_home=True)
    # Client ID, new value, keep in this session.
    answers(monkeypatch, ["1", "session-id", "1"])
    terminal.credentials(args_for(tmp_path), session)
    output = capsys.readouterr().out
    assert session.secrets["SIA_CLIENT_ID"] == "session-id"
    assert "exported SIA_CLIENT_ID still takes precedence" in output
    assert not (tmp_path / ".env").exists()


def test_credentials_storage_typo_reprompts_without_losing_pair(tmp_path, monkeypatch):
    session = Session(shell_env={}, in_home=True)
    answers(monkeypatch, ["1", "session-id", "typo", "1"])
    terminal.credentials(args_for(tmp_path), session)
    assert session.secrets["SIA_CLIENT_ID"] == "session-id"


def test_credentials_save_secret_to_env_without_disclosure(tmp_path, monkeypatch, capsys):
    path = tmp_path / ".env"
    path.write_text("# keep\nUNRELATED=value\n", encoding="utf-8")
    path.chmod(0o600)
    session = Session(shell_env={})
    answers(monkeypatch, ["2", "2", "yes"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": 'secret # with "quotes"')
    terminal.credentials(args_for(tmp_path), session)
    output = capsys.readouterr().out
    assert 'secret # with "quotes"' not in output
    assert read_dotenv(path)["SIA_CLIENT_SECRET"] == 'secret # with "quotes"'
    assert "# keep" in path.read_text(encoding="utf-8") and "UNRELATED=value" in path.read_text(encoding="utf-8")


def test_credentials_detect_env_created_during_prompt(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    answers(monkeypatch, ["1", "new-id", "2", "yes", "retry"])
    changed = False

    def create_then_update(target, updates, *, expected_digest=None):
        nonlocal changed
        if not changed:
            path.write_text("EXTERNAL=keep\n", encoding="utf-8")
            changed = True
        return real_update_dotenv(target, updates, expected_digest=expected_digest)

    monkeypatch.setattr(terminal, "update_dotenv", create_then_update)
    terminal.credentials(args_for(tmp_path), Session(shell_env={}))
    assert read_dotenv(path) == {"EXTERNAL": "keep", "SIA_CLIENT_ID": "new-id"}


def test_windows_secure_save_failure_falls_back_to_home_session_automatically(tmp_path, monkeypatch, capsys):
    path = tmp_path / ".env"
    session = Session(shell_env={}, in_home=True)
    answers(monkeypatch, ["service-user", "2", "yes"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "private-password")

    def fail_before_publish(*args, **kwargs):
        raise terminal.WindowsCredentialProtectionError(path, "ACL API unavailable", published=False)

    monkeypatch.setattr(terminal, "update_dotenv", fail_before_publish)
    terminal.credentials(args_for(tmp_path), session, service_pair=True)
    output = capsys.readouterr().out
    assert session.secrets == {"SIA_CLIENT_ID": "service-user", "SIA_CLIENT_SECRET": "private-password"}
    assert not path.exists()
    assert "automatically for this home session only" in output
    assert "private-password" not in output


def test_windows_post_publish_acl_failure_is_reported_without_false_session_only_claim(tmp_path, monkeypatch, capsys):
    path = tmp_path / ".env"
    session = Session(shell_env={}, in_home=True)
    answers(monkeypatch, ["service-user", "2", "yes"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "private-password")

    def fail_after_publish(target, updates, **kwargs):
        path.write_text('SIA_CLIENT_ID="service-user"\nSIA_CLIENT_SECRET="private-password"\n')
        raise terminal.WindowsCredentialProtectionError(path, "verification unavailable", published=True)

    monkeypatch.setattr(terminal, "update_dotenv", fail_after_publish)
    terminal.credentials(args_for(tmp_path), session, service_pair=True)
    output = capsys.readouterr().out
    words = " ".join(output.split())
    assert session.secrets["SIA_CLIENT_SECRET"] == "private-password"
    assert "Windows replaced" in words and "could not confirm" in words and "Run /doctor" in words
    assert "nothing was written" not in words and "automatically for this home session only" not in words
    assert "private-password" not in output


def test_windows_secure_save_failure_does_not_claim_standalone_session_fallback(tmp_path, monkeypatch, capsys):
    path = tmp_path / ".env"
    session = Session(shell_env={})
    answers(monkeypatch, ["1", "service-user", "2", "yes"])

    def fail_before_publish(*args, **kwargs):
        raise terminal.WindowsCredentialProtectionError(path, "ACL API unavailable", published=False)

    monkeypatch.setattr(terminal, "update_dotenv", fail_before_publish)
    terminal.credentials(args_for(tmp_path), session)
    output = capsys.readouterr().out
    assert session.secrets == {} and not path.exists()
    assert "standalone command cannot retain session credentials" in " ".join(output.split())


def test_terminal_edit_repairs_invalid_config_and_preserves_comment(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED + '\n[http]\n# operator note\nverify = "false"\n', encoding="utf-8")
    document = open_settings(path)
    assert document.config is None
    answers(monkeypatch, ["false", "yes"])
    terminal.edit_field(document, "http", "verify")
    assert terminal.save_document(document)
    assert load_config(path).http.verify is False
    assert "# operator note" in path.read_text(encoding="utf-8")


def test_settings_output_masks_credentials_embedded_in_invalid_url(tmp_path, capsys):
    path = tmp_path / "config.toml"
    path.write_text(TENANT.replace("https://abc1234.id.cyberark.cloud",
                                   "https://operator:private-password@abc1234.id.cyberark.cloud") + REQUIRED)
    terminal.show_settings(args_for(tmp_path), Session(shell_env={}))
    output = capsys.readouterr().out
    assert "operator" not in output and "private-password" not in output
    assert "https://***@abc1234.id.cyberark.cloud" in output


def test_settings_output_does_not_mask_words_from_unrelated_shell_variables(tmp_path, capsys):
    """Only the credentials SIA reads are secrets; TOKENIZERS_PARALLELISM=false must not hide every "false"."""
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED)
    (tmp_path / ".env").write_text("SIA_CLIENT_SECRET=hunter2-secret\nSIA_SA_DMZ_PASSWORD=dmz-secret\n")
    session = Session(shell_env={"TOKENIZERS_PARALLELISM": "false", "PASSWORD_STORE_DIR": str(tmp_path),
                                 "PVWA_PASSWORD": "vault-secret", "SIA_SA_WEB_PASSWORD": "web-secret"})
    terminal.show_settings(args_for(tmp_path), session)
    output = capsys.readouterr().out
    assert "target_set_cert_validation = false" in output and str(tmp_path) in output and "***" not in output
    assert redact("false") == "false"
    assert redact("hunter2-secret dmz-secret vault-secret web-secret") == "*** *** *** ***"


def test_home_help_and_exit_do_not_construct_tenant_context(tmp_path, monkeypatch, capsys):
    answers(monkeypatch, ["/help settings", "0"])
    called = []

    def run(argv):
        called.append(argv)
        raise AssertionError("help and exit must remain offline")

    assert terminal.home(args_for(tmp_path), Session(shell_env={}), run) == 0
    output = capsys.readouterr().out
    assert "Settings" in output and "Setup needed" in output
    assert called == []


def test_first_launch_has_next_step_without_technical_dump(tmp_path, monkeypatch, capsys):
    answers(monkeypatch, ["unknown", "/help start", "/exit"])
    assert terminal.home(args_for(tmp_path), Session(shell_env={}), lambda argv: 0) == 0
    output = capsys.readouterr().out
    assert (tmp_path / "config.toml").is_file()
    assert 'subdomain = ""' in (tmp_path / "config.toml").read_text()
    assert "Next: /setup" in output
    assert output.count("What would you like to do?") == 1
    assert "SIA_CLIENT_SECRET" not in output
    assert "FileNotFoundError" not in output
    assert "Last command exit code" not in output


def test_home_forwards_explicit_command_arguments(tmp_path, monkeypatch):
    answers(monkeypatch, ["/plan --server web01.example.com --group 'Server Admins' --drift", "/exit"])
    called = []
    assert terminal.home(args_for(tmp_path), Session(shell_env={}), lambda argv: called.append(argv) or 0) == 0
    assert called == [["plan", "--server", "web01.example.com", "--group", "Server Admins", "--drift", "--input", str(tmp_path / "input")]]


def test_settings_search_and_nested_back_keep_pending_edits(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED)
    answers(monkeypatch, ["tenant.subdomain", "updated", "http.timeout_seconds", "/back", "advanced", "/back", "save", "yes", "back"])
    assert terminal.settings(args_for(tmp_path), Session(shell_env={})) == 0
    assert load_config(path).tenant.subdomain == "updated"


def test_pending_settings_resume_and_discard_requires_yes(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED)
    session = Session(shell_env={})
    answers(monkeypatch, ["tenant.subdomain", "updated", "back"])
    assert terminal.settings(args_for(tmp_path), session) == 0
    assert load_config(path).tenant.subdomain == "acme"
    answers(monkeypatch, ["discard", "no", "save", "yes"])
    assert terminal.settings(args_for(tmp_path), session) == 0
    assert load_config(path).tenant.subdomain == "updated"


def test_setup_declined_save_and_invalid_value_can_be_repaired(tmp_path, monkeypatch, capsys):
    answers(monkeypatch, ["acme", "invalid-url", "no", "https://abc1234.id.cyberark.cloud",
                          "continue", "no", "continue", "yes", "no"])
    assert terminal.setup(args_for(tmp_path), Session(shell_env={})) == 0
    assert load_config(tmp_path / "config.toml").tenant.identity_url == "https://abc1234.id.cyberark.cloud"
    output = capsys.readouterr().out
    assert "That value needs attention" in output
    assert "Nothing saved" in output


def test_guided_credentials_save_both_values_together(tmp_path, monkeypatch, capsys):
    answers(monkeypatch, ["service-user", "2", "yes"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "private-password")
    terminal.credentials(args_for(tmp_path), Session(shell_env={}), service_pair=True)
    assert read_dotenv(tmp_path / ".env") == {"SIA_CLIENT_ID": "service-user", "SIA_CLIENT_SECRET": "private-password"}
    assert "private-password" not in capsys.readouterr().out


def test_guided_credentials_empty_password_leaves_both_unchanged(tmp_path, monkeypatch):
    answers(monkeypatch, ["service-user", "/cancel"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "")
    session = Session(shell_env={}, in_home=True)
    with pytest.raises(terminal.Cancelled):
        terminal.credentials(args_for(tmp_path), session, service_pair=True)
    assert not (tmp_path / ".env").exists()
    assert session.secrets == {}


def test_settings_summary_shows_only_changed_labels_unless_details_requested(tmp_path, monkeypatch, capsys):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED)
    doc = open_settings(path)
    doc.set("tenant", "subdomain", "updated")
    answers(monkeypatch, ["yes"])
    assert terminal.save_document(doc)
    output = capsys.readouterr().out
    assert "Subdomain: acme → updated" in output
    assert "@@" not in output and "days_of_week" not in output


def test_setting_groups_cover_every_real_setting_once():
    grouped = [d.dotted_key for key in terminal.SETTING_GROUPS for d in terminal.group_descriptors(key)]
    assert len(grouped) == len(set(grouped))
    assert set(grouped) == {d.dotted_key for d in terminal.setting_descriptors()}


def test_every_known_validation_field_routes_to_a_visible_setup_group():
    for descriptor in terminal.setting_descriptors():
        issue = ValidationIssue(((descriptor.section, descriptor.key),), "repair")
        assert terminal._groups_for_issues((issue,)), descriptor.dotted_key
    unknown = ValidationIssue((("unknown", "key"),), "repair", "unknown")
    assert terminal._groups_for_issues((unknown,)) == ()


def test_setup_offers_and_requires_acceptance_for_safe_url_correction(tmp_path, monkeypatch, capsys):
    answers(monkeypatch, ["acme", "abc1234.id.cyberark.cloud/path?copied=true", "yes",
                          "continue", "yes", "no"])
    assert terminal.setup(args_for(tmp_path), Session(shell_env={})) == 0
    assert load_config(tmp_path / "config.toml").tenant.identity_url == "https://abc1234.id.cyberark.cloud"
    output = capsys.readouterr().out
    assert "safe syntax correction" in output


def test_setup_back_repairs_identity_url_without_losing_subdomain(tmp_path, monkeypatch):
    session = Session(shell_env={})
    answers(monkeypatch, ["acme", "/back", "", "wrong.example", "no", "/cancel"])
    assert terminal.setup(args_for(tmp_path), session) == 2
    draft = session.config_drafts[str((tmp_path / "config.toml").resolve())]
    assert terminal._table_value(draft.document, "tenant", "subdomain") == "acme"


def test_drafts_are_isolated_by_resolved_config_path(tmp_path, monkeypatch):
    first = tmp_path / "one"
    second = tmp_path / "two"
    first.mkdir()
    second.mkdir()
    (first / "config.toml").write_text(TENANT + REQUIRED)
    (second / "config.toml").write_text(TENANT.replace("acme", "other") + REQUIRED)
    session = Session(shell_env={})
    answers(monkeypatch, ["tenant.subdomain", "pending", "back"])
    assert terminal.settings(args_for(first), session) == 0
    answers(monkeypatch, ["back"])
    assert terminal.settings(args_for(second), session) == 0
    assert len(session.pending_drafts()) == 1
    assert load_config(first / "config.toml").tenant.subdomain == "acme"
    assert load_config(second / "config.toml").tenant.subdomain == "other"


def test_nonoverlapping_external_settings_edit_is_rebased(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED)
    doc = open_settings(path)
    doc.set("tenant", "subdomain", "draft")
    path.write_text(TENANT + REQUIRED + "\n[http]\ntimeout_seconds = 77\n")
    answers(monkeypatch, ["yes"])
    assert terminal.save_document(doc) is False
    answers(monkeypatch, ["yes"])
    assert terminal.save_document(doc) is True
    cfg = load_config(path)
    assert cfg.tenant.subdomain == "draft" and cfg.http.timeout_seconds == 77


def test_rebase_failure_offers_home_and_keeps_draft_for_later_retry(tmp_path, monkeypatch, capsys):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED)
    doc = open_settings(path)
    doc.set("tenant", "subdomain", "draft")
    path.write_text('[tenant\ninvalid = "toml"\n')
    answers(monkeypatch, ["yes", "home"])
    with pytest.raises(terminal.Cancelled):
        terminal.save_document(doc)
    assert doc.document["tenant"]["subdomain"] == "draft"
    output = capsys.readouterr().out
    assert "Cannot reload" in output and "Try again after repairing" in output


def test_unknown_setting_routes_to_external_repair_and_reload(tmp_path, monkeypatch, capsys):
    path = tmp_path / "config.toml"
    path.write_text(TENANT.replace("\nidentity_url", '\nunknown = "remove-me"\nidentity_url') + REQUIRED)
    calls = 0

    def read(label, *args, **kwargs):
        nonlocal calls
        if label == "Settings" and calls == 0:
            calls += 1
            path.write_text(TENANT + REQUIRED)
            return "reload"
        return "back"

    monkeypatch.setattr(terminal, "read_input", read)
    assert terminal.settings(args_for(tmp_path), Session(shell_env={}, in_home=True)) == 0
    output = capsys.readouterr().out
    assert "repair" in output.lower()
    assert "Configuration reloaded" in output


def test_overlapping_external_settings_edit_asks_which_value_to_keep(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED)
    doc = open_settings(path)
    doc.set("tenant", "subdomain", "draft")
    path.write_text(TENANT.replace("acme", "disk") + REQUIRED)
    answers(monkeypatch, ["yes", "draft"])
    assert terminal.save_document(doc) is False
    answers(monkeypatch, ["yes"])
    assert terminal.save_document(doc) is True
    assert load_config(path).tenant.subdomain == "draft"


def test_malformed_dotenv_can_be_ignored_for_current_session(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text('SIA_CLIENT_ID="unterminated\n')
    session = Session(shell_env={}, in_home=True)
    answers(monkeypatch, ["ignore", "1", "session-id", "1"])
    terminal.credentials(args_for(tmp_path), session)
    assert session.secrets["SIA_CLIENT_ID"] == "session-id"
    assert session.path_key(path) in session.ignored_env_files
    assert path.read_text() == 'SIA_CLIENT_ID="unterminated\n'


def test_workflow_validates_fqdn_and_preserves_windows_path(tmp_path, monkeypatch, capsys):
    args = args_for(tmp_path)
    answers(monkeypatch, ["2", "bad host", "web01.example.com", "Server Admins", "no", "no",
                          r"C:\Users\operator\SIA Input", "", "run"])
    argv = terminal.workflow("verify", args)
    assert argv == ["verify", "--server", "web01.example.com", "--group", "Server Admins",
                    "--input", r"C:\Users\operator\SIA Input", "--drift"]
    assert "needs attention" in capsys.readouterr().out


def test_workflow_back_revisits_previous_answer_with_its_default(tmp_path, monkeypatch):
    answers(monkeypatch, ["2", "web01.example.com", "/back", "", "Server Admins", "no", "no", "", "", "run"])
    argv = terminal.workflow("verify", args_for(tmp_path))
    assert argv[argv.index("--server") + 1] == "web01.example.com"
    assert argv[argv.index("--group") + 1] == "Server Admins"


def test_workflow_reprompts_for_every_invalid_advanced_choice(tmp_path, monkeypatch, capsys):
    answers(monkeypatch, ["1", "", "no", "no", "yes",
                          "-1", "0", "not-a-number", "0", "0", "16",
                          "wrong", "auto", "wrong", "all", "-2", "100",
                          "", "", "no", "run"])
    argv = terminal.workflow("plan", args_for(tmp_path))
    assert argv[argv.index("--workers") + 1] == "16"
    assert argv[argv.index("--lookup") + 1] == "auto"
    assert argv[argv.index("--only") + 1] == "all"
    assert capsys.readouterr().out.count("needs attention") >= 6


def test_workflow_review_can_jump_to_one_answer(tmp_path, monkeypatch):
    answers(monkeypatch, ["1", "first input", "", "edit", "2", "second input", "", "run"])
    argv = terminal.workflow("verify", args_for(tmp_path))
    assert argv[argv.index("--input") + 1] == "second input"


@pytest.mark.parametrize("text", [
    r'/plan --input C:\Users\operator\input',
    r'sia plan --input "C:\Users\operator\SIA Input"',
    r"sia 'plan' '--input' 'C:\Users\operator\SIA Input'",
])
def test_split_command_line_accepts_optional_sia_and_preserves_windows_paths(text):
    tokens = terminal.split_command_line(text, windows=True)
    assert tokens[0] == "plan"
    assert tokens[-1].startswith("C:\\Users\\operator\\")


def test_command_parser_round_trips_posix_quotes_and_apostrophes():
    argv = ["plan", "--group", "O'Brien Admins", "--input", "/tmp/input files"]
    rendered = terminal.command_string(argv, windows=False)
    assert terminal.split_command_line(rendered, windows=False) == argv


def test_command_parser_round_trips_windows_quotes_and_backslashes(monkeypatch):
    argv = ["plan", "--group", "Server Admins", "--input", r"C:\SIA Input\folder\\"]
    rendered = __import__("subprocess").list2cmdline(["sia", *argv])
    assert terminal.split_command_line(rendered, windows=True) == argv


def test_powershell_command_display_quotes_every_argument_without_interpolation():
    argv = ["plan", "--group", "O'Brien $env:USER; & whoami `ignored`", "--input",
            r"C:\SIA Input\folder\\"]
    rendered = terminal.command_string(argv, windows=True)
    assert rendered == (
        "sia 'plan' '--group' 'O''Brien $env:USER; & whoami `ignored`' "
        "'--input' 'C:\\SIA Input\\folder\\\\'"
    )
    assert terminal.split_command_line(rendered, windows=True) == argv


@pytest.mark.parametrize("text", [
    'sia plan --input "C:\\unfinished path',
    "sia 'plan' '--input' 'C:\\unfinished path",
])
def test_windows_command_parser_rejects_unmatched_quotes(text):
    with pytest.raises(ValueError, match="Unmatched .* quote"):
        terminal.split_command_line(text, windows=True)


def test_windows_command_parser_treats_shell_syntax_as_literal_data():
    text = "sia 'plan' '--group' '$env:USER; $(whoami) & calc.exe | ignored `still-data`'"
    assert terminal.split_command_line(text, windows=True) == [
        "plan", "--group", "$env:USER; $(whoami) & calc.exe | ignored `still-data`",
    ]


def test_home_reports_unmatched_quotes_and_does_not_dispatch(tmp_path, monkeypatch, capsys):
    answers(monkeypatch, ['/plan --input "unfinished', '/exit'])
    called = []
    assert terminal.home(args_for(tmp_path), Session(shell_env={}), called.append) == 0
    assert called == []
    assert "quot" in capsys.readouterr().out.lower()


def test_home_confirms_exit_when_a_draft_is_pending(tmp_path, monkeypatch, capsys):
    path = tmp_path / "config.toml"
    path.write_text(TENANT + REQUIRED)
    session = Session(shell_env={})
    draft = terminal._open_draft(args_for(tmp_path), session, flow="settings")
    draft.document.set("tenant", "subdomain", "pending")
    answers(monkeypatch, ["/exit", "no", "/exit", "yes"])
    assert terminal.home(args_for(tmp_path), session, lambda argv: 0) == 0
    assert "Exit cancelled" in capsys.readouterr().out
