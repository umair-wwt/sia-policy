"""Guided terminal workspace. Tenant work uses the regular CLI dispatcher."""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import sys
from dataclasses import dataclass
from difflib import unified_diff
from pathlib import Path, PureWindowsPath
from typing import Any, Callable

from .config import (
    ConfigError,
    decode_text_file,
    load_config,
    read_dotenv,
    suggest_https_base_url,
    validate_dns_name,
)
from .diagnostics import diagnose, render_diagnostic, sanitize
from .help import help_text
from .redact import register_secret
from .runtime import prompt_secret
from .settings import (
    SettingsConflictError,
    descriptor_for,
    open_settings,
    parse_setting_value,
    setting_descriptors,
    storable_env_value,
    update_dotenv,
    validate_setting_value,
)
from .console import heading, menu, note, panel, read_input
from .starter import ensure_starter_config, missing_tenant_fields
from .windows_security import WindowsCredentialProtectionError


class Cancelled(Exception):
    pass


class Back(Exception):
    """Return one screen without discarding the surrounding draft."""


@dataclass
class ConfigDraft:
    document: Any
    baseline: str
    flow: str = "settings"
    step: str = "tenant.subdomain"


def ask(prompt: str, default: str | None = None, *, choices=None, path=False, commands=False) -> str:
    answer = read_input(prompt, default, choices=choices, path=path, commands=commands).strip()
    if answer.lower() == "/cancel":
        raise Cancelled
    if answer.lower() == "/back":
        raise Back
    return answer if answer else (default or "")


def yes(prompt: str, *, default: bool = False) -> bool:
    while True:
        value = ask(prompt, "yes" if default else "no", choices={"yes": "Continue", "no": "Skip this step"}).lower()
        if value in ("yes", "y"):
            return True
        if value in ("no", "n"):
            return False
        print("Enter yes or no. Use /back for the previous screen or /cancel to return home.")


def _draft_key(args) -> str:
    return str(Path(args.config).expanduser().resolve())


def _open_draft(args, session, *, flow: str, create: bool = False) -> ConfigDraft:
    key = _draft_key(args)
    draft = session.config_drafts.get(key)
    if draft is not None:
        draft.flow = flow
        return draft
    doc = open_settings(args.config, create=create)
    draft = ConfigDraft(doc, doc.preview(), flow=flow)
    session.config_drafts[key] = draft
    return draft


def _clear_draft(args, session) -> None:
    session.config_drafts.pop(_draft_key(args), None)


def _draft_exit_message(session, retained: str, discarded: str) -> str:
    return retained if session.in_home else discarded


def _table_value(doc, section: str, key: str, default: Any = None) -> Any:
    """Read malformed documents defensively so repair screens can still render."""
    table = doc.document.get(section, {})
    try:
        value = table.get(key, default)
    except (AttributeError, TypeError):
        return default
    return value.unwrap() if hasattr(value, "unwrap") else value


def display(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return json.dumps(list(value))
    return str(value) if value is not None else ""


def safe_display(value) -> str:
    """Format terminal data while masking registered secrets and URL userinfo."""
    return str(sanitize(display(value)))


TEMPLATE_FIELDS = {
    "time_zone", "days_of_week", "from_hour", "to_hour", "max_session_hours", "idle_minutes",
    "assign_local_groups", "enable_reconnect", "policy_tags", "ssh_username",
}


def applicability(section: str, key: str, raw: dict) -> str:
    defaults = raw.get("defaults", {})
    template = defaults.get("template_policy", "") if isinstance(defaults, dict) else ""
    if section == "defaults" and key in TEMPLATE_FIELDS and template:
        return f"Controlled by template policy {template!r} when present; CSV group/SSH overrides still apply. Tenant template values are not read in this screen."
    if section == "defaults" and key == "policy_status":
        return "New policies only. Existing status changes require the explicit Activate/Suspend run option."
    if section == "defaults" and key in ("assign_local_groups", "group_template", "ssh_username"):
        return "Used when the CSV row does not supply an override."
    if section == "http" or section == "auth":
        return "Used on the next command."
    if section == "connect":
        return "Used by connection-information exports."
    return "Save locally, then preview with plan --drift; existing managed objects need apply --update where supported."


def paths(args) -> dict[str, str]:
    return {"configuration": str(Path(args.config).resolve()), "credentials": str(Path(args.env).resolve()),
            "input": str(Path(getattr(args, "input", "input")).resolve()), "reports": str(Path(args.report_dir).resolve())}


def show_settings(args, session) -> dict:
    doc = open_settings(args.config)
    raw = doc.document.unwrap()
    data = {"paths": paths(args), "settings": [], "credentials": []}
    try:
        cfg = doc.validate()
    except ConfigError as exc:
        cfg = None
        data["diagnostics"] = [diagnose(exc, stage="Settings").to_dict()]
    for descriptor in setting_descriptors():
        section, key = descriptor.section, descriptor.key
        table = raw.get(section, {})
        value = table.get(key, descriptor.default) if isinstance(table, dict) else descriptor.default
        effective = getattr(getattr(cfg, section), key) if cfg is not None else value
        source = "config file" if isinstance(table, dict) and key in table else "tool default"
        if args.ca_bundle and section == "http" and key in ("ca_bundle", "verify"):
            effective = str(Path(args.ca_bundle).resolve()) if key == "ca_bundle" else True
            source = "command line"
        data["settings"].append({"section": section, "key": key, "label": descriptor.label,
                                 "value": sanitize(value), "effective_value": sanitize(effective), "source": source,
                                 "help": descriptor.help, "applies": applicability(section, key, raw)})
    try:
        values, sources = session.values(args.env)
        file_values = ({} if session.path_key(args.env) in session.ignored_env_files
                       else read_dotenv(args.env))
        for key in ("SIA_CLIENT_ID", "SIA_CLIENT_SECRET", "PVWA_USER", "PVWA_PASSWORD"):
            data["credentials"].append({"key": key, "status": "set" if values.get(key) else "missing",
                                        "source": sources.get(key, "none"),
                                        "file_shadowed": key in file_values and sources.get(key) != "file"})
    except ConfigError as exc:
        data.setdefault("diagnostics", []).append(diagnose(exc, stage="Credentials file").to_dict())
    if args.json:
        print(json.dumps(sanitize(data), indent=2, default=str))
    else:
        for name, value in data["paths"].items():
            print(f"{name.capitalize()}: {value}")
        current = ""
        for row in data["settings"]:
            if row["section"] != current:
                current = row["section"]
                print(f"\n[{current}]")
            print(f"  {row['key']} = {safe_display(row['value'])} ({row['source']})")
            if row["effective_value"] != row["value"]:
                print(f"    Effective: {safe_display(row['effective_value'])}")
            print(f"    {row['help']}\n    {row['applies']}")
        print("\nCredentials:")
        for row in data["credentials"]:
            print(f"  {row['key']}: {row['status']} ({row['source']})" + ("; file value is shadowed" if row["file_shadowed"] else ""))
        for diagnostic in data.get("diagnostics", []):
            print(f"\nNeeds attention: {diagnostic['message']}")
    return data


def edit_field(doc, section: str, key: str, *, required: bool = False) -> None:
    descriptor = descriptor_for(section, key)
    current = _table_value(doc, section, key, descriptor.default)
    heading(descriptor.label, descriptor.help)
    if section == "defaults" and (key == "policy_status" or _table_value(doc, "defaults", "template_policy", "")):
        note(applicability(section, key, doc.document.unwrap()))
    choices = {str(value): "" for value in descriptor.choices}
    if descriptor.kind == "boolean":
        choices = {"true": "Enabled", "false": "Disabled"}
    elif descriptor.kind == "timezone":
        from zoneinfo import available_timezones
        choices = {value: "Time zone" for value in sorted(available_timezones())}
    actions = "/back keeps this field unchanged · /cancel returns home"
    if not (required or descriptor.required):
        actions = f"/empty clears it · {actions}"
    note(f"Saved as {section}.{key}. Enter keeps the current value. {actions}.")
    while True:
        current_text = safe_display(current)
        # A redacted value cannot safely be sent back into the document as a
        # prompt default. Invalid credential-bearing URLs must be re-entered.
        if current_text != display(current):
            current_text = ""
        field_choices = dict(choices)
        if not (required or descriptor.required):
            field_choices["/empty"] = "Clear this optional setting"
        field_choices.update({"/back": "Previous screen", "/cancel": "Return home and keep the draft"})
        text = ask("New value", current_text if current_text else None,
                   choices=field_choices, path=descriptor.kind == "path")
        if text == "/empty":
            text = ""
        if (required or descriptor.required) and not text:
            print("Please enter your organization's value.")
            continue
        try:
            value = parse_setting_value(descriptor, text)
            issues = validate_setting_value(descriptor, value)
            if issues:
                suggestion = suggest_https_base_url(text) if descriptor.kind == "url" else None
                if suggestion:
                    note(f"This looks like a base URL with a safe syntax correction: {suggestion}")
                    if yes("Use this corrected URL?"):
                        value = suggestion
                        issues = validate_setting_value(descriptor, value)
                if issues:
                    for issue in issues:
                        print(f"That value needs attention: {issue.message}")
                    continue
            doc.set(section, key, value)
            return
        except (ConfigError, ValueError, TypeError) as exc:
            suggestion = suggest_https_base_url(text) if descriptor.kind == "url" else None
            if suggestion:
                note(f"This looks like a base URL with a safe syntax correction: {suggestion}")
                if yes("Use this corrected URL?"):
                    doc.set(section, key, suggestion)
                    return
            print(f"That value needs attention: {exc}")


def rebase_document(doc) -> tuple:
    """Reload a changed settings file and explicitly resolve overlapping fields."""
    conflicts = doc.conflicts or doc.rebase()
    if conflicts:
        panel("Settings changed on disk",
              "Another process edited the same settings. Choose which value to keep for each overlap.",
              tone="warning")
        for conflict in conflicts:
            descriptor = descriptor_for(conflict.section, conflict.key)
            panel(descriptor.label,
                  f"File now has: {safe_display(conflict.disk) or '(empty)'}\n"
                  f"Your draft has: {safe_display(conflict.draft) or '(empty)'}")
            while True:
                choice = ask("Keep which value?", "draft",
                             choices={"draft": "Keep your pending value", "disk": "Use the newer file value",
                                      "/back": "Return without resolving this overlap",
                                      "/cancel": "Return home with this draft intact"}).lower()
                if choice in ("draft", "disk"):
                    doc.resolve_conflict(conflict.section, conflict.key, use=choice)
                    break
                note("Choose draft or disk. The overlap remains unresolved.")
    return conflicts


def rebase_with_recovery(doc) -> tuple:
    """Keep a draft recoverable while an externally edited file is repaired."""
    while True:
        try:
            return rebase_document(doc)
        except ConfigError as exc:
            panel("Cannot reload the configuration file", str(exc), tone="warning")
            menu("Reload actions", {"retry": "Try again after repairing the file",
                                    "home": "Return home with this draft retained"})
            action = ask("Reload", choices={"retry": "Read the file again", "home": "Return home",
                                             "/back": "Return to settings review",
                                             "/cancel": "Return home"}).lower()
            if action == "retry":
                continue
            if action == "home":
                raise Cancelled from None
            note("Choose retry or home.")


def save_document(doc) -> bool:
    issues = doc.issues()
    if issues:
        raise ConfigError("\n".join(issue.message for issue in issues))
    doc.validate()
    preview = doc.preview()
    before = decode_text_file(doc.path, "configuration") if doc.path.is_file() else ""
    changes = "".join(unified_diff(
        before.splitlines(keepends=True), preview.splitlines(keepends=True),
        fromfile=f"{doc.path} (current)", tofile=f"{doc.path} (proposed)",
    ))
    import tomllib
    try:
        original = tomllib.loads(before) if before else {}
    except tomllib.TOMLDecodeError:
        original = {}
    changed = []
    for d in setting_descriptors():
        old_table = original.get(d.section, {})
        old = old_table.get(d.key, d.default) if isinstance(old_table, dict) else d.default
        new = _table_value(doc, d.section, d.key, d.default)
        if display(old) != display(new):
            changed.append(f"{d.label}: {safe_display(old) or '(empty)'} → {safe_display(new) or '(empty)'}")
    panel("Review settings", "\n".join(changed) or "The settings already match this file.")
    note(f"Save to {doc.path.resolve()}. This changes local settings only.")
    while True:
        choice = ask("Save these settings?", "no", choices={"yes": "Save changes", "no": "Keep editing / cancel save", "details": "View the complete TOML diff"}).lower()
        if choice == "details":
            print(sanitize(changes) or "No file changes.")
            continue
        if choice in ("no", "n"):
            note("Nothing saved.")
            return False
        if choice in ("yes", "y"):
            break
        note("Choose yes, no, or details.")
    try:
        doc.save()
    except SettingsConflictError:
        rebase_with_recovery(doc)
        note("Reloaded the newer file and retained non-overlapping edits. Review the merged settings, then save again.",
             tone="warning")
        return False
    note(f"Saved {doc.path}. Preview tenant changes with Plan when you are ready.", tone="success")
    return True


def credentials(args, session, *, service_pair: bool = False) -> None:
    path = Path(args.env).expanduser().resolve()
    while True:
        before = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        try:
            file_values = {} if session.path_key(path) in session.ignored_env_files else read_dotenv(path)
            values, sources = session.values(path)
            break
        except ConfigError as exc:
            panel("Credentials file needs attention", str(exc), tone="warning")
            menu("Credential file actions", {
                "retry": "Try the file again after repairing it",
                "ignore": "Ignore this .env file for this SIA session",
                "back": "Return without changing credentials",
            })
            try:
                action = ask("Credential file", choices={
                    "retry": "Read the file again", "ignore": "Use shell/session credentials only",
                    "back": "Return", "/cancel": "Return home",
                }).lower()
            except Back:
                return
            if action == "retry":
                continue
            if action == "ignore":
                session.ignore_env_file(path)
                file_values = {}
                values, sources = session.values(path)
                note("This .env file is excluded for the current SIA session. The file itself was not changed.")
                break
            if action in ("back", ""):
                return
            note("Choose retry, ignore, or back.")
    heading("Sign-in credentials", "Your service user lets SIA read or update the tenant. Passwords are hidden.")
    keys = ("SIA_CLIENT_ID", "SIA_CLIENT_SECRET", "PVWA_USER", "PVWA_PASSWORD")
    labels = ("SIA service user", "SIA service-user password", "Vault user (optional)", "Vault password (optional)")
    options = {"sia": ("Set up SIA sign-in", "Enter the service user and its password together")}
    for number, (key, label) in enumerate(zip(keys, labels, strict=True), 1):
        shadow = "; saved file value overridden" if key in file_values and sources.get(key) != "file" else ""
        options[str(number)] = (label, f"{'Set' if values.get(key) else 'Missing'} · {sources.get(key, 'none')}{shadow}")
    options["5"] = ("Another account password", "Use the password variable from your account mapping")
    options["0"] = ("Back", "Return without changing credentials")
    if not service_pair:
        menu("Credentials", options)
    choice = "sia" if service_pair else ask("Credential", choices={key: value[0] for key, value in options.items()})
    if choice in ("", "0", "back"):
        return
    updates = {}
    if choice.lower() == "sia":
        while True:
            note("Step 1 of 2 · service user, usually a name such as svc_sia@your-tenant.cyberark.cloud")
            user = ask("Service user")
            if not user:
                note("Credentials unchanged.")
                return
            if not storable_env_value(user):
                note("The service user must be one line with no control characters.", tone="warning")
                continue
            note("Step 2 of 2 · service-user password. Nothing you type is displayed.")
            while True:
                password = prompt_secret("Service-user password (hidden; empty returns to service user): ")
                if not password:
                    note("No password entered. Returning to the service-user step; neither value has been retained.")
                    break
                if not storable_env_value(password):
                    note("A password must be one line with no control characters. Please enter it again.",
                         tone="warning")
                    continue
                break
            if password:
                break
        updates = {"SIA_CLIENT_ID": user, "SIA_CLIENT_SECRET": password}
    elif choice == "5":
        import re
        while True:
            key = ask("Environment variable name from strong_accounts.csv")
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) and key.upper().endswith("_PASSWORD"):
                break
            note("Choose a valid password environment-variable name ending in _PASSWORD.", tone="warning")
    elif choice in ("1", "2", "3", "4"):
        key = keys[int(choice) - 1]
    elif choice.lower() != "sia":
        print("Choose one of the listed numbers.")
        return
    if not updates:
        secret = key.endswith(("SECRET", "PASSWORD"))
        while True:
            value = prompt_secret(f"New {key} (hidden; empty cancels): ") if secret else ask(f"New {key}")
            if not value:
                print("Credential unchanged.")
                return
            if not storable_env_value(value):
                note("A credential must be one line with no control characters. Please enter it again.",
                     tone="warning")
                continue
            break
        updates[key] = value
    for key, value in updates.items():
        if key.endswith(("SECRET", "PASSWORD")):
            register_secret(value)
    if session.in_home:
        print("1. Keep for this home session only\n2. Save to the local .env file\n0. Cancel")
    else:
        print("2. Save to the local .env file\n0. Cancel\nFor session-only credentials, start sia and open Settings from its home screen.")
    storage_choices = ({"1": "This home session only", "2": "Save to .env", "0": "Cancel"}
                       if session.in_home else {"2": "Save to .env", "0": "Cancel"})
    while True:
        choice = ask("Where should these credentials be kept?", "1" if session.in_home else "2",
                     choices=storage_choices)
        if choice in storage_choices:
            break
        note("Choose one of the displayed storage options. Your newly entered credential is still held on this screen.",
             tone="warning")
    if choice == "1" and session.in_home:
        session.secrets.update(updates)
        print(f"{', '.join(updates)} stored for this session only.")
    elif choice == "2":
        if not yes(f"Save {', '.join(updates)} to {path.resolve()}?"):
            return
        while True:
            try:
                update_dotenv(path, updates, expected_digest=before)
                session.use_env_file(path)
                break
            except SettingsConflictError:
                panel("Credentials file changed",
                      "The .env file changed while this screen was open. Your newly entered credential is still held only on this screen.",
                      tone="warning")
                options = {"retry": "Merge this credential into the newer file", "back": "Do not save it"}
                if session.in_home:
                    options["session"] = "Keep it for this SIA session only"
                action = ask("Credential save", choices=options).lower()
                if action == "retry":
                    try:
                        read_dotenv(path)
                    except ConfigError as exc:
                        panel("The newer .env file needs repair", str(exc), tone="warning")
                        continue
                    before = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
                    continue
                if action == "session" and session.in_home:
                    session.secrets.update(updates)
                    note("Credential kept for this SIA session only.", tone="success")
                    return
                note("Credential unchanged.")
                return
            except WindowsCredentialProtectionError as exc:
                if exc.published:
                    # The write result is known, but its Windows DACL is not.
                    # Keep the values in memory so the current home session can
                    # continue while accurately reporting that the file exists.
                    if session.in_home:
                        session.secrets.update(updates)
                    session.use_env_file(path)
                    panel(
                        "Credential file permissions need attention",
                        f"Windows replaced {path}, but SIA could not confirm that only your account can read it. "
                        "The credentials may be present in that file. Run /doctor before using the saved file "
                        "in a new session.",
                        tone="warning",
                    )
                    if session.in_home:
                        note("The entered credentials are also available to this open SIA home session.")
                    return
                if session.in_home:
                    session.secrets.update(updates)
                    note(
                        "Windows could not create an owner-only credential file, so nothing was written. "
                        "SIA kept the credentials automatically for this home session only.",
                        tone="warning",
                    )
                    return
                panel(
                    "Credentials were not saved",
                    "Windows could not create an owner-only credential file, and a standalone command cannot "
                    "retain session credentials. Start sia, open /credentials, and the home session will keep "
                    "them in memory if secure file storage is unavailable.",
                    tone="warning",
                )
                return
            except ConfigError as exc:
                panel("Credentials file needs attention",
                      f"{exc}\n\nYour newly entered credential has not been written.", tone="warning")
                options = {"retry": "Try again after repairing the file", "back": "Do not save it"}
                if session.in_home:
                    options["session"] = "Keep it for this SIA session only"
                action = ask("Credential save", choices=options).lower()
                if action == "retry":
                    before = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
                    continue
                if action == "session" and session.in_home:
                    session.secrets.update(updates)
                    note("Credential kept for this SIA session only.", tone="success")
                    return
                note("Credential unchanged.")
                return
        for key in updates:
            session.secrets.pop(key, None)
        print("Saved credentials. Their values are hidden.")
    else:
        print("Credential unchanged.")
        return
    for key in updates:
        if key in session.shell_env:
            note(f"The exported {key} still takes precedence. Unset it before starting a new SIA session to use the saved value.")


# Each setting appears in one small, named group. Search still reaches every field.
SETTING_GROUPS = {
    "tenant": ("Tenant connection", ("tenant",), ()),
    "access": ("Access and sessions", (), ("time_zone", "days_of_week", "from_hour", "to_hour", "max_session_hours", "idle_minutes", "assign_local_groups", "enable_reconnect", "policy_status")),
    "accounts": ("Server accounts", (), ("strong_account_template", "strong_account_type", "strong_account_safe_template", "strong_account_account_name_template", "strong_account_username_template", "strong_account_domain", "target_set_scope", "target_set_cert_validation")),
    "policies": ("Policy names and groups", (), ("policy_name_template", "description_template", "policy_tags", "owner_tag", "template_policy", "group_template", "provision_format", "ssh_username")),
    "network": ("Network and certificates", ("http",), ()),
    "sign-in": ("Authentication options", ("auth",), ()),
    "connect": ("Connection exports", ("connect",), ()),
    "vault": ("Vault onboarding", ("pvwa",), ()),
}


def group_descriptors(group):
    _, sections, keys = SETTING_GROUPS[group]
    return [d for d in setting_descriptors() if d.section in sections or (d.section == "defaults" and d.key in keys)]


def edit_group(doc, descriptors, title):
    while True:
        options = {}
        for number, d in enumerate(descriptors, 1):
            value = _table_value(doc, d.section, d.key, d.default)
            options[str(number)] = f"{d.label}: {safe_display(value) or 'Not set'}"
        options["back"] = "Back — keep pending edits and return"
        options["cancel"] = "Cancel — return home and retain the settings draft"
        menu(title, options)
        choices = dict(options)
        choices.update({d.dotted_key: d.label for d in descriptors})
        try:
            selected = ask("Choose a setting", choices=choices)
            if selected in ("", "0", "back"):
                return
            if selected == "cancel":
                raise Cancelled
            d = next((d for d in descriptors if selected.lower() == d.dotted_key.lower()), None)
            if selected.isdigit() and 1 <= int(selected) <= len(descriptors):
                d = descriptors[int(selected) - 1]
            if d is None:
                note("Choose a setting number, or start typing its name to see suggestions.")
                continue
            try:
                edit_field(doc, d.section, d.key, required=d.section == "tenant" and d.key != "root_domain")
                note("Change pending. Save from Settings when you are finished.", tone="success")
            except Back:
                note("This field is unchanged.")
        except Back:
            return


def _groups_for_issues(issues) -> tuple[str, ...]:
    groups: list[str] = []
    for issue in issues:
        for section, key in issue.keys:
            for group in SETTING_GROUPS:
                if any(d.section == section and d.key == key for d in group_descriptors(group)):
                    if group not in groups:
                        groups.append(group)
                    break
    return tuple(groups)


def setup(args, session) -> int:
    heading("Set up this project", "Connect your tenant, review every local default, then add sign-in credentials.")
    note("Nothing is sent to CyberArk during setup. /back moves one screen; /cancel returns home and keeps this session's draft.")
    ensure_starter_config(args.config)
    try:
        draft = _open_draft(args, session, flow="setup")
    except ConfigError as exc:
        panel("Configuration file needs attention", str(exc), tone="warning")
        note("Repair the TOML in the displayed file, then run setup again. The file was not replaced.")
        return 2
    doc = draft.document
    step = draft.step if draft.step in ("tenant.subdomain", "tenant.identity_url", "review", "credentials") else "tenant.subdomain"
    if doc.preview() != draft.baseline:
        note("Resumed the unsaved setup draft for this configuration file.")
    try:
        while step != "credentials":
            draft.step = step
            if step == "tenant.subdomain":
                heading("1 of 3 · Your tenant")
                try:
                    edit_field(doc, "tenant", "subdomain", required=True)
                    step = "tenant.identity_url"
                except Back:
                    note(_draft_exit_message(
                        session,
                        "Setup draft retained. You are back home; use setup again in this session to resume it.",
                        "Setup closed. Unsaved changes are discarded when this standalone command exits.",
                    ))
                    return 2
                continue
            if step == "tenant.identity_url":
                heading("1 of 3 · Your tenant")
                try:
                    edit_field(doc, "tenant", "identity_url", required=True)
                    step = "review"
                except Back:
                    step = "tenant.subdomain"
                continue

            defaults = {key: _table_value(doc, "defaults", key, descriptor_for("defaults", key).default)
                        for key in ("time_zone", "days_of_week", "from_hour", "to_hour", "max_session_hours",
                                    "idle_minutes", "assign_local_groups", "strong_account_type", "policy_status",
                                    "target_set_cert_validation")}
            heading("2 of 3 · Review and save")
            panel("Starting settings", "\n".join((
                f"Time zone: {defaults['time_zone']}",
                f"Allowed days (0 = Sunday): {display(defaults['days_of_week'])}",
                f"Daily access: {defaults['from_hour'] or 'all day'}{(' to ' + defaults['to_hour']) if defaults['to_hour'] else ''}",
                f"Session limit: {defaults['max_session_hours']} hours · idle timeout: {defaults['idle_minutes']} minutes",
                f"Temporary Windows user groups: {', '.join(defaults['assign_local_groups'] or [])}",
                f"Account source: {defaults['strong_account_type']} · new policies: {defaults['policy_status']}",
                f"Validate target certificates: {display(defaults['target_set_cert_validation'])}",
            )))
            review_options = {group: SETTING_GROUPS[group][0] for group in SETTING_GROUPS}
            review_options.update({"continue": "Validate, review, and save", "back": "Return to Identity URL",
                                   "discard": "Discard this setup draft", "cancel": "Return home and retain this draft"})
            current_issues = doc.issues()
            external_issues = tuple(issue for issue in current_issues
                                    if issue.code in ("unknown", "parse") or not _groups_for_issues((issue,)))
            if external_issues:
                panel("Configuration file needs external repair",
                      "\n".join(issue.message for issue in external_issues), tone="warning")
                review_options["reload"] = "Reload after repairing the displayed file"
            menu("Review actions", review_options)
            try:
                choice = ask("Continue or customize?", "continue", choices=review_options).lower()
            except Back:
                step = "tenant.identity_url"
                continue
            if choice in SETTING_GROUPS:
                edit_group(doc, group_descriptors(choice), SETTING_GROUPS[choice][0])
            elif choice == "back":
                step = "tenant.identity_url"
            elif choice == "cancel":
                raise Cancelled
            elif choice == "discard":
                if yes("Discard all unsaved setup changes?"):
                    _clear_draft(args, session)
                    note("Setup draft discarded.")
                    return 2
            elif choice == "reload":
                rebase_with_recovery(doc)
                note("Configuration reloaded. Non-overlapping setup answers were retained.")
            elif choice == "continue":
                issues = current_issues
                if issues:
                    panel("Settings need attention", "\n".join(f"• {issue.message}" for issue in issues), tone="warning")
                    groups = _groups_for_issues(issues)
                    if external_issues:
                        note("Repair the displayed TOML file externally, then choose reload. Your known setting edits remain in this draft.")
                    else:
                        note("Repair the highlighted " + (", ".join(groups) if groups else "settings") + ". Your other edits remain in this draft.")
                    continue
                try:
                    if save_document(doc):
                        _clear_draft(args, session)
                        step = "credentials"
                except Back:
                    note("Returned to setup review. The merged draft is still available.")
            else:
                note("Choose one of the displayed actions.")

        heading("3 of 3 · Service-user sign-in")
        if yes("Add your service user and password now?", default=True):
            credentials(args, session, service_pair=True)
        values, _ = session.values(args.env)
        if not all(values.get(key) for key in ("SIA_CLIENT_ID", "SIA_CLIENT_SECRET")):
            note("Configuration saved. Sign-in is still incomplete; open Credentials when you have your service-user details.")
        panel("Setup saved", "Next: open Troubleshoot to check your files. Its optional tenant check tests sign-in without changing the tenant.")
        return 0
    except Back:
        if step == "credentials":
            note(f"Credential setup cancelled. Configuration remains saved at {Path(args.config).resolve()}.")
        else:
            note(_draft_exit_message(
                session,
                "Setup draft retained. Use setup again in this home session to resume it.",
                "Setup closed. Unsaved changes are discarded when this standalone command exits.",
            ))
        return 2
    except Cancelled:
        if step == "credentials":
            note(f"Credential setup cancelled. Configuration remains saved at {Path(args.config).resolve()}.")
        else:
            note(_draft_exit_message(
                session,
                "Setup cancelled. Unsaved non-secret settings remain available in this home session.",
                "Setup cancelled. Unsaved changes are discarded when this standalone command exits.",
            ))
        return 2
    except EOFError:
        if step == "credentials":
            note(f"Credential input closed. Configuration remains saved at {Path(args.config).resolve()}.")
        else:
            note(_draft_exit_message(
                session,
                "Setup input closed. Unsaved non-secret settings remain available in this home session.",
                "Setup input closed. Unsaved changes are discarded when this standalone command exits.",
            ))
        return 2
    except KeyboardInterrupt:
        print()
        if step == "credentials":
            note(f"Credential setup interrupted. Configuration remains saved at {Path(args.config).resolve()}.")
        else:
            note(_draft_exit_message(
                session,
                "Setup interrupted. Unsaved non-secret settings remain available in this home session.",
                "Setup interrupted. Unsaved changes are discarded when this standalone command exits.",
            ))
        return 130


def settings(args, session) -> int:
    if args.show:
        return 2 if show_settings(args, session).get("diagnostics") else 0
    if not Path(args.config).exists():
        note("No configuration file yet. Opening guided setup.")
        return setup(args, session)
    while True:
        try:
            draft = _open_draft(args, session, flow="settings")
            break
        except ConfigError as exc:
            panel("Configuration file needs attention", str(exc), tone="warning")
            menu("Configuration actions", {"retry": "Try again after repairing the file",
                                            "back": "Return home without changing it"})
            try:
                action = ask("Configuration file", choices={"retry": "Read it again", "back": "Return home",
                                                                    "/cancel": "Return home"}).lower()
            except (Back, Cancelled, EOFError):
                return 2
            except KeyboardInterrupt:
                return 130
            if action == "retry":
                continue
            return 2
    doc = draft.document
    if doc.preview() != draft.baseline:
        note("Resumed this configuration file's unsaved settings draft.")
    shown_structural: tuple[str, ...] = ()
    while True:
        heading("Settings", f"{doc.path.name} · {'Unsaved changes' if doc.preview() != draft.baseline else 'No pending changes'}")
        all_issues = doc.issues()
        structural = tuple(issue.message for issue in all_issues
                           if issue.code in ("unknown", "parse") or not _groups_for_issues((issue,)))
        if structural and structural != shown_structural:
            panel("Configuration structure needs attention", "\n".join(structural), tone="warning")
            note("Repair the displayed file externally, then choose reload. Pending edits will be merged onto the repaired file.")
            shown_structural = structural
        menu_options = {
            "tenant": "Tenant name and Identity URL",
            "access": "Access schedule, session limits and permissions",
            "accounts": "Server account source and naming conventions",
            "credentials": "Service-user and optional Vault sign-in",
            "advanced": "Policies, network, authentication and exports",
            "paths": "See which project files are in use",
            "save": "Review and save pending changes",
            "validate": "Check every local setting",
            "back": "Return home and retain pending changes",
            "discard": "Discard this file's pending changes",
            "cancel": "Return home and retain pending changes",
        }
        if structural:
            menu_options["reload"] = "Reload after repairing the configuration file"
        menu("Choose a group", menu_options)
        note("Type a group, or search any setting by name (for example: timeout). /back returns home; /cancel also retains the draft.")
        choices = {key: label for key, (label, _, _) in SETTING_GROUPS.items()}
        choices.update({"credentials": "Manage sign-in", "advanced": "More setting groups", "paths": "Project files",
                        "validate": "Check local settings", "save": "Review and save", "back": "Return home",
                        "discard": "Discard pending changes", "cancel": "Return home and retain changes"})
        if structural:
            choices["reload"] = "Reload after external repair"
        choices.update({d.dotted_key: d.label for d in setting_descriptors()})
        at_main = True
        try:
            choice = ask("Settings", choices=choices).lower()
            at_main = False
            if choice in ("back", ""):
                note(_draft_exit_message(
                    session,
                    "Settings closed. Pending edits remain available in this home session.",
                    "Settings closed. Unsaved changes are discarded when this standalone command exits.",
                ))
                return 0
            elif choice == "cancel":
                raise Cancelled
            elif choice == "discard":
                if yes("Discard this configuration file's unsaved changes?"):
                    _clear_draft(args, session)
                    note("Settings draft discarded.")
                    return 0
            elif choice == "reload":
                rebase_with_recovery(doc)
                shown_structural = ()
                note("Configuration reloaded. Non-overlapping pending edits were retained; review before saving.")
            elif choice in SETTING_GROUPS:
                edit_group(doc, group_descriptors(choice), SETTING_GROUPS[choice][0])
            elif choice == "advanced":
                groups = ("policies", "network", "sign-in", "connect", "vault")
                menu("Advanced settings", {key: (SETTING_GROUPS[key][0], "") for key in groups})
                selected = ask("Group", choices={**{key: SETTING_GROUPS[key][0] for key in groups},
                                                  "back": "Return to Settings", "/cancel": "Return home"})
                if selected in groups:
                    edit_group(doc, group_descriptors(selected), SETTING_GROUPS[selected][0])
                elif selected not in ("", "back"):
                    note("Choose one of the listed groups.")
            elif choice == "credentials":
                credentials(args, session)
            elif choice == "paths":
                panel("Project files", "\n".join(f"{key.capitalize()}: {value}" for key, value in paths(args).items()))
                note("Paths inside TOML resolve beside config.toml. Command-line paths resolve from the working directory.")
            elif choice == "validate":
                issues = doc.issues()
                if issues:
                    panel("Settings need attention", "\n".join(f"• {issue.message}" for issue in issues), tone="warning")
                    groups = _groups_for_issues(issues)
                    if groups:
                        note("Open one of these groups to repair them: " + ", ".join(groups))
                else:
                    note("Local settings are valid. Tenant values have not been checked.", tone="success")
            elif choice == "save":
                if save_document(doc):
                    _clear_draft(args, session)
                    return 0
            else:
                descriptors = [d for d in setting_descriptors() if choice in f"{d.dotted_key} {d.label} {d.help}".lower()]
                if descriptors:
                    if len(descriptors) == 1:
                        d = descriptors[0]
                        edit_field(doc, d.section, d.key)
                    else:
                        edit_group(doc, descriptors, f"Settings matching {choice!r}")
                else:
                    note("No setting matched. Try a word such as tenant, timeout, or certificate.")
        except Back:
            if at_main:
                note(_draft_exit_message(
                    session,
                    "Settings closed. Pending edits remain available in this home session.",
                    "Settings closed. Unsaved changes are discarded when this standalone command exits.",
                ))
                return 0
            note("Returned to Settings. Your pending edits are still here.")
        except Cancelled:
            note(_draft_exit_message(
                session,
                "Settings cancelled. Pending non-secret edits remain available in this home session.",
                "Settings cancelled. Unsaved changes are discarded when this standalone command exits.",
            ))
            return 2
        except EOFError:
            note(_draft_exit_message(
                session,
                "Settings input closed. Pending non-secret edits remain available in this home session.",
                "Settings input closed. Unsaved changes are discarded when this standalone command exits.",
            ))
            return 2
        except KeyboardInterrupt:
            print()
            note(_draft_exit_message(
                session,
                "Settings interrupted. Pending non-secret edits remain available in this home session.",
                "Settings interrupted. Unsaved changes are discarded when this standalone command exits.",
            ))
            return 130
        except ConfigError as exc:
            render_diagnostic(diagnose(exc, stage="Settings"), sys.stdout, verbose=args.verbose)
            note("The settings draft is still available. Repair the indicated value or return home.")
        except Exception as exc:
            render_diagnostic(diagnose(exc, stage="Settings"), sys.stdout, verbose=args.verbose)
            note("Settings closed after an unexpected local error. The in-memory draft is still available.")
            return 2


def _powershell_literal(value: str) -> str:
    """Return one inert PowerShell single-quoted string literal."""
    return "'" + str(value).replace("'", "''") + "'"


def command_string(argv: list[str], *, windows: bool | None = None) -> str:
    """Render a pasteable equivalent command for the current platform.

    PowerShell interpolates variables and subexpressions in double-quoted
    strings.  Quote every displayed argument with a single-quoted literal so
    paths and operator characters remain data when an operator pastes the
    reviewed command into PowerShell.
    """
    use_windows = os.name == "nt" if windows is None else windows
    if use_windows:
        return " ".join(["sia", *(_powershell_literal(value) for value in argv)])
    return shlex.join(["sia", *argv])


def _split_windows_command_line(text: str) -> list[str]:
    """Parse direct home-prompt argv using common PowerShell/CRT quoting.

    This parser only creates strings for the in-process CLI dispatcher.  It
    never invokes PowerShell or cmd.exe, so ``$``, backticks, ``&`` and other
    shell metacharacters are passed literally and cannot expand or execute.
    PowerShell single-quoted literals (including doubled apostrophes) and the
    double-quoted/backslash form produced by ``subprocess.list2cmdline`` are
    both accepted.
    """
    result: list[str] = []
    index = 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        value: list[str] = []
        quoted = False
        single_quoted = False
        started = False
        while index < len(text) and (quoted or single_quoted or not text[index].isspace()):
            started = True
            if single_quoted:
                if text[index] == "'":
                    if index + 1 < len(text) and text[index + 1] == "'":
                        value.append("'")
                        index += 2
                    else:
                        single_quoted = False
                        index += 1
                else:
                    value.append(text[index])
                    index += 1
                continue
            if not quoted and text[index] == "'":
                single_quoted = True
                index += 1
                continue
            if text[index] == "\\":
                start = index
                while index < len(text) and text[index] == "\\":
                    index += 1
                count = index - start
                if index < len(text) and text[index] == '"':
                    value.extend("\\" * (count // 2))
                    if count % 2:
                        value.append('"')
                    else:
                        quoted = not quoted
                    index += 1
                else:
                    value.extend("\\" * count)
                continue
            if text[index] == '"':
                if quoted and index + 1 < len(text) and text[index + 1] == '"':
                    value.append('"')
                    index += 2
                else:
                    quoted = not quoted
                    index += 1
                continue
            value.append(text[index])
            index += 1
        if quoted or single_quoted:
            kind = "double" if quoted else "single"
            raise ValueError(f"Unmatched {kind} quote in command. Close the quote and try again.")
        if started:
            result.append("".join(value))
    return result


def split_command_line(text: str, *, windows: bool | None = None) -> list[str]:
    """Round-trip the current platform's command syntax, including quoted paths."""
    use_windows = os.name == "nt" if windows is None else windows
    cleaned = _split_windows_command_line(text) if use_windows else shlex.split(text)
    if cleaned:
        executable = PureWindowsPath(cleaned[0]).name if use_windows else Path(cleaned[0]).name
        if executable.lstrip("/").casefold() in ("sia", "sia.exe"):
            cleaned = cleaned[1:]
    if cleaned and cleaned[0].startswith("/"):
        cleaned[0] = cleaned[0][1:]
    return cleaned


def _workflow_steps(command: str, args, answers: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = [
        {"key": "source", "label": "Work with a server list or one server?", "default": "1",
         "choices": {"1": "Server list (CSV files)", "2": "One server"}, "kind": "choice"},
    ]
    if answers.get("source") == "2":
        steps.extend([
            {"key": "server", "label": "Server FQDN", "kind": "fqdn"},
            {"key": "group", "label": "Identity group (empty uses naming convention)", "kind": "text"},
            {"key": "ssh", "label": "Is this an SSH/Linux server?", "default": False, "kind": "bool"},
        ])
        if answers.get("ssh") is True:
            steps.append({"key": "ssh_username", "label": "SSH username", "kind": "required_text"})
        else:
            steps.append({"key": "workgroup", "label": "Is this a workgroup server (not domain-joined)?",
                          "default": False, "kind": "bool"})
    steps.append({"key": "input", "label": "Folder containing your CSV files",
                  "default": getattr(args, "input", "input"), "kind": "path"})
    if command in ("plan", "apply"):
        steps.append({"key": "update", "label": "Include updates to existing managed objects?",
                      "default": False, "kind": "bool"})
        if answers.get("update") is True:
            steps.append({"key": "policy_state", "label": "Existing policy status", "default": "keep", "kind": "choice",
                          "choices": {"keep": "Leave current status unchanged", "Active": "Activate selected policies",
                                      "Suspended": "Suspend selected policies"}})
        steps.extend([
            {"key": "resume", "label": "Resume completed rows from a matching checkpoint?", "default": False, "kind": "bool"},
            {"key": "advanced", "label": "Configure advanced run options (waves, workers, adoption)?",
             "default": False, "kind": "bool"},
        ])
        if answers.get("advanced") is True:
            steps.extend([
                {"key": "offset", "label": "First server offset", "default": "0", "kind": "nonnegative"},
                {"key": "limit", "label": "Maximum servers (0 = all)", "default": "0", "kind": "nonnegative"},
                {"key": "workers", "label": "Workers (1-16)", "default": "1", "kind": "workers"},
                {"key": "lookup", "label": "Lookup mode", "default": "auto", "kind": "choice",
                 "choices": {"auto": "Detect", "search": "Per server", "list": "List objects"}},
                {"key": "only", "label": "Stage", "default": "all", "kind": "choice",
                 "choices": {key: "" for key in ("all", "vault", "secrets", "targetsets", "policies")}},
                {"key": "progress_every", "label": "Log progress every N objects (0 = off)", "default": "100", "kind": "nonnegative"},
                {"key": "checkpoint", "label": "Checkpoint file (empty uses the input directory)", "kind": "path"},
                {"key": "passwords", "label": "Password CSV path (empty uses configured file or hidden prompts)", "kind": "path"},
            ])
            if answers.get("update") is True:
                steps.append({"key": "adopt", "label": "Adopt an unmanaged server FQDN (empty adopts none)", "kind": "optional_fqdn"})
            steps.append({"key": "keep_going", "label": "Continue after a rejected create/update instead of stopping?",
                          "default": False, "kind": "bool"})
    elif command == "connect-info":
        steps.extend([
            {"key": "tenant", "label": "Read tenant status before exporting?", "default": True, "kind": "bool"},
            {"key": "login_user", "label": "Login user (empty leaves a user placeholder)", "kind": "text"},
            {"key": "output", "label": "CSV output path (empty creates one in reports)", "kind": "path"},
            {"key": "rdp", "label": "RDP file directory (empty skips RDP files)", "kind": "path"},
        ])
    elif command == "verify":
        steps.append({"key": "output", "label": "Verification CSV path (empty prints the result only)", "kind": "path"})
    return steps


def _prompt_workflow_step(step: dict[str, Any], previous: Any = None) -> Any:
    default = previous if previous is not None else step.get("default")
    kind = step["kind"]
    if kind == "bool":
        return yes(step["label"], default=bool(default))
    while True:
        text = ask(step["label"], None if default is None else str(default),
                   choices=step.get("choices"), path=kind == "path")
        try:
            if kind == "choice":
                choices = step["choices"]
                match = next((value for value in choices if text.casefold() == value.casefold()), None)
                if match is None:
                    raise ConfigError("Choose one of the displayed values.")
                return match
            if kind in ("fqdn", "optional_fqdn"):
                if not text and kind == "optional_fqdn":
                    return ""
                return validate_dns_name(step["label"], text)
            if kind == "required_text" and not text:
                raise ConfigError(f"{step['label']} is required.")
            if kind in ("text", "required_text"):
                if any(not char.isprintable() or char in "\r\n\x00" for char in text):
                    raise ConfigError(f"{step['label']} must contain printable text on one line.")
                return text
            if kind in ("nonnegative", "workers"):
                value = int(text)
                if kind == "nonnegative" and value < 0:
                    raise ConfigError(f"{step['label']} must be zero or greater.")
                if kind == "workers" and not 1 <= value <= 16:
                    raise ConfigError("Workers must be from 1 through 16.")
                return str(value)
            return text
        except (ConfigError, ValueError) as exc:
            note(f"That answer needs attention: {exc}", tone="warning")


def _workflow_argv(command: str, answers: dict[str, Any]) -> list[str]:
    argv = [command]
    if answers.get("source") == "2":
        argv += ["--server", answers["server"]]
        if answers.get("group"):
            argv += ["--group", answers["group"]]
        if answers.get("ssh"):
            argv += ["--protocol", "ssh", "--ssh-username", answers["ssh_username"]]
        elif answers.get("workgroup"):
            argv.append("--workgroup")
    argv += ["--input", answers["input"]]
    if command in ("plan", "apply", "verify"):
        argv.append("--drift")
    if command in ("plan", "apply"):
        if answers.get("update"):
            argv.append("--update")
            if answers.get("policy_state", "keep") != "keep":
                argv += ["--set-policy-status", answers["policy_state"]]
        if answers.get("resume"):
            argv.append("--resume")
        if answers.get("advanced"):
            for key, flag in (("offset", "--offset"), ("limit", "--limit"), ("workers", "--workers"),
                              ("lookup", "--lookup"), ("only", "--only"), ("progress_every", "--progress-every")):
                argv += [flag, answers[key]]
            for key, flag in (("checkpoint", "--checkpoint"), ("passwords", "--passwords"), ("adopt", "--adopt")):
                if answers.get(key):
                    argv += [flag, answers[key]]
            if answers.get("keep_going"):
                argv.append("--keep-going")
    if command == "connect-info":
        if not answers.get("tenant", True):
            argv.append("--no-tenant")
        for key, flag in (("login_user", "--login-user"), ("output", "--out"), ("rdp", "--rdp-dir")):
            if answers.get(key):
                argv += [flag, answers[key]]
    elif command == "verify" and answers.get("output"):
        argv += ["--out", answers["output"]]
    return argv


def workflow(command: str, args) -> list[str]:
    descriptions = {"plan": "Preview what would change. This reads the tenant and does not apply changes.",
                    "apply": "Prepare changes. You will review the plan and confirm before anything is applied.",
                    "verify": "Read the tenant and check whether server access is configured as expected.",
                    "connect-info": "Create connection instructions for your servers."}
    heading(command.replace("-", " ").title(), descriptions[command])
    note("Answer a few questions to prepare this run. Enter accepts a default; /back moves one answer; /cancel returns home.")
    answers: dict[str, Any] = {}
    index = 0
    while True:
        steps = _workflow_steps(command, args, answers)
        if index < len(steps):
            step = steps[index]
            try:
                answers[step["key"]] = _prompt_workflow_step(step, answers.get(step["key"]))
                index += 1
            except Back:
                if index == 0:
                    raise
                index -= 1
            continue
        argv = _workflow_argv(command, answers)
        panel("Review run", "Equivalent command:\n" + command_string(argv))
        choices = {"run": "Run this reviewed command", "edit": "Return to an answer",
                   "cancel": "Return home without running"}
        try:
            action = ask("Run or edit?", "run", choices=choices).lower()
        except Back:
            index = max(0, len(steps) - 1)
            continue
        if action == "run":
            return argv
        if action == "cancel":
            raise Cancelled
        if action == "edit":
            editable = {str(number): step["label"] for number, step in enumerate(steps, 1)}
            menu("Answers", editable)
            try:
                selected = ask("Answer to edit", choices={**editable, "back": "Return to review"})
            except Back:
                continue
            if selected == "back":
                continue
            if selected.isdigit() and 1 <= int(selected) <= len(steps):
                index = int(selected) - 1
            else:
                note("Choose an answer number.")
            continue
        note("Choose run, edit, or cancel.")


HOME_COMMANDS = {
    "/setup": "Fill in your tenant details",
    "/settings": "Edit configuration by topic or search",
    "/credentials": "Add your service user and password",
    "/doctor": "Troubleshoot files and optional tenant access",
    "/plan": "Preview server changes without applying them",
    "/apply": "Review and apply server changes",
    "/verify": "Check current server configuration",
    "/connect-info": "Get connection instructions",
    "/help": "Read help or explain an error code",
    "/menu": "Show the home menu again",
    "/exit": "Close SIA",
}


def readiness(args, session):
    draft = session.config_drafts.get(_draft_key(args))
    if draft is not None and draft.document.preview() != draft.baseline:
        return "Unsaved settings draft", "Next: /settings or /setup — resume the pending edits for this configuration file."
    try:
        if missing_tenant_fields(args.config):
            return "Setup needed", "Next: /setup — fill in your tenant name and Identity URL."
        cfg = load_config(args.config)
    except Exception:
        return "Configuration needs attention", "Next: /doctor — find the setting or file that needs fixing."
    try:
        values, _ = session.values(args.env)
        if not all(values.get(key) for key in ("SIA_CLIENT_ID", "SIA_CLIENT_SECRET")):
            return f"Tenant: {cfg.tenant.subdomain} · sign-in incomplete", "Next: /credentials — add your service user and password."
    except Exception:
        return f"Tenant: {cfg.tenant.subdomain} · credentials need attention", "Next: /doctor — check the credentials file."
    return f"Tenant: {cfg.tenant.subdomain} · sign-in configured", "Next: /doctor to check access, or /plan to preview changes."


def home(args, session, run: Callable[[list[str]], int]) -> int:
    session.in_home = True
    created = ensure_starter_config(args.config)
    heading("SIA · Infrastructure access", "Configure CyberArk server access. Preview changes before applying them.")
    note(f"Project: {Path(args.config).resolve().parent.name} · configuration: {Path(args.config).name}")
    if created:
        note(f"Created starter configuration: {Path(args.config).resolve()}")
    aliases = {"1": "setup", "2": "settings", "3": "doctor", "4": "plan", "5": "apply", "6": "verify",
               "7": "connect-info", "8": "help", "0": "exit", "quit": "exit", "troubleshoot": "doctor"}
    choices = dict(HOME_COMMANDS)
    from .help import TOPICS
    choices.update({f"/help {key}": title for key, (title, _) in TOPICS.items()})
    show_menu = True
    show_status = True
    while True:
        if show_status:
            status, next_step = readiness(args, session)
            panel(status, next_step)
            show_status = False
        if show_menu:
            menu("What would you like to do?", {key: description
                 for key, description in HOME_COMMANDS.items() if key not in ("/menu", "/exit")})
            note("Type / for suggestions · Tab completes · ↑/↓ selects · Enter runs · /exit closes")
            show_menu = False
        try:
            choice = ask("sia", choices=choices, commands=True)
            if not choice:
                continue
            try:
                tokens = split_command_line(choice)
            except ValueError as exc:
                note(str(exc), tone="warning")
                continue
            if not tokens:
                continue
            command = aliases.get(tokens[0].lstrip('/').lower(), tokens[0].lstrip('/').lower())
            arguments = tokens[1:]
            if command in ("exit", "menu", "credentials") and arguments:
                note(f"/{command} does not take arguments. Use /{command} on its own.")
                continue
            if command == "exit":
                pending = session.pending_drafts()
                if pending and not yes(f"Exit and discard {len(pending)} unsaved settings draft(s)?"):
                    note("Exit cancelled. Open /settings to review or discard the pending draft.")
                    continue
                note("SIA closed. Saved settings remain in config.toml; session-only credentials are cleared when this process exits.")
                return 0
            if command == "menu":
                show_menu = show_status = True
                continue
            if command == "help":
                heading("Help")
                # Wrap paragraphs while preserving lists and line breaks.
                for paragraph in help_text(" ".join(arguments)).split("\n\n"):
                    note(paragraph, tone="info")
                    print()
                continue
            if command == "credentials":
                credentials(args, session, service_pair=True)
                show_status = True
                continue
            if command not in ("doctor", "plan", "apply", "verify", "connect-info", "settings", "setup", "preflight"):
                note("That command is not available. Type / to see suggestions, or /menu for the full menu.")
                continue
            if arguments:
                # Explicit arguments follow exactly the same parser as the standalone CLI.
                argv = [command, *arguments]
                if command in ("plan", "apply", "verify", "connect-info", "doctor") and not any(arg == "--input" or arg.startswith("--input=") for arg in arguments):
                    argv += ["--input", getattr(args, "input", "input")]
            elif command == "doctor":
                heading("Troubleshoot", "Check local setup first. You can also test tenant access without changing it.")
                for item in session.last_diagnostics:
                    panel(f"Last problem · {item['code']}", "\n".join([item['message'], *item.get('actions', [])]), tone="warning")
                argv = ["doctor", "--input", getattr(args, "input", "input")]
                if yes("Also check sign-in and tenant access?"):
                    argv.append("--online")
            elif command in ("plan", "apply", "verify", "connect-info"):
                argv = workflow(command, args)
            else:
                argv = [command]
            session.last_exit_code = run(argv)
            result = {0: "Finished", 1: "Needs attention — see the result above or open /doctor", 2: "Could not finish — review the message above", 130: "Interrupted"}.get(session.last_exit_code, "Needs attention")
            note(f"{command}: {result}.", tone="success" if session.last_exit_code == 0 else "warning")
            note("Choose another command. /menu shows all options.")
            show_status = command in ("settings", "setup")
        except (Back, Cancelled, KeyboardInterrupt):
            note("Cancelled. You are back home; unsaved workflow settings were discarded.")
        except EOFError:
            note("Session closed.")
            return 0
        except Exception as exc:
            diagnostic = diagnose(exc, stage="Terminal")
            session.last_diagnostics = [diagnostic.to_dict()]
            render_diagnostic(diagnostic, sys.stdout, verbose=args.verbose)
