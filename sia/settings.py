"""Editable, source-aware settings files for the interactive terminal interface.

This module deliberately contains no prompts.  It provides the typed catalogue and
safe file operations; callers decide how to present them.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import tempfile
from dataclasses import MISSING, dataclass, field, fields
from pathlib import Path
from typing import Any, Mapping, get_args, get_origin, get_type_hints

import tomlkit
from tomlkit.exceptions import TOMLKitError
from tomlkit.toml_document import TOMLDocument

from .config import (
    AuthConfig,
    Config,
    ConfigError,
    ConfigValidationError,
    ConnectConfig,
    Defaults,
    HttpConfig,
    IDENTITY_AUTH_METHODS,
    POLICY_STATUSES,
    PVWA_AUTH_TYPES,
    PVWAConfig,
    REQUIRED_DEFAULT_KEYS,
    SECRETS_API_FAMILIES,
    SECTIONS,
    STRONG_ACCOUNT_TYPES,
    TARGETSETS_API_FAMILIES,
    TARGET_SET_SCOPES,
    TenantConfig,
    ValidationIssue,
    decode_text_bytes,
    decode_text_file,
    parse_config,
    read_dotenv,
    scan_quoted_value,
    toml_error_hint,
    validate_field,
)
from .windows_security import (
    WindowsCredentialProtectionError,
    create_protected_temporary_file,
    inspect_credential_permissions,
    protect_credential_file,
    windows_acl_supported,
)


class SettingsConflictError(ConfigError):
    """The settings file changed on disk after it was opened."""


@dataclass(frozen=True)
class SettingsMergeConflict:
    """One setting changed both in the draft and on disk since it was opened."""

    section: str
    key: str
    base: Any
    disk: Any
    draft: Any

    @property
    def dotted_key(self) -> str:
        return f"{self.section}.{self.key}"


@dataclass(frozen=True)
class SettingDescriptor:
    section: str
    key: str
    label: str
    help: str
    kind: str
    default: Any = None
    choices: tuple[str, ...] = ()
    required: bool = False
    basic: bool = False

    @property
    def dotted_key(self) -> str:
        return f"{self.section}.{self.key}"


@dataclass(frozen=True)
class SettingValue:
    descriptor: SettingDescriptor
    value: Any
    source: str                         # "config file" or "tool default"


_SECTION_CLASSES = {
    "tenant": TenantConfig,
    "defaults": Defaults,
    "auth": AuthConfig,
    "http": HttpConfig,
    "connect": ConnectConfig,
    "pvwa": PVWAConfig,
}

_CHOICES: dict[tuple[str, str], tuple[str, ...]] = {
    ("defaults", "policy_status"): POLICY_STATUSES,
    ("defaults", "strong_account_type"): STRONG_ACCOUNT_TYPES,
    ("defaults", "target_set_scope"): TARGET_SET_SCOPES,
    ("auth", "identity_auth"): IDENTITY_AUTH_METHODS,
    ("http", "secrets_api"): SECRETS_API_FAMILIES,
    ("http", "targetsets_api"): TARGETSETS_API_FAMILIES,
    ("pvwa", "auth_type"): PVWA_AUTH_TYPES,
}

_KINDS: dict[tuple[str, str], str] = {
    ("tenant", "identity_url"): "url",
    ("defaults", "time_zone"): "timezone",
    ("defaults", "policy_name_template"): "template",
    ("defaults", "description_template"): "template",
    ("defaults", "group_template"): "template",
    ("defaults", "strong_account_template"): "template",
    ("defaults", "strong_account_safe_template"): "template",
    ("defaults", "strong_account_account_name_template"): "template",
    ("defaults", "strong_account_username_template"): "template",
    ("defaults", "strong_account_domain"): "template",
    ("auth", "password_file"): "path",
    ("http", "ca_bundle"): "path",
    ("pvwa", "base_url"): "url",
}

_BASIC = {
    ("tenant", "subdomain"), ("tenant", "identity_url"),
    ("defaults", "time_zone"), ("defaults", "days_of_week"),
    ("defaults", "from_hour"), ("defaults", "to_hour"),
    ("defaults", "target_set_cert_validation"), ("defaults", "max_session_hours"),
    ("defaults", "idle_minutes"), ("defaults", "assign_local_groups"),
    ("defaults", "enable_reconnect"), ("defaults", "group_template"),
    ("defaults", "target_set_scope"), ("defaults", "strong_account_template"),
    ("defaults", "strong_account_type"), ("defaults", "strong_account_safe_template"),
    ("defaults", "strong_account_account_name_template"),
    ("defaults", "strong_account_username_template"), ("defaults", "strong_account_domain"),
    ("auth", "identity_auth"), ("connect", "login_suffix"),
    ("connect", "gateway_host"), ("connect", "network"),
}

_LABELS = {
    "identity_url": "Identity tenant URL",
    "root_domain": "CyberArk root domain",
    "fqdn": "FQDN",
    "policy_tags": "Policy tags",
    "policy_status": "New policy status",
    "time_zone": "Time zone",
    "from_hour": "Access starts",
    "to_hour": "Access ends",
    "target_set_cert_validation": "Validate target certificates",
    "pvwa": "PVWA",
    "base_url": "PVWA base URL",
    "ca_bundle": "Custom CA bundle",
    "system_trust": "Use system trust store",
    "cpm_managed": "CPM manages passwords",
    "oidc_application": "OIDC application",
}

_HELP: dict[tuple[str, str], str] = {
    ("tenant", "subdomain"): "Tenant name before .cyberark.cloud, for example acme.",
    ("tenant", "identity_url"): "Identity tenant base URL, for example https://abc1234.id.cyberark.cloud.",
    ("tenant", "root_domain"): "CyberArk platform root domain. Keep cyberark.cloud unless your tenant uses another domain.",
    ("defaults", "policy_name_template"): "Name for generated policies. {fqdn} is the safest unique default.",
    ("defaults", "description_template"): "Description for generated policies; supports server placeholders and {protocol}.",
    ("defaults", "policy_tags"): "Tags added to new policies, in addition to the ownership tag.",
    ("defaults", "policy_status"): "Status used only when a policy is created. Existing policy status is preserved unless explicitly changed.",
    ("defaults", "time_zone"): "IANA time zone used for the access schedule, for example America/Chicago.",
    ("defaults", "days_of_week"): "Allowed days: 0 is Sunday through 6 is Saturday.",
    ("defaults", "from_hour"): "Daily access start in 24-hour HH:MM form. Leave both times blank for all day.",
    ("defaults", "to_hour"): "Daily access end in 24-hour HH:MM form. Leave both times blank for all day.",
    ("defaults", "max_session_hours"): "Maximum connected session length, from 1 through 24 hours.",
    ("defaults", "idle_minutes"): "Disconnect an idle session after 1 through 120 minutes.",
    ("defaults", "assign_local_groups"): "Windows local groups assigned to the temporary user.",
    ("defaults", "enable_reconnect"): "Allow the same temporary user to reconnect during the original session window.",
    ("defaults", "target_set_cert_validation"): "Validate certificates presented by target servers.",
    ("defaults", "provision_format"): "Temporary-user naming format. When set, it must contain <user>.",
    ("defaults", "template_policy"): "Existing policy whose approved settings are copied into generated policies.",
    ("defaults", "owner_tag"): "Tag that proves a policy or target set belongs to this tool.",
    ("defaults", "ssh_username"): "Default certificate username for SSH server rows.",
    ("defaults", "group_template"): "Identity group naming convention used when a server row leaves group blank.",
    ("defaults", "target_set_scope"): "Whether target sets are created per server or shared by configured domains.",
    ("defaults", "strong_account_template"): "Strong-account name convention used when a server row leaves it blank.",
    ("defaults", "strong_account_type"): "Whether derived accounts already exist, reference a Vault account, or store credentials.",
    ("defaults", "strong_account_safe_template"): "Vault Safe convention for derived vault accounts.",
    ("defaults", "strong_account_account_name_template"): "Vault account-name convention for derived vault accounts.",
    ("defaults", "strong_account_username_template"): "Windows username convention for derived vault or credentials accounts.",
    ("defaults", "strong_account_domain"): "Use local for local accounts, or an AD domain name; placeholders are supported.",
    ("auth", "identity_auth"): "Authentication flow for Identity directory group lookups.",
    ("auth", "oidc_application"): "OIDC application name used by the service-user Identity flow.",
    ("auth", "password_file"): "Optional password CSV. Relative paths resolve beside this configuration file.",
    ("http", "timeout_seconds"): "Maximum seconds to wait for one HTTP request.",
    ("http", "max_retries"): "Maximum retries for safe retryable requests.",
    ("http", "status_polls"): "Read-backs while a newly created policy is still validating, from 1 through 10.",
    ("http", "max_requests_per_second"): "Shared request-rate limit. Zero disables rate limiting.",
    ("http", "lookup_search_max_rows"): "Largest run that uses per-server lookup in automatic lookup mode.",
    ("http", "secrets_api"): "Strong-account API family. Auto detects it with read-only requests.",
    ("http", "targetsets_api"): "Target-set API family. Auto detects it with read-only requests.",
    ("http", "ca_bundle"): "Trusted corporate CA file or directory. Relative paths resolve beside this configuration file.",
    ("http", "system_trust"): "Verify against the trust store this computer already uses, so a corporate root "
                              "installed by IT is honoured. A custom CA bundle takes precedence when both are set.",
    ("http", "verify"): "Verify HTTPS certificates. Disable only in a controlled lab.",
    ("connect", "login_suffix"): "Text after @ in Identity login names; blank derives it from the client ID.",
    ("connect", "gateway_host"): "RDP gateway host; blank uses the tenant default.",
    ("connect", "network"): "Optional connector network included in connection instructions.",
    ("pvwa", "base_url"): "PVWA base URL. Leave blank to disable the optional Vault onboarding stage.",
    ("pvwa", "auth_type"): "PVWA logon method.",
    ("pvwa", "platform_id"): "PVWA platform assigned to onboarded local accounts.",
    ("pvwa", "cpm_managed"): "Allow CPM to manage and rotate onboarded passwords.",
}


def _default_for(config_field: Any) -> Any:
    if config_field.default is not MISSING:
        return config_field.default
    if config_field.default_factory is not MISSING:  # type: ignore[comparison-overlap]
        return config_field.default_factory()
    return None


def _kind_for(section: str, key: str, type_hint: Any) -> str:
    if (section, key) in _CHOICES:
        return "choice"
    if (section, key) in _KINDS:
        return _KINDS[(section, key)]
    origin = get_origin(type_hint)
    if origin is tuple:
        return "integer_list" if get_args(type_hint)[0] is int else "string_list"
    return {bool: "boolean", int: "integer", float: "number", str: "text"}.get(type_hint, "text")


def _make_descriptors() -> tuple[SettingDescriptor, ...]:
    result: list[SettingDescriptor] = []
    for section in SECTIONS:
        cls = _SECTION_CLASSES[section]
        hints = get_type_hints(cls)
        for config_field in fields(cls):
            key = config_field.name
            pair = (section, key)
            result.append(SettingDescriptor(
                section=section,
                key=key,
                label=_LABELS.get(key, key.replace("_", " ").capitalize()),
                help=_HELP[pair],
                kind=_kind_for(section, key, hints[key]),
                default=_default_for(config_field),
                choices=_CHOICES.get(pair, ()),
                required=(pair in {("tenant", "subdomain"), ("tenant", "identity_url")}
                          or (section == "defaults" and key in REQUIRED_DEFAULT_KEYS)),
                basic=pair in _BASIC,
            ))
    return tuple(result)


SETTING_DESCRIPTORS = _make_descriptors()
_DESCRIPTOR_INDEX = {(item.section, item.key): item for item in SETTING_DESCRIPTORS}


def setting_descriptors(*, include_advanced: bool = True) -> tuple[SettingDescriptor, ...]:
    """Return the stable setting catalogue in file/display order."""
    if include_advanced:
        return SETTING_DESCRIPTORS
    return tuple(item for item in SETTING_DESCRIPTORS if item.basic)


def descriptor_for(section: str, key: str) -> SettingDescriptor:
    try:
        return _DESCRIPTOR_INDEX[(section, key)]
    except KeyError as exc:
        raise ConfigError(f"unknown setting [{section}] {key}") from exc


def parse_setting_value(descriptor: SettingDescriptor, text: str) -> Any:
    """Turn terminal input into the setting's TOML-compatible Python value."""
    raw = text.strip()
    if descriptor.kind == "choice":
        for choice in descriptor.choices:
            if raw.casefold() == choice.casefold():
                return choice
        raise ConfigError(f"{descriptor.dotted_key} must be one of {', '.join(descriptor.choices)}")
    if descriptor.kind == "boolean":
        if raw.casefold() in ("true", "yes", "y", "1"):
            return True
        if raw.casefold() in ("false", "no", "n", "0"):
            return False
        raise ConfigError(f"{descriptor.dotted_key} must be true or false")
    if descriptor.kind == "integer":
        try:
            return int(raw)
        except ValueError as exc:
            raise ConfigError(f"{descriptor.dotted_key} must be an integer") from exc
    if descriptor.kind == "number":
        try:
            value = float(raw)
        except ValueError as exc:
            raise ConfigError(f"{descriptor.dotted_key} must be a number") from exc
        if not math.isfinite(value):
            raise ConfigError(f"{descriptor.dotted_key} must be a finite number")
        return value
    if descriptor.kind in ("integer_list", "string_list"):
        if not raw:
            return []
        if raw.startswith("["):
            try:
                values = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ConfigError(f"{descriptor.dotted_key} must be a JSON list or comma-separated values") from exc
            if not isinstance(values, list):
                raise ConfigError(f"{descriptor.dotted_key} must be a list")
        else:
            values = [item.strip() for item in raw.split(",") if item.strip()]
        if descriptor.kind == "integer_list":
            parsed: list[int] = []
            for item in values:
                if type(item) is int:
                    parsed.append(item)
                    continue
                if isinstance(item, str) and re.fullmatch(r"[+-]?\d+", item):
                    parsed.append(int(item))
                    continue
                raise ConfigError(f"{descriptor.dotted_key} must contain integers")
            return parsed
        if any(not isinstance(item, str) for item in values):
            raise ConfigError(f"{descriptor.dotted_key} must contain text values")
        return values
    return text


def validate_setting_value(descriptor: SettingDescriptor, value: Any) -> tuple[ValidationIssue, ...]:
    """Return direct issues for one candidate value without enforcing dependent fields."""
    return validate_field(descriptor.section, descriptor.key, value)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _current_digest(path: Path) -> str | None:
    try:
        return _digest(path.read_bytes())
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ConfigError(f"cannot read file {path}: {exc}") from exc


def _toml_compatible(value: Any) -> Any:
    return list(value) if isinstance(value, tuple) else value


def _new_document() -> TOMLDocument:
    document = tomlkit.document()
    document.add(tomlkit.comment("SIA policy automation settings. Secrets belong in .env, never in this file."))
    for section in SECTIONS:
        section_table = tomlkit.table()
        for descriptor in (item for item in SETTING_DESCRIPTORS if item.section == section):
            value = descriptor.default
            if value is None:
                value = ""
            section_table.add(descriptor.key, _toml_compatible(value))
        document.add(section, section_table)
    return document


_ABSENT = object()


def _copy_document(document: TOMLDocument) -> TOMLDocument:
    return tomlkit.parse(tomlkit.dumps(document))


def _document_value(document: TOMLDocument, section: str, key: str) -> Any:
    table = document.get(section, _ABSENT)
    if table is _ABSENT or not hasattr(table, "get"):
        return _ABSENT
    value = table.get(key, _ABSENT)
    if value is not _ABSENT and hasattr(value, "unwrap"):
        value = value.unwrap()
    return value


def _put_document_value(document: TOMLDocument, section: str, key: str, value: Any) -> None:
    table = document.get(section, _ABSENT)
    if table is _ABSENT or not hasattr(table, "get"):
        if section in document:
            del document[section]
        document.add(section, tomlkit.table())
    if value is _ABSENT:
        if key in document[section]:
            del document[section][key]
    else:
        document[section][key] = _toml_compatible(value)


@dataclass
class SettingsDocument:
    path: Path
    document: TOMLDocument
    original_digest: str | None
    config: Config | None = None
    validation_error: str | None = None
    base_document: TOMLDocument | None = None
    conflicts: tuple[SettingsMergeConflict, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.base_document is None:
            self.base_document = _copy_document(self.document)

    def _refresh_validation(self) -> None:
        try:
            self.config = self.validate()
            self.validation_error = None
        except ConfigError as exc:
            self.config = None
            self.validation_error = str(exc)

    def set(self, section: str, key: str, value: Any) -> None:
        descriptor_for(section, key)
        _put_document_value(self.document, section, key, value)
        self._refresh_validation()

    def preview(self) -> str:
        return tomlkit.dumps(self.document)

    def validate(self) -> Config:
        return parse_config(self.preview(), self.path)

    def issues(self) -> tuple[ValidationIssue, ...]:
        """Return structured review issues, including parse/type errors when available."""
        try:
            self.validate()
        except ConfigValidationError as exc:
            return exc.issues
        except ConfigError as exc:
            return (ValidationIssue((), str(exc), "parse"),)
        return ()

    def values(self) -> tuple[SettingValue, ...]:
        values: list[SettingValue] = []
        for descriptor in SETTING_DESCRIPTORS:
            table = self.document.get(descriptor.section, {})
            is_table = hasattr(table, "get")
            in_file = is_table and descriptor.key in table
            if self.config is not None:
                value = getattr(getattr(self.config, descriptor.section), descriptor.key)
            else:
                value = table.get(descriptor.key, descriptor.default) if is_table else descriptor.default
                if hasattr(value, "unwrap"):
                    value = value.unwrap()
            values.append(SettingValue(descriptor, value, "config file" if in_file else "tool default"))
        return tuple(values)

    def rebase(self) -> tuple[SettingsMergeConflict, ...]:
        """Merge a draft onto the latest file, preserving latest comments and reporting overlaps.

        Non-overlapping draft edits are applied immediately. Overlapping fields retain the disk
        value until :meth:`resolve_conflict` explicitly selects ``disk`` or ``draft``.
        """
        if self.conflicts:
            # The retained draft values live in these conflict objects. Re-reading before the
            # operator resolves them could replace that only copy with the disk value.
            return self.conflicts
        try:
            data = self.path.read_bytes()
            exists = True
        except FileNotFoundError:
            data = b""
            exists = False
        except OSError as exc:
            raise ConfigError(f"cannot read config file {self.path}: {exc}") from exc
        if not exists or not data:
            # Deletion/truncation is recoverable: keep the complete draft and let the next
            # reviewed save recreate the file instead of silently discarding unchanged settings.
            self.base_document = tomlkit.document()
            self.original_digest = _digest(data) if exists else None
            self._refresh_validation()
            return ()
        if data:
            text = decode_text_bytes(data, self.path, "configuration")
            try:
                latest = tomlkit.parse(text)
            except TOMLKitError as exc:
                raise ConfigError(f"{self.path}: invalid TOML: {exc}{toml_error_hint(text)}") from exc
        else:
            latest = tomlkit.document()
        base = self.base_document or tomlkit.document()
        merged = _copy_document(latest)
        conflicts: list[SettingsMergeConflict] = []
        for descriptor in SETTING_DESCRIPTORS:
            section, key = descriptor.section, descriptor.key
            base_value = _document_value(base, section, key)
            disk_value = _document_value(latest, section, key)
            draft_value = _document_value(self.document, section, key)
            draft_changed = draft_value != base_value
            disk_changed = disk_value != base_value
            if draft_changed and disk_changed and draft_value != disk_value:
                conflicts.append(SettingsMergeConflict(section, key, base_value, disk_value, draft_value))
            elif draft_changed:
                _put_document_value(merged, section, key, draft_value)
        self.document = merged
        self.base_document = _copy_document(latest)
        self.original_digest = _digest(data) if exists else None
        self.conflicts = tuple(conflicts)
        self._refresh_validation()
        return self.conflicts

    def resolve_conflict(self, section: str, key: str, *, use: str) -> None:
        """Resolve one three-way merge overlap with the latest disk or retained draft value."""
        if use not in ("disk", "draft"):
            raise ConfigError("settings conflict resolution must use 'disk' or 'draft'")
        conflict = next((item for item in self.conflicts if (item.section, item.key) == (section, key)), None)
        if conflict is None:
            raise ConfigError(f"no unresolved settings conflict for {section}.{key}")
        if use == "draft":
            _put_document_value(self.document, section, key, conflict.draft)
        self.conflicts = tuple(item for item in self.conflicts if item is not conflict)
        self._refresh_validation()

    def save(self) -> Config:
        if self.conflicts:
            names = ", ".join(item.dotted_key for item in self.conflicts)
            raise SettingsConflictError(f"resolve overlapping external edits before saving: {names}")
        config = self.validate()
        current = _current_digest(self.path)
        if current != self.original_digest:
            raise SettingsConflictError(
                f"{self.path} changed after settings were opened; reopen settings so the newer edits are not overwritten"
            )
        data = self.preview().encode("utf-8")
        _atomic_write(self.path, data, mode=None, expected_digest=self.original_digest)
        self.original_digest = _digest(data)
        self.base_document = _copy_document(self.document)
        self.conflicts = ()
        self.config = config
        self.validation_error = None
        return config


def open_settings(path: str | Path, *, create: bool = False) -> SettingsDocument:
    """Open settings without writing. Invalid values may be edited; invalid TOML cannot be safely repaired."""
    config_path = Path(path).expanduser().resolve()
    if not config_path.is_file():
        if config_path.exists():
            raise ConfigError(f"configuration path is not a regular file: {config_path}")
        if not create:
            raise ConfigError(f"config file not found: {config_path} (run setup to create it)")
        return SettingsDocument(config_path, _new_document(), None, None, "complete the required tenant settings")
    try:
        data = config_path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read config file {config_path}: {exc}") from exc
    text = decode_text_bytes(data, config_path, "configuration")
    try:
        document = tomlkit.parse(text)
    except TOMLKitError as exc:
        raise ConfigError(f"{config_path}: invalid TOML: {exc}{toml_error_hint(text)}") from exc
    try:
        config = parse_config(tomlkit.dumps(document), config_path)
        error = None
    except ConfigError as exc:
        config = None
        error = str(exc)
    return SettingsDocument(config_path, document, _digest(data), config, error)


_ENV_ASSIGNMENT = re.compile(r"^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)(\s*=\s*)(.*?)(\r?\n)?$")
_EXPECTED_UNSET = object()


def _inline_comment(raw_value: str) -> str:
    """The trailing comment on the line being rewritten, so re-saving never drops the operator's note."""
    value = raw_value.rstrip()
    if not value:
        return ""
    if value[0] in "\"'":
        scanned = scan_quoted_value(value)
        # A value SIA cannot delimit is one it must not interpret either; fall through to the
        # unquoted scan rather than silently discarding whatever the operator wrote after it.
        if scanned is not None:
            rest = value[scanned[1]:].strip()
            return f"  {rest}" if rest.startswith("#") else ""
    index = value.find(" #")
    return f"  {value[index + 1:].strip()}" if index >= 0 else ""


# Anything `str.splitlines()` breaks on would tear the value across two .env lines. Listing the
# characters by hand has already gone wrong once: json.dumps escaped the C0 set but left U+0085,
# U+2028 and U+2029 raw, so asking splitlines() itself is the only durable test.
_ENV_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _render_env_value(value: str) -> str:
    """Serialize one .env value so that reading it back returns exactly this string.

    Quoting only delimits, so the form is chosen for legibility: bare wherever that survives the
    reader, then single quotes, then double quotes with the quote character doubled. A pasted
    secret containing a backslash is therefore stored verbatim -- an operator who opens the file
    sees their own credential and has nothing to "correct".
    """
    if _ENV_CONTROL.search(value) or (value and value.splitlines() != [value]):
        raise ConfigError("a credential must be one line with no control characters")
    bare_unsafe = ('"', "'", " #")
    if (value and value == value.strip() and value[0] not in "\"'}]#"
            and not any(item in value for item in bare_unsafe)):
        return value
    if "'" not in value:
        return f"'{value}'"
    return '"' + value.replace('"', '""') + '"'


def storable_env_value(value: str) -> bool:
    """Whether :func:`update_dotenv` can store this value, for refusing it at the prompt instead.

    Defined by asking the serializer, so what a prompt accepts and what a save accepts cannot drift.
    """
    try:
        _render_env_value(value)
    except ConfigError:
        return False
    return True


def update_dotenv(path: str | Path, updates: Mapping[str, str | None], *,
                  expected_digest: str | None | object = _EXPECTED_UNSET) -> str:
    """Atomically update selected .env keys while preserving every unrelated line and comment.

    ``None`` removes a key.  The file is always owner-only on POSIX.  Pass an expected digest when editing a
    previously displayed file to prevent overwriting an external edit.

    Only the lines being changed are rewritten, and a rewritten line keeps the line endings already
    in the file. A leading UTF-8 byte-order mark is dropped, which repairs a file saved from Notepad.
    """
    env_path = Path(path).expanduser().resolve()
    for key, value in updates.items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ConfigError(f"invalid environment variable name {key!r}")
        if value is not None and not isinstance(value, str):
            raise ConfigError(f"environment variable {key} must be text")
    rendered_values = {key: _render_env_value(value) for key, value in updates.items() if value is not None}
    current = _current_digest(env_path)
    if expected_digest is not _EXPECTED_UNSET and current != expected_digest:
        raise SettingsConflictError(
            f"{env_path} changed after it was opened; reopen settings so the newer edits are not overwritten"
        )
    # Check line syntax and duplicate keys before deciding which line to replace. Values are never
    # read here, so a value elsewhere in the file that no longer decodes must not block this save --
    # rewriting its key is how an operator repairs it.
    read_dotenv(env_path, strict=False)
    original = decode_text_file(env_path, "credentials file") if env_path.is_file() else ""
    lines = original.splitlines(keepends=True)
    remaining = dict(updates)
    rendered: list[str] = []
    newline = "\r\n" if any(line.endswith("\r\n") for line in lines) else "\n"
    for line in lines:
        match = _ENV_ASSIGNMENT.match(line)
        if not match or match.group(2) not in remaining:
            rendered.append(line)
            continue
        key = match.group(2)
        value = remaining.pop(key)
        if value is None:
            continue
        ending = match.group(5) or newline
        comment = _inline_comment(match.group(4))
        rendered.append(f"{match.group(1)}{key}{match.group(3)}{rendered_values[key]}{comment}{ending}")
    if remaining:
        if rendered and not rendered[-1].endswith(("\n", "\r")):
            rendered[-1] += newline
        for key, value in remaining.items():
            if value is not None:
                rendered.append(f"{key}={rendered_values[key]}{newline}")
    data = "".join(rendered).encode("utf-8")
    _atomic_write(env_path, data, mode=0o600, expected_digest=current)
    return _digest(data)


def dotenv_digest(path: str | Path) -> str | None:
    """Return a digest suitable for ``update_dotenv(expected_digest=...)``."""
    return _current_digest(Path(path).expanduser().resolve())


def _atomic_write(path: Path, data: bytes, *, mode: int | None,
                  expected_digest: str | None | object = _EXPECTED_UNSET) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing_mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else None
    windows_credential = mode == 0o600 and windows_acl_supported()
    if windows_credential:
        descriptor, temporary = create_protected_temporary_file(path.parent, f".{path.name}.")
    else:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if not windows_credential:
            os.chmod(temporary, mode if mode is not None else (existing_mode or 0o600))
        if expected_digest is not _EXPECTED_UNSET and _current_digest(path) != expected_digest:
            raise SettingsConflictError(
                f"{path} changed while the replacement file was being staged; reload it before saving"
            )
        if windows_credential and path.exists():
            # Windows replacement behavior can retain either file's security metadata
            # depending on the filesystem/API path. Protect both possible origins before
            # any credential bytes are published.
            protect_credential_file(path)
        # Protection does not change file contents. Recheck afterwards so a concurrent
        # edit cannot be hidden by the ACL operation before the replace.
        if expected_digest is not _EXPECTED_UNSET and _current_digest(path) != expected_digest:
            raise SettingsConflictError(
                f"{path} changed while the replacement file was being staged; reload it before saving"
            )
        os.replace(temporary, path)
        if windows_credential:
            status = inspect_credential_permissions(path)
            if status.secure is not True:
                raise WindowsCredentialProtectionError(path, status.message, published=True)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
