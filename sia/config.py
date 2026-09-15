"""Configuration loading: config.toml (non-secret) + .env (secrets) + validation."""
from __future__ import annotations

import codecs
import csv
import ipaddress
import logging
import math
import os
import re
import stat
import string
import tomllib
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from types import UnionType
from typing import Any, Mapping, Union, get_args, get_origin, get_type_hints
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .redact import register_secret
from .windows_security import inspect_credential_permissions, windows_acl_supported

HOUR_RE = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")
FQDN_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
SUBDOMAIN_RE = re.compile(rf"^{FQDN_LABEL}$")
TAG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
IDENTITY_AUTH_METHODS = ("platform_token", "service_user_oidc")
STRONG_ACCOUNT_TYPES = ("existing", "vault", "credentials")
SECRETS_API_FAMILIES = ("auto", "public", "legacy")
TARGETSETS_API_FAMILIES = ("auto", "legacy", "discovery")
PVWA_AUTH_TYPES = ("cyberark", "ldap")
TEMPLATE_PLACEHOLDERS = ("hostname", "fqdn", "domain", "hostname_upper", "hostname_lower", "domain_upper")
TARGET_SET_SCOPES = ("server", "auto", "domain")
POLICY_STATUSES = ("Active", "Suspended")
PRINCIPAL_TYPES = ("role", "group")
PRINCIPAL_RENAME_HINT = ('policies grant access to Identity roles by default; '
                         'set [defaults] principal_type = "group" to keep using groups')
# Keys earlier releases used: the unknown-key error names the replacement instead of leaving the operator guessing.
RENAMED_KEYS: dict[tuple[str, str], str] = {("defaults", "group_template"): "principal_template"}
# [defaults] keys that must be written explicitly in config.toml (no silent organizational defaults)
REQUIRED_DEFAULT_KEYS = ("days_of_week", "from_hour", "to_hour", "target_set_cert_validation")


class ConfigError(Exception):
    """Raised for invalid or missing configuration."""


@dataclass(frozen=True)
class ValidationIssue:
    """One actionable configuration problem and the settings that can repair it."""

    keys: tuple[tuple[str, str], ...]
    message: str
    code: str = "invalid"

    @property
    def dotted_keys(self) -> tuple[str, ...]:
        return tuple(f"{section}.{key}" for section, key in self.keys)


class ConfigValidationError(ConfigError):
    """A complete set of configuration validation problems."""

    def __init__(self, issues: tuple[ValidationIssue, ...] | list[ValidationIssue]):
        self.issues = tuple(issues)
        super().__init__("\n".join(issue.message for issue in self.issues))


@dataclass(frozen=True)
class TenantConfig:
    subdomain: str
    identity_url: str
    root_domain: str = "cyberark.cloud"

    @property
    def dpa_url(self) -> str:
        return f"https://{self.subdomain}.dpa.{self.root_domain}"

    @property
    def uap_url(self) -> str:
        return f"https://{self.subdomain}.uap.{self.root_domain}"

    @property
    def portal_url(self) -> str:
        return f"https://{self.subdomain}.{self.root_domain}"


@dataclass(frozen=True)
class StrongAccountTemplate:
    """How a per-server strong account is derived when servers.csv leaves `strong_account` blank.

    `name` is always rendered; for type=vault the Vault reference is (safe, account_name); for type=credentials the
    stored account is (username, password from the password file / env). Templates may use {hostname}, {fqdn},
    {domain}. type=existing keeps the historical behaviour: the rendered name is only looked up in SIA.
    """
    name: str
    type: str = "existing"
    safe: str = ""
    account_name: str = ""
    username: str = ""
    account_domain: str = "local"


@dataclass(frozen=True)
class Defaults:
    policy_name_template: str = "{fqdn}"
    description_template: str = "Automated: {protocol} ZSP access to {fqdn}"
    policy_tags: tuple[str, ...] = ("automated",)
    policy_status: str = "Active"              # metadata.status on create: Active, or Suspended to stage a rollout
    time_zone: str = "GMT"
    days_of_week: tuple[int, ...] = (0, 1, 2, 3, 4, 5, 6)
    from_hour: str = ""
    to_hour: str = ""
    max_session_hours: int = 2
    idle_minutes: int = 10
    assign_local_groups: tuple[str, ...] = ("Administrators",)
    enable_reconnect: bool = False
    target_set_cert_validation: bool = False
    provision_format: str = ""
    template_policy: str = ""
    owner_tag: str = "sia-policy-automation"   # policy tag / description marker identifying objects this tool manages
    # Fields a tenant carries on a policy that this tool never writes: "note" (reported, preserved on --update) or
    # "fail" (a read-back failure and drift, as older versions treated them). ignore_readback_keys silences named
    # leaves by signature path, e.g. "conditions.overrideRecording".
    readback_extra_keys: str = "note"
    ignore_readback_keys: tuple[str, ...] = ()
    ssh_username: str = ""                     # default certificate username for protocol=ssh rows
    # What kind of Identity principal a policy grants access to: role (default; tenant-wide, nothing to pin) or
    # group (may need a directory pin in groups.csv when the same name exists in several directories).
    principal_type: str = "role"
    # Principal derived from the server name (servers.csv leaves principal blank), e.g. "SIA-{hostname_upper}-RDP".
    # domains.csv may override it per domain. Several principals: separate them with ';'.
    principal_template: str = ""
    # How wide a target set is: server = one "Target" set per FQDN (every server has its own strong account);
    # auto = servers whose strong account comes from domains.csv share that domain's set, the rest fall back to
    # per-server; domain = as auto, but a domain-joined server missing from domains.csv is an error.
    target_set_scope: str = "server"
    # Per-server strong accounts derived from a naming convention (servers.csv leaves strong_account blank):
    strong_account_template: str = ""          # e.g. "ADM-{hostname}": the strong account's name
    strong_account_type: str = "existing"      # existing (look up only) | vault (create a Vault reference) | credentials
    strong_account_safe_template: str = ""     # vault: Safe holding the account, e.g. "SIA-LocalAdmins"
    strong_account_account_name_template: str = ""   # vault: the account's Name in the Vault, e.g. "{hostname}-Administrator"
    strong_account_username_template: str = ""       # vault/credentials: the Windows user name, e.g. "Administrator"
    strong_account_domain: str = "local"       # "local" for a local administrator, else the AD domain of the account

    @property
    def strong_account_spec(self) -> StrongAccountTemplate | None:
        if not self.strong_account_template:
            return None
        return StrongAccountTemplate(
            name=self.strong_account_template, type=self.strong_account_type,
            safe=self.strong_account_safe_template, account_name=self.strong_account_account_name_template,
            username=self.strong_account_username_template, account_domain=self.strong_account_domain or "local")


@dataclass(frozen=True)
class AuthConfig:
    identity_auth: str = "platform_token"      # platform_token | service_user_oidc (for Identity directory calls)
    oidc_application: str = "__idaptive_cybr_user_oidc"
    password_file: str = ""                    # optional CSV (name,password) with strong-account passwords, kept outside the repo


@dataclass(frozen=True)
class HttpConfig:
    timeout_seconds: int = 60
    max_retries: int = 4
    status_polls: int = 5                      # GETs after creating a policy while it is still "Validating" (1..10)
    max_requests_per_second: float = 0.0       # global rate limit shared by all workers; 0 = off
    lookup_search_max_rows: int = 2000         # --lookup auto: search per server up to this many servers, else list
    policy_page_size: int = 50                 # rows per GET /api/policies page; raise it if policy reads are slow
    secrets_api: str = "auto"                  # auto | public (/api/secrets/public/v1+v2) | legacy (/api/secrets)
    targetsets_api: str = "auto"               # auto | legacy (/api/targetsets) | discovery (/api/discovery/targetsets)
    ca_bundle: str = ""                        # PEM file/dir of trusted CAs (TLS-inspecting proxies); "" = certifi
    verify: bool = True                        # never set false outside a lab: it disables TLS verification entirely
    system_trust: bool = True                  # verify against the OS trust store, so a corporate root already
                                               # installed on the machine is honoured without exporting a bundle

    @property
    def tls_verify(self) -> str | bool:
        """What to pass to requests as `verify`: a CA bundle path, or True/False."""
        if not self.verify:
            return False
        return self.ca_bundle or True

    @property
    def trust_source(self) -> str:
        """Which trust store the settings select, before checking whether truststore is installed."""
        if not self.verify:
            return "disabled"
        if self.ca_bundle:
            return "ca_bundle"
        return "system" if self.system_trust else "certifi"


@dataclass(frozen=True)
class ConnectConfig:
    """Values printed by `connect-info` (nothing here is secret)."""
    login_suffix: str = ""                     # the part after '@' in users' Identity login names, e.g. "acme.cyberark.cloud"
    gateway_host: str = ""                     # override the SIA RDP gateway host (default <subdomain>.rdp.<root_domain>)
    network: str = ""                          # connector network name to add as "/n <network>" (optional for FQDN targets)


@dataclass(frozen=True)
class PVWAConfig:
    """PAM Self-Hosted (PVWA) REST API, used only by the optional `vault` stage that onboards missing accounts."""
    base_url: str = ""                         # e.g. https://pvwa.corp.example.com ("" = vault stage disabled)
    auth_type: str = "cyberark"                # cyberark | ldap
    platform_id: str = "WinServerLocal"        # platform assigned to onboarded local administrator accounts
    cpm_managed: bool = True                   # automaticManagementEnabled on the onboarded account

    @property
    def enabled(self) -> bool:
        return bool(self.base_url)


@dataclass(frozen=True)
class Config:
    tenant: TenantConfig
    defaults: Defaults = field(default_factory=Defaults)
    auth: AuthConfig = field(default_factory=AuthConfig)
    http: HttpConfig = field(default_factory=HttpConfig)
    connect: ConnectConfig = field(default_factory=ConnectConfig)
    pvwa: PVWAConfig = field(default_factory=PVWAConfig)


SECTIONS = ("tenant", "defaults", "auth", "http", "connect", "pvwa")


def unknown_key_hint(section: str, key: str) -> str:
    """Suffix for an unknown-key error when the key is one an earlier release used under another name."""
    new = RENAMED_KEYS.get((section, key))
    return f" ({key!r} was renamed to {new!r}: {PRINCIPAL_RENAME_HINT})" if new else ""


def _build(cls, section: dict[str, Any], name: str):
    """Instantiate a frozen dataclass while rejecting unknown keys and incorrect TOML types."""
    known = {f.name: f for f in fields(cls)}
    unknown = sorted(set(section) - set(known))
    if unknown:
        rename_hints = "".join(unknown_key_hint(name, key) for key in unknown)
        raise ConfigError(f"[{name}] has unknown key(s): {', '.join(unknown)}{rename_hints}")
    hints = get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for key, value in section.items():
        if isinstance(value, list):
            value = tuple(value)
        expected = hints[key]
        if not _matches_type(value, expected):
            raise ConfigError(
                f"[{name}] {key} must be {_type_name(expected)}, got {_value_type_name(value)}"
            )
        kwargs[key] = value
    try:
        return cls(**kwargs)
    except TypeError as exc:
        raise ConfigError(f"[{name}] is invalid: {exc}") from exc


def _matches_type(value: Any, expected: Any) -> bool:
    """Strict runtime check for the small type vocabulary used by the config dataclasses."""
    origin = get_origin(expected)
    if origin is tuple:
        args = get_args(expected)
        item_type = args[0] if args else Any
        return isinstance(value, tuple) and all(_matches_type(item, item_type) for item in value)
    if origin in (UnionType, Union):
        return any(_matches_type(value, option) for option in get_args(expected))
    if expected is Any:
        return True
    if expected is bool:
        return type(value) is bool
    if expected is int:
        return type(value) is int
    if expected is float:
        return type(value) in (int, float)
    return type(value) is expected


def _type_name(expected: Any) -> str:
    origin = get_origin(expected)
    if origin is tuple:
        item = get_args(expected)[0]
        item_name = {str: "strings", int: "integers", float: "numbers"}.get(item, "values")
        return f"a list of {item_name}"
    if expected is str:
        return "a string"
    if expected is bool:
        return "a boolean (true or false, without quotes)"
    if expected is int:
        return "an integer"
    if expected is float:
        return "a number"
    return getattr(expected, "__name__", str(expected))


def _value_type_name(value: Any) -> str:
    if isinstance(value, tuple):
        return "a list with invalid item types"
    return {str: "a string", bool: "a boolean", int: "an integer", float: "a number"}.get(
        type(value), type(value).__name__
    )


def _check_template(label: str, template: str, placeholders: tuple[str, ...] = TEMPLATE_PLACEHOLDERS) -> None:
    try:
        parsed = list(string.Formatter().parse(template))
    except ValueError as exc:
        raise ConfigError(f"[defaults] {label} is not a valid template: {exc}") from exc
    invalid = [field_name for _, field_name, _, _ in parsed
               if field_name is not None and field_name not in placeholders]
    if invalid:
        allowed = ", ".join("{" + p + "}" for p in placeholders)
        raise ConfigError(f"[defaults] {label} may only use {allowed}")
    if any(conversion for _, field_name, _, conversion in parsed if field_name is not None):
        raise ConfigError(f"[defaults] {label} must not use template conversions such as !r or !s")
    if any(format_spec for _, field_name, format_spec, _ in parsed if field_name is not None):
        raise ConfigError(f"[defaults] {label} must not use template format specifications")


def suggest_https_base_url(value: str) -> str | None:
    """Return a conservative base-URL correction that keeps the supplied host and port.

    This only fixes syntax operators commonly paste incorrectly: a missing/HTTP scheme and a
    path, query, fragment, or trailing slash. Credentials, malformed ports, whitespace and
    invalid hosts are never repaired automatically.
    """
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or raw != value or any(not char.isprintable() or char.isspace() for char in raw):
        return None
    if "://" in raw:
        scheme = raw.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            return None
        candidate = raw
    else:
        if raw.startswith("//"):
            return None
        candidate = f"https://{raw}"
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if not hostname or parsed.username is not None or parsed.password is not None:
        return None
    if port is not None and port < 1:
        return None
    host = hostname.lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if not _valid_dns_name(host):
            return None
        authority = host
    else:
        authority = f"[{host}]" if ip.version == 6 else host
    if port is not None:
        authority += f":{port}"
    return f"https://{authority}"


def _validate_https_url(label: str, value: str, *, allow_empty: bool = False) -> None:
    if not value and allow_empty:
        return
    if any(not char.isprintable() or char.isspace() for char in value):
        raise ConfigError(f"{label} must not contain whitespace or control characters")
    try:
        parsed = urlsplit(value)
        _ = parsed.port     # a malformed port raises ValueError here
    except ValueError as exc:
        raise ConfigError(f"{label} is not a valid URL: {exc}") from exc
    suggestion = suggest_https_base_url(value)
    if suggestion != value or parsed.path or parsed.query or parsed.fragment or any(
            delimiter in value.partition("://")[2] for delimiter in ("?", "#")):
        raise ConfigError(f"{label} must be an https:// URL with a host and no path, query, fragment, credentials, or trailing slash")


def _valid_dns_name(value: str) -> bool:
    """ASCII DNS host/domain without a trailing dot, whitespace, controls, or empty labels."""
    return (bool(value) and len(value) <= 253 and value == value.lower() and not value.endswith(".")
            and all(re.fullmatch(FQDN_LABEL, label) for label in value.split(".")))


def validate_dns_name(label: str, value: str) -> str:
    """Validate a bare DNS host/domain and return it for convenient boundary checks."""
    if not _valid_dns_name(value):
        raise ConfigError(f"{label} must be a bare DNS host name such as good.example (no scheme, path, spaces, or control characters)")
    return value


def validate_connection_token(label: str, value: str, *, allow_empty: bool = False) -> str:
    """Validate one whitespace-delimited value in the SIA RDP login string."""
    if not value and allow_empty:
        return value
    if (not value or any(not char.isprintable() or char.isspace() for char in value)
            or "/" in value or "\\" in value):
        raise ConfigError(f"{label} must be one printable value with no whitespace, slash, backslash, or control characters")
    return value


def _issue(section: str, key: str, message: str, *related: tuple[str, str],
           code: str = "invalid") -> ValidationIssue:
    return ValidationIssue(((section, key), *related), message, code)


def validation_issues(cfg: Config) -> tuple[ValidationIssue, ...]:
    """Collect every semantic configuration problem in stable settings order."""
    t, d, h = cfg.tenant, cfg.defaults, cfg.http
    issues: list[ValidationIssue] = []
    if not t.subdomain or not SUBDOMAIN_RE.fullmatch(t.subdomain):
        issues.append(_issue("tenant", "subdomain",
            "[tenant] subdomain must be the tenant subdomain only, e.g. 'acme' (lowercase letters, digits, '-')"))
    for section, key, label, value, allow_empty in (
        ("tenant", "identity_url", "[tenant] identity_url", t.identity_url, False),
        ("pvwa", "base_url", "[pvwa] base_url", cfg.pvwa.base_url, True),
    ):
        try:
            _validate_https_url(label, value, allow_empty=allow_empty)
        except ConfigError as exc:
            issues.append(_issue(section, key, str(exc), code="url"))
    try:
        validate_dns_name("[tenant] root_domain", t.root_domain)
    except ConfigError as exc:
        issues.append(_issue("tenant", "root_domain", str(exc), code="dns"))
    for key, value in (("from_hour", d.from_hour), ("to_hour", d.to_hour)):
        if value and not HOUR_RE.fullmatch(value):
            issues.append(_issue("defaults", key,
                f"[defaults] {key} must be HH:MM (24h) or empty, got {value!r}"))
    if bool(d.from_hour) != bool(d.to_hour):
        issues.append(_issue("defaults", "from_hour",
            "[defaults] from_hour and to_hour must both be set or both be empty", ("defaults", "to_hour"),
            code="dependent"))
    if not 1 <= d.max_session_hours <= 24:
        issues.append(_issue("defaults", "max_session_hours", "[defaults] max_session_hours must be between 1 and 24"))
    if not 1 <= d.idle_minutes <= 120:
        issues.append(_issue("defaults", "idle_minutes", "[defaults] idle_minutes must be between 1 and 120"))
    if not d.days_of_week or any(type(x) is not int or x < 0 or x > 6 for x in d.days_of_week):
        issues.append(_issue("defaults", "days_of_week",
            "[defaults] days_of_week must be a non-empty list of integers 0 (Sunday) .. 6 (Saturday)"))
    elif len(set(d.days_of_week)) != len(d.days_of_week):
        issues.append(_issue("defaults", "days_of_week", "[defaults] days_of_week contains duplicates"))
    try:
        ZoneInfo(d.time_zone)
    except (ZoneInfoNotFoundError, ValueError):
        issues.append(_issue("defaults", "time_zone",
            f"[defaults] time_zone {d.time_zone!r} is not a recognized IANA time zone"))
    if not d.assign_local_groups:
        issues.append(_issue("defaults", "assign_local_groups",
            "[defaults] assign_local_groups must list at least one local group"))
    elif any(not item.strip() for item in d.assign_local_groups):
        issues.append(_issue("defaults", "assign_local_groups",
            "[defaults] assign_local_groups must not contain blank group names"))
    if d.readback_extra_keys not in ("note", "fail"):
        issues.append(_issue("defaults", "readback_extra_keys",
            f"[defaults] readback_extra_keys must be \"note\" or \"fail\", got {d.readback_extra_keys!r}"))
    if any(not item.strip() or "." not in item.strip() for item in d.ignore_readback_keys):
        issues.append(_issue("defaults", "ignore_readback_keys",
            "[defaults] ignore_readback_keys entries must be dotted signature paths such as \"conditions.someField\""))
    if any(not item.strip() for item in d.policy_tags):
        issues.append(_issue("defaults", "policy_tags", "[defaults] policy_tags must not contain blank tags"))
    if len(set(d.policy_tags)) != len(d.policy_tags):
        issues.append(_issue("defaults", "policy_tags", "[defaults] policy_tags contains duplicates"))
    effective_tag_count = len(d.policy_tags) + (0 if d.owner_tag in d.policy_tags else 1)
    if effective_tag_count > 20:
        issues.append(_issue("defaults", "policy_tags",
            f"[defaults] policy_tags plus owner_tag would create {effective_tag_count} tags; the maximum is 20",
            ("defaults", "owner_tag"), code="dependent"))
    template_fields = (
        ("policy_name_template", TEMPLATE_PLACEHOLDERS),
        ("strong_account_template", TEMPLATE_PLACEHOLDERS),
        ("strong_account_safe_template", TEMPLATE_PLACEHOLDERS),
        ("strong_account_account_name_template", TEMPLATE_PLACEHOLDERS),
        ("strong_account_username_template", TEMPLATE_PLACEHOLDERS),
        ("strong_account_domain", TEMPLATE_PLACEHOLDERS),
        ("principal_template", TEMPLATE_PLACEHOLDERS),
        ("description_template", TEMPLATE_PLACEHOLDERS + ("protocol",)),
    )
    for key, placeholders in template_fields:
        try:
            _check_template(key, getattr(d, key), placeholders)
        except ConfigError as exc:
            issues.append(_issue("defaults", key, str(exc), code="template"))
    if not d.policy_name_template.strip():
        issues.append(_issue("defaults", "policy_name_template", "[defaults] policy_name_template must not be empty"))
    if d.target_set_scope not in TARGET_SET_SCOPES:
        issues.append(_issue("defaults", "target_set_scope",
            f"[defaults] target_set_scope must be one of {', '.join(TARGET_SET_SCOPES)}"))
    if d.principal_type not in PRINCIPAL_TYPES:
        issues.append(_issue("defaults", "principal_type",
            f"[defaults] principal_type must be one of {', '.join(PRINCIPAL_TYPES)}"))
    if d.policy_status not in POLICY_STATUSES:
        issues.append(_issue("defaults", "policy_status",
            f"[defaults] policy_status must be one of {', '.join(POLICY_STATUSES)} "
            "(Validating/Error/Warning are set by the platform, not requested)"))
    if d.strong_account_type not in STRONG_ACCOUNT_TYPES:
        issues.append(_issue("defaults", "strong_account_type",
            f"[defaults] strong_account_type must be one of {', '.join(STRONG_ACCOUNT_TYPES)}"))
    if d.strong_account_type != "existing" and not d.strong_account_template:
        issues.append(_issue("defaults", "strong_account_type",
            "[defaults] strong_account_type = vault/credentials needs strong_account_template (the account's name)",
            ("defaults", "strong_account_template"), code="dependent"))
    if d.strong_account_template and d.strong_account_type == "vault" and not (
            d.strong_account_safe_template and d.strong_account_account_name_template):
        issues.append(_issue("defaults", "strong_account_type",
            "[defaults] strong_account_type = \"vault\" needs strong_account_safe_template and "
            "strong_account_account_name_template", ("defaults", "strong_account_safe_template"),
            ("defaults", "strong_account_account_name_template"), code="dependent"))
    if d.strong_account_template and d.strong_account_type == "credentials" and not d.strong_account_username_template:
        issues.append(_issue("defaults", "strong_account_type",
            "[defaults] strong_account_type = \"credentials\" needs strong_account_username_template",
            ("defaults", "strong_account_username_template"), code="dependent"))
    if not d.strong_account_domain:
        issues.append(_issue("defaults", "strong_account_domain",
            "[defaults] strong_account_domain must be \"local\" or an AD domain name"))
    if d.provision_format and "<user>" not in d.provision_format:
        issues.append(_issue("defaults", "provision_format",
            "[defaults] provision_format must contain <user> (SIA rejects formats without it)"))
    if not TAG_RE.fullmatch(d.owner_tag):
        issues.append(_issue("defaults", "owner_tag",
            "[defaults] owner_tag must be 1-64 characters of letters, digits, '_', '.' or '-'"))
    if cfg.auth.identity_auth not in IDENTITY_AUTH_METHODS:
        issues.append(_issue("auth", "identity_auth",
            f"[auth] identity_auth must be one of {', '.join(IDENTITY_AUTH_METHODS)}"))
    if not cfg.auth.oidc_application:
        issues.append(_issue("auth", "oidc_application", "[auth] oidc_application must not be empty"))
    if h.timeout_seconds <= 0:
        issues.append(_issue("http", "timeout_seconds", "[http] timeout_seconds must be > 0"))
    if h.max_retries < 0:
        issues.append(_issue("http", "max_retries", "[http] max_retries must be >= 0"))
    if not 1 <= h.status_polls <= 10:
        issues.append(_issue("http", "status_polls", "[http] status_polls must be between 1 and 10"))
    try:
        request_rate_is_finite = math.isfinite(h.max_requests_per_second)
    except (OverflowError, TypeError, ValueError):
        request_rate_is_finite = False
    if not request_rate_is_finite or h.max_requests_per_second < 0:
        issues.append(_issue("http", "max_requests_per_second",
            "[http] max_requests_per_second must be a finite number >= 0 (0 = no limit)"))
    if h.lookup_search_max_rows < 0:
        issues.append(_issue("http", "lookup_search_max_rows", "[http] lookup_search_max_rows must be an integer >= 0"))
    if h.policy_page_size < 1:
        issues.append(_issue("http", "policy_page_size", "[http] policy_page_size must be an integer >= 1"))
    if h.secrets_api not in SECRETS_API_FAMILIES:
        issues.append(_issue("http", "secrets_api", f"[http] secrets_api must be one of {', '.join(SECRETS_API_FAMILIES)}"))
    if h.targetsets_api not in TARGETSETS_API_FAMILIES:
        issues.append(_issue("http", "targetsets_api",
            f"[http] targetsets_api must be one of {', '.join(TARGETSETS_API_FAMILIES)}"))
    if h.ca_bundle and not Path(h.ca_bundle).exists():
        issues.append(_issue("http", "ca_bundle",
            f"[http] ca_bundle {h.ca_bundle!r} does not exist (expected a PEM file or a directory of them)",
            code="filesystem"))
    if h.ca_bundle and not h.verify:
        issues.append(_issue("http", "ca_bundle", "[http] ca_bundle is set but verify = false; pick one",
            ("http", "verify"), code="dependent"))
    if cfg.pvwa.auth_type not in PVWA_AUTH_TYPES:
        issues.append(_issue("pvwa", "auth_type", f"[pvwa] auth_type must be one of {', '.join(PVWA_AUTH_TYPES)}"))
    if not cfg.pvwa.platform_id:
        issues.append(_issue("pvwa", "platform_id", "[pvwa] platform_id must not be empty"))
    for key, value in (("gateway_host", cfg.connect.gateway_host), ("login_suffix", cfg.connect.login_suffix)):
        if value:
            try:
                validate_dns_name(f"[connect] {key}", value)
            except ConfigError as exc:
                issues.append(_issue("connect", key, str(exc), code="dns"))
    if cfg.connect.network:
        try:
            validate_connection_token("[connect] network", cfg.connect.network)
        except ConfigError as exc:
            issues.append(_issue("connect", "network", str(exc)))
    return tuple(issues)


def validate(cfg: Config) -> None:
    issues = validation_issues(cfg)
    if issues:
        raise ConfigValidationError(issues)


def validate_field(section: str, key: str, value: Any) -> tuple[ValidationIssue, ...]:
    """Validate one field independently; dependent combinations remain review-time issues."""
    section_classes = {"tenant": TenantConfig, "defaults": Defaults, "auth": AuthConfig,
                       "http": HttpConfig, "connect": ConnectConfig, "pvwa": PVWAConfig}
    cls = section_classes.get(section)
    if cls is None or key not in {item.name for item in fields(cls)}:
        raise ConfigError(f"unknown setting [{section}] {key}")
    if isinstance(value, list):
        value = tuple(value)
    expected = get_type_hints(cls)[key]
    if not _matches_type(value, expected):
        return (_issue(section, key,
            f"[{section}] {key} must be {_type_name(expected)}, got {_value_type_name(value)}", code="type"),)
    base = Config(TenantConfig("placeholder", "https://placeholder.example"))
    updated_section = replace(getattr(base, section), **{key: value})
    candidate = replace(base, **{section: updated_section})
    pair = (section, key)
    return tuple(issue for issue in validation_issues(candidate)
                 if issue.keys == (pair,) and issue.code != "filesystem")


# A double-quoted TOML value containing a backslash: the usual cause of an "invalid TOML" report on
# Windows, because a path pasted from Explorer turns \U, \c, \o and friends into invalid escapes.
_BACKSLASH_IN_BASIC_STRING = re.compile(r'=\s*"[^"\n]*\\')


def toml_error_hint(text: str) -> str:
    """An explanation to append to an invalid-TOML message when a Windows path is the likely cause."""
    if not _BACKSLASH_IN_BASIC_STRING.search(text):
        return ""
    return (". A double-quoted value treats a backslash as an escape character, so a Windows path "
            'needs forward slashes ("C:/certs/corp-root.pem"), doubled backslashes '
            '("C:\\\\certs\\\\corp-root.pem"), or single quotes (\'C:\\certs\\corp-root.pem\')')


def parse_config(text: str, source_path: str | Path = "config.toml") -> Config:
    """Parse and validate TOML text. Relative file settings resolve beside ``source_path``."""
    path = Path(source_path).expanduser().resolve()
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}{toml_error_hint(text)}") from exc
    structural: list[ValidationIssue] = []
    unknown = sorted(set(raw) - set(SECTIONS))
    for name in unknown:
        structural.append(_issue(name, "*", f"{path}: unknown section(s): {name}", code="unknown"))
    if "tenant" not in raw:
        structural.append(ValidationIssue(
            (("tenant", "subdomain"), ("tenant", "identity_url")),
            f"{path}: missing [tenant] section", "required"))
    section_classes = {"tenant": TenantConfig, "defaults": Defaults, "auth": AuthConfig,
                       "http": HttpConfig, "connect": ConnectConfig, "pvwa": PVWAConfig}
    for section_name, cls in section_classes.items():
        if section_name not in raw:
            continue
        table = raw[section_name]
        if not isinstance(table, dict):
            structural.append(ValidationIssue(
                tuple((section_name, item.name) for item in fields(cls)),
                f"{path}: [{section_name}] must be a TOML table", "type"))
            continue
        hints = get_type_hints(cls)
        for key in sorted(set(table) - set(hints)):
            structural.append(_issue(section_name, key,
                f"[{section_name}] has unknown key(s): {key}{unknown_key_hint(section_name, key)}", code="unknown"))
        for key, value in table.items():
            if key not in hints:
                continue
            normalized = tuple(value) if isinstance(value, list) else value
            if not _matches_type(normalized, hints[key]):
                structural.append(_issue(section_name, key,
                    f"[{section_name}] {key} must be {_type_name(hints[key])}, got {_value_type_name(normalized)}",
                    code="type"))
    tenant_table = raw.get("tenant") if isinstance(raw.get("tenant"), dict) else {}
    for key in ("subdomain", "identity_url"):
        if key not in tenant_table:
            structural.append(_issue("tenant", key, f"{path}: [tenant] must set required key {key}", code="required"))
    defaults_table = raw.get("defaults") if isinstance(raw.get("defaults"), dict) else {}
    missing = [key for key in REQUIRED_DEFAULT_KEYS if key not in defaults_table]
    if missing:
        structural.append(ValidationIssue(
            tuple(("defaults", key) for key in missing),
            f"{path}: [defaults] must set {', '.join(missing)} explicitly -- the access window (days_of_week, "
            "from_hour/to_hour; \"\" = all day) and target_set_cert_validation are organizational decisions, not tool defaults",
            "required"))
    if structural:
        raise ConfigValidationError(structural)
    cfg = Config(
        tenant=_build(TenantConfig, raw["tenant"], "tenant"),
        defaults=_build(Defaults, raw.get("defaults", {}), "defaults"),
        auth=_build(AuthConfig, raw.get("auth", {}), "auth"),
        http=_build(HttpConfig, raw.get("http", {}), "http"),
        connect=_build(ConnectConfig, raw.get("connect", {}), "connect"),
        pvwa=_build(PVWAConfig, raw.get("pvwa", {}), "pvwa"),
    )
    # Paths written in config belong to that config, so they remain stable when the command is launched elsewhere.
    password_file = cfg.auth.password_file
    ca_bundle = cfg.http.ca_bundle
    if password_file and not Path(password_file).expanduser().is_absolute():
        password_file = str((path.parent / Path(password_file).expanduser()).resolve())
    elif password_file:
        password_file = str(Path(password_file).expanduser())
    if ca_bundle and not Path(ca_bundle).expanduser().is_absolute():
        ca_bundle = str((path.parent / Path(ca_bundle).expanduser()).resolve())
    elif ca_bundle:
        ca_bundle = str(Path(ca_bundle).expanduser())
    cfg = replace(cfg, auth=replace(cfg.auth, password_file=password_file),
                  http=replace(cfg.http, ca_bundle=ca_bundle))
    validate(cfg)
    return cfg


# UTF-32's BOMs start with UTF-16's, so the wider prefix has to be tested first.
_BYTE_ORDER_MARKS = (
    (codecs.BOM_UTF32_LE, "UTF-32"), (codecs.BOM_UTF32_BE, "UTF-32"),
    (codecs.BOM_UTF16_LE, "UTF-16"), (codecs.BOM_UTF16_BE, "UTF-16"),
)


def decode_text_bytes(data: bytes, path: Path, label: str) -> str:
    """Decode one project text file as UTF-8, absorbing a byte-order mark.

    Ordinary Windows editing produces both shapes this has to survive: Notepad writes UTF-8
    with a BOM, and PowerShell 5.1's ``>``, ``Out-File`` and ``Set-Content`` write UTF-16 by
    default.  ``utf-8-sig`` absorbs a UTF-8 BOM; UTF-16 cannot be decoded as UTF-8 at all, so
    it is reported with the command that rewrites it rather than as a decoding failure.

    Callers that also digest the file keep hashing the raw bytes; only the parsed text changes.
    """
    for mark, encoding in _BYTE_ORDER_MARKS:
        if data.startswith(mark):
            raise ConfigError(
                f"{path}: this {label} is {encoding} text and SIA reads UTF-8. PowerShell's >, Out-File and "
                f"Set-Content write {encoding} unless told otherwise; rewrite the file with "
                f"Set-Content -Encoding utf8, or in Notepad use File > Save as with encoding UTF-8."
            )
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{path}: {label} must be UTF-8 text: {exc}") from exc


def decode_text_file(path: Path, label: str) -> str:
    """Read and decode one project text file; see :func:`decode_text_bytes`."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read {label} {path}: {exc}") from exc
    return decode_text_bytes(data, path, label)


def load_config(path: str | Path) -> Config:
    path = Path(path).expanduser()
    if not path.is_file():
        raise ConfigError(f"config file not found: {path} (copy config.example.toml to config.toml)")
    return parse_config(decode_text_file(path, "configuration"), path)


_ENV_LINE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(\s*)(.*)$")
_SECRET_WORDS = ("SECRET", "PASSWORD", "TOKEN")
# The only sequences the JSON-quoting writer this replaced could emit for a printable value.
_LEGACY_ESCAPE = re.compile(r"\\[\\\"']")


def looks_like_credential(key: str) -> bool:
    """Whether an environment variable name reads as a credential.

    A naming heuristic, not a security boundary: `password_env` in strong_accounts.csv is
    operator-chosen, so this can only be used to decide how loudly to explain something.
    """
    return any(word in key.upper() for word in _SECRET_WORDS)


def scan_quoted_value(value: str) -> tuple[str, int] | None:
    """Decode a leading quoted literal as ``(text, index after its closing quote)``.

    Quoting delimits a value; it does not escape anything inside it.  A backslash is always
    literal, which is what a pasted credential needs: `DOMAIN\\user` and `C:\\path` mean
    themselves.  Only the quote character is special, and doubling it writes one literal
    quote -- the convention `_powershell_literal` already emits and `_split_windows_command_line`
    already accepts.  Returns None when the closing quote is absent.
    """
    quote = value[0]
    parts: list[str] = []
    index = 1
    while index < len(value):
        if value[index] == quote:
            if value[index + 1:index + 2] == quote:
                parts.append(quote)
                index += 2
                continue
            return "".join(parts), index + 1
        parts.append(value[index])
        index += 1
    return None


def _parse_env_value(path: Path, lineno: int, key: str, raw: str, *, strict: bool = True) -> str:
    value = raw.strip()
    if not value:
        return ""
    if value[0] in "\"'":
        quote = value[0]
        kind = "double" if quote == '"' else "single"
        scanned = scan_quoted_value(value)
        if scanned is None:
            if not strict:
                return value
            raise ConfigError(
                f"{path}:{lineno}: {key} has an unterminated {kind}-quoted value. Add the closing {quote}, "
                f"or remove both quotes -- an unquoted value runs literally to the end of the line."
            )
        text, end = scanned
        remainder = value[end:].strip()
        if remainder and not remainder.startswith("#"):
            if not strict:
                return value
            raise ConfigError(
                f"{path}:{lineno}: {key} has text after the closing {quote} of its {kind}-quoted value. "
                f"Put one {quote} before and after the whole value, and write {quote * 2} for a literal "
                f"{quote} inside it. A backslash needs no doubling."
            )
        if _LEGACY_ESCAPE.search(value[:end]):
            _warn_once(path, lineno, key, "legacy-escape",
                       f"{key} contains a backslash before a quote or another backslash. Quoted values are now "
                       f"taken literally, so that backslash is part of the value; SIA releases before this one "
                       f"read \\\\ as one backslash. If this credential was saved by an older release, re-enter "
                       f"it under Settings > Credentials so the file matches what the tenant expects.")
        return text
    if value[0] in "}]":
        raise ConfigError(f"{path}:{lineno}: malformed value")
    text = value.split(" #", 1)[0].rstrip()
    if looks_like_credential(key) and text != value:
        _warn_once(path, lineno, key, "bare-trim",
                   f"{key} is unquoted, so everything from its first ' #' onwards was read as a comment. "
                   f"If those characters belong to the credential, wrap the whole value in single quotes.")
    return text


def read_dotenv(path: str | Path, *, strict: bool = True) -> dict[str, str]:
    """Read a .env file without changing ``os.environ``. Missing files return an empty mapping.

    ``strict=False`` keeps the line-syntax and duplicate-key checks but hands back the raw text
    of a value it cannot decode instead of raising.  That is what :func:`update_dotenv` needs:
    it never looks at the decoded values, so one unrepairable line elsewhere in the file must
    not be able to block saving a credential.
    """
    path = Path(path)
    loaded: dict[str, str] = {}
    first_lines: dict[str, int] = {}
    try:
        path_stat = path.stat()
    except FileNotFoundError as exc:
        # exists()/is_file() follow symlinks, so a broken credential symlink
        # otherwise looks exactly like the intentionally optional missing file.
        try:
            path.lstat()
        except FileNotFoundError:
            return loaded
        except OSError as inspect_exc:
            raise ConfigError(f"cannot inspect credentials path {path}: {inspect_exc}") from inspect_exc
        raise ConfigError(f"credentials path {path} is a broken symbolic link") from exc
    except OSError as exc:
        raise ConfigError(f"cannot inspect credentials path {path}: {exc}") from exc
    if not stat.S_ISREG(path_stat.st_mode):
        raise ConfigError(f"credentials path {path} must be a regular file")
    _warn_if_readable_by_others(path)
    lines = decode_text_file(path, "credentials file").splitlines()
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ENV_LINE.match(stripped)
        if not match:
            raise ConfigError(f"{path}:{lineno}: expected KEY=VALUE")
        key = match.group(1)
        if key in loaded:
            raise ConfigError(f"{path}:{lineno}: duplicate key {key!r} (first set on line {first_lines[key]})")
        value = _parse_env_value(path, lineno, key, match.group(3), strict=strict)
        # An unquoted value loses the whitespace around it to `line.strip()` above. Quotes are
        # what preserve it, so say so rather than letting a padded credential fail silently.
        if (looks_like_credential(key) and match.group(3)[:1] not in "\"'"
                and (match.group(2) or line != line.rstrip())):
            _warn_once(path, lineno, key, "bare-space",
                       f"{key} is unquoted, so the spaces around its value were removed. If that whitespace "
                       f"belongs to the credential, wrap the whole value in single quotes.")
        loaded[key] = value
        first_lines[key] = lineno
    return loaded


@dataclass(frozen=True)
class EnvValue:
    """An environment value and the source that won precedence resolution."""
    value: str
    source: str                         # "environment", "dotenv", or "missing"


def resolve_env(name: str, dotenv: Mapping[str, str] | None = None,
                environ: Mapping[str, str] | None = None) -> EnvValue:
    """Resolve an environment setting without mutation; exported values override .env values."""
    environment = os.environ if environ is None else environ
    if name in environment:
        return EnvValue(environment[name], "environment")
    if dotenv is not None and name in dotenv:
        return EnvValue(dotenv[name], "dotenv")
    return EnvValue("", "missing")


def load_dotenv(path: str | Path, *, override: bool = False) -> dict[str, str]:
    """Compatibility loader: parse with :func:`read_dotenv`, then update ``os.environ``."""
    loaded = read_dotenv(path)
    for key, value in loaded.items():
        if override or key not in os.environ:
            os.environ[key] = value
    return loaded


_PERMISSION_WARNINGS_SHOWN: set[str] = set()
_VALUE_WARNINGS_SHOWN: set[tuple[str, str, str]] = set()


def _warn_once(path: Path, lineno: int, key: str, kind: str, message: str) -> None:
    """Explain one lossy or newly reinterpreted .env value, at most once per process.

    The terminal home re-reads credentials on every status refresh, so an unsuppressed warning
    would either scroll away or bury the screen. Never include the value itself.
    """
    marker = (os.path.normcase(str(path)), key, kind)
    if marker in _VALUE_WARNINGS_SHOWN:
        return
    _VALUE_WARNINGS_SHOWN.add(marker)
    logging.getLogger("sia.config").warning("%s:%d: %s", path, lineno, message)


def _warn_if_readable_by_others(path: Path) -> None:
    """Warn once per file per process: the terminal home re-reads credentials on every status refresh."""
    key = os.path.normcase(str(path.resolve()))
    if key in _PERMISSION_WARNINGS_SHOWN:
        return
    if windows_acl_supported():
        status = inspect_credential_permissions(path)
        if status.secure is not True:
            _PERMISSION_WARNINGS_SHOWN.add(key)
            logging.getLogger("sia.config").warning("%s: %s", path, status.message)
        return
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        _PERMISSION_WARNINGS_SHOWN.add(key)
        logging.getLogger("sia.config").warning(
            "%s is readable by other users (mode %o); run: chmod 600 %s", path, stat.S_IMODE(mode), path)


def load_password_file(path: str | Path) -> dict[str, str]:
    """Strong-account passwords from a CSV with columns name,password (name = strong_accounts.csv `name`, or the
    name rendered from strong_account_template).

    Keep this file outside the repository with owner-only permissions. Every password is registered with the
    redactor so it can never appear in logs or error messages.
    """
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"password file not found: {path}")
    _warn_if_readable_by_others(path)
    passwords: dict[str, str] = {}
    names_seen: dict[str, str] = {}
    problems: list[str] = []
    reader: csv.DictReader[str] | None = None
    try:
        with path.open(encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh, strict=True)
            raw_header = reader.fieldnames or []
            header = [h.strip() for h in raw_header]
            duplicates = sorted({h for h in header if h and header.count(h) > 1})
            if any(not h for h in header):
                raise ConfigError(f"{path.name}: header contains a blank column name")
            if duplicates:
                raise ConfigError(f"{path.name}: header contains duplicate column(s): {', '.join(duplicates)}")
            if "name" not in header or "password" not in header:
                raise ConfigError(f"{path.name}: header must contain the columns name,password")
            unknown = sorted(set(header) - {"name", "password"})
            if unknown:
                raise ConfigError(f"{path.name}: unknown column(s): {', '.join(unknown)} (allowed: name, password)")
            for raw in reader:
                line = reader.line_num
                if None in raw and any((cell or "").strip() for cell in raw[None]):  # type: ignore[index]
                    problems.append(f"{path.name}:{line}: more cells than header columns")
                cells = {(key or "").strip(): value for key, value in raw.items() if key is not None}
                name = (cells.get("name") or "").strip()
                password = (cells.get("password") or "")
                if not name and not password.strip():
                    continue
                canonical = name.casefold()
                if not name:
                    problems.append(f"{path.name}:{line}: name is required")
                elif canonical in names_seen:
                    problems.append(f"{path.name}:{line}: duplicate name {name!r} (also {names_seen[canonical]!r})")
                elif not password:
                    problems.append(f"{path.name}:{line}: password for {name!r} is empty")
                else:
                    names_seen[canonical] = name
                    passwords[name] = password
                    register_secret(password)
    except csv.Error as exc:
        line = reader.line_num if reader is not None else 1
        raise ConfigError(f"{path.name}:{line}: invalid CSV: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{path}: password file must be UTF-8 text: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read password file {path}: {exc}") from exc
    if problems:
        raise ConfigError("\n".join(problems))
    return passwords


def env_var_for_password(account_name: str) -> str:
    """Default env var name for a credentials-type strong account: SIA_SA_<NAME>_PASSWORD."""
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", account_name).strip("_").upper()
    if not normalized:
        raise ConfigError("strong-account name must contain a letter or digit to derive its password environment variable")
    return f"SIA_SA_{normalized}_PASSWORD"
