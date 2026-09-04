"""Configuration loading: config.toml (non-secret) + .env (secrets) + validation."""
from __future__ import annotations

import csv
import logging
import os
import re
import stat
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from .redact import register_secret

HOUR_RE = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")
SUBDOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
TAG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
IDENTITY_AUTH_METHODS = ("platform_token", "service_user_oidc")
STRONG_ACCOUNT_TYPES = ("existing", "vault", "credentials")
SECRETS_API_FAMILIES = ("auto", "public", "legacy")
TARGETSETS_API_FAMILIES = ("auto", "legacy", "discovery")
PVWA_AUTH_TYPES = ("cyberark", "ldap")
TEMPLATE_PLACEHOLDERS = ("hostname", "fqdn", "domain", "hostname_upper", "hostname_lower", "domain_upper")
TARGET_SET_SCOPES = ("server", "auto", "domain")
POLICY_STATUSES = ("Active", "Suspended")
# [defaults] keys that must be written explicitly in config.toml (no silent organizational defaults)
REQUIRED_DEFAULT_KEYS = ("days_of_week", "from_hour", "to_hour", "target_set_cert_validation")


class ConfigError(Exception):
    """Raised for invalid or missing configuration."""


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
    ssh_username: str = ""                     # default certificate username for protocol=ssh rows
    # Identity group derived from the server name (servers.csv leaves group blank), e.g. "SIA-{hostname_upper}-RDP".
    # domains.csv may override it per domain. Several groups: separate them with ';'.
    group_template: str = ""
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
    status_polls: int = 1                      # GETs after creating a policy while it is still "Validating" (1..10)
    max_requests_per_second: float = 0.0       # global rate limit shared by all workers; 0 = off
    lookup_search_max_rows: int = 2000         # --lookup auto: search per server up to this many servers, else list
    secrets_api: str = "auto"                  # auto | public (/api/secrets/public/v1+v2) | legacy (/api/secrets)
    targetsets_api: str = "auto"               # auto | legacy (/api/targetsets) | discovery (/api/discovery/targetsets)
    ca_bundle: str = ""                        # PEM file/dir of trusted CAs (TLS-inspecting proxies); "" = certifi
    verify: bool = True                        # never set false outside a lab: it disables TLS verification entirely

    @property
    def tls_verify(self) -> str | bool:
        """What to pass to requests as `verify`: a CA bundle path, or True/False."""
        if not self.verify:
            return False
        return self.ca_bundle or True


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


def _build(cls, section: dict[str, Any], name: str):
    """Instantiate a frozen dataclass from a TOML table, rejecting unknown keys and coercing lists to tuples."""
    known = {f.name: f for f in fields(cls)}
    unknown = sorted(set(section) - set(known))
    if unknown:
        raise ConfigError(f"[{name}] has unknown key(s): {', '.join(unknown)}")
    kwargs = {}
    for key, value in section.items():
        if isinstance(value, list):
            value = tuple(value)
        kwargs[key] = value
    try:
        return cls(**kwargs)
    except TypeError as exc:
        raise ConfigError(f"[{name}] is invalid: {exc}") from exc


def _check_template(label: str, template: str, placeholders: tuple[str, ...] = TEMPLATE_PLACEHOLDERS) -> None:
    # longest first: {hostname_upper} must not be read as {hostname} followed by stray text
    alternatives = "|".join(sorted(placeholders, key=len, reverse=True))
    if re.sub(r"\{(" + alternatives + r")\}", "", template).count("{"):
        allowed = ", ".join("{" + p + "}" for p in placeholders)
        raise ConfigError(f"[defaults] {label} may only use {allowed}")


def validate(cfg: Config) -> None:
    t, d, h = cfg.tenant, cfg.defaults, cfg.http
    if not t.subdomain or not SUBDOMAIN_RE.match(t.subdomain):
        raise ConfigError("[tenant] subdomain must be the tenant subdomain only, e.g. 'acme' (lowercase letters, digits, '-')")
    if not t.identity_url.startswith("https://") or t.identity_url.endswith("/"):
        raise ConfigError("[tenant] identity_url must start with https:// and have no trailing slash")
    if not t.root_domain or "/" in t.root_domain:
        raise ConfigError("[tenant] root_domain must be a bare domain such as cyberark.cloud")
    for label, value in (("from_hour", d.from_hour), ("to_hour", d.to_hour)):
        if value and not HOUR_RE.match(value):
            raise ConfigError(f"[defaults] {label} must be HH:MM (24h) or empty, got {value!r}")
    if bool(d.from_hour) != bool(d.to_hour):
        raise ConfigError("[defaults] from_hour and to_hour must both be set or both be empty")
    if not 1 <= d.max_session_hours <= 24:
        raise ConfigError("[defaults] max_session_hours must be between 1 and 24")
    if not 1 <= d.idle_minutes <= 120:
        raise ConfigError("[defaults] idle_minutes must be between 1 and 120")
    if not d.days_of_week or any((not isinstance(x, int)) or x < 0 or x > 6 for x in d.days_of_week):
        raise ConfigError("[defaults] days_of_week must be a non-empty list of integers 0 (Sunday) .. 6 (Saturday)")
    if len(set(d.days_of_week)) != len(d.days_of_week):
        raise ConfigError("[defaults] days_of_week contains duplicates")
    if not d.assign_local_groups:
        raise ConfigError("[defaults] assign_local_groups must list at least one local group")
    for label in ("policy_name_template", "strong_account_template", "strong_account_safe_template",
                  "strong_account_account_name_template", "strong_account_username_template",
                  "strong_account_domain", "group_template"):
        _check_template(label, getattr(d, label))
    if not d.policy_name_template.strip():
        raise ConfigError("[defaults] policy_name_template must not be empty")
    if d.target_set_scope not in TARGET_SET_SCOPES:
        raise ConfigError(f"[defaults] target_set_scope must be one of {', '.join(TARGET_SET_SCOPES)}")
    if d.policy_status not in POLICY_STATUSES:
        raise ConfigError(f"[defaults] policy_status must be one of {', '.join(POLICY_STATUSES)} "
                          "(Validating/Error/Warning are set by the platform, not requested)")
    _check_template("description_template", d.description_template, TEMPLATE_PLACEHOLDERS + ("protocol",))
    if d.strong_account_type not in STRONG_ACCOUNT_TYPES:
        raise ConfigError(f"[defaults] strong_account_type must be one of {', '.join(STRONG_ACCOUNT_TYPES)}")
    if d.strong_account_type != "existing" and not d.strong_account_template:
        raise ConfigError("[defaults] strong_account_type = vault/credentials needs strong_account_template (the account's name)")
    if d.strong_account_template and d.strong_account_type == "vault" and not (
            d.strong_account_safe_template and d.strong_account_account_name_template):
        raise ConfigError("[defaults] strong_account_type = \"vault\" needs strong_account_safe_template and "
                          "strong_account_account_name_template")
    if d.strong_account_template and d.strong_account_type == "credentials" and not d.strong_account_username_template:
        raise ConfigError("[defaults] strong_account_type = \"credentials\" needs strong_account_username_template")
    if not d.strong_account_domain:
        raise ConfigError("[defaults] strong_account_domain must be \"local\" or an AD domain name")
    if d.provision_format and "<user>" not in d.provision_format:
        raise ConfigError("[defaults] provision_format must contain <user> (SIA rejects formats without it)")
    if not TAG_RE.match(d.owner_tag):
        raise ConfigError("[defaults] owner_tag must be 1-64 characters of letters, digits, '_', '.' or '-'")
    if cfg.auth.identity_auth not in IDENTITY_AUTH_METHODS:
        raise ConfigError(f"[auth] identity_auth must be one of {', '.join(IDENTITY_AUTH_METHODS)}")
    if not cfg.auth.oidc_application:
        raise ConfigError("[auth] oidc_application must not be empty")
    if h.timeout_seconds <= 0 or h.max_retries < 0:
        raise ConfigError("[http] timeout_seconds must be > 0 and max_retries >= 0")
    if not 1 <= h.status_polls <= 10:
        raise ConfigError("[http] status_polls must be between 1 and 10")
    if not isinstance(h.max_requests_per_second, (int, float)) or h.max_requests_per_second < 0:
        raise ConfigError("[http] max_requests_per_second must be a number >= 0 (0 = no limit)")
    if not isinstance(h.lookup_search_max_rows, int) or h.lookup_search_max_rows < 0:
        raise ConfigError("[http] lookup_search_max_rows must be an integer >= 0")
    if h.secrets_api not in SECRETS_API_FAMILIES:
        raise ConfigError(f"[http] secrets_api must be one of {', '.join(SECRETS_API_FAMILIES)}")
    if h.targetsets_api not in TARGETSETS_API_FAMILIES:
        raise ConfigError(f"[http] targetsets_api must be one of {', '.join(TARGETSETS_API_FAMILIES)}")
    if h.ca_bundle and not Path(h.ca_bundle).exists():
        raise ConfigError(f"[http] ca_bundle {h.ca_bundle!r} does not exist (expected a PEM file or a directory of them)")
    if h.ca_bundle and not h.verify:
        raise ConfigError("[http] ca_bundle is set but verify = false; pick one")
    p = cfg.pvwa
    if p.base_url and (not p.base_url.startswith("https://") or p.base_url.endswith("/")):
        raise ConfigError("[pvwa] base_url must start with https:// and have no trailing slash")
    if p.auth_type not in PVWA_AUTH_TYPES:
        raise ConfigError(f"[pvwa] auth_type must be one of {', '.join(PVWA_AUTH_TYPES)}")
    if not p.platform_id:
        raise ConfigError("[pvwa] platform_id must not be empty")
    c = cfg.connect
    if c.gateway_host and ("/" in c.gateway_host or " " in c.gateway_host):
        raise ConfigError("[connect] gateway_host must be a bare host name such as acme.rdp.cyberark.cloud")
    if c.login_suffix and ("@" in c.login_suffix or " " in c.login_suffix):
        raise ConfigError("[connect] login_suffix is the part after '@' in login names, e.g. acme.cyberark.cloud")


def load_config(path: str | Path) -> Config:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"config file not found: {path} (copy config.example.toml to config.toml)")
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc
    unknown = sorted(set(raw) - set(SECTIONS))
    if unknown:
        raise ConfigError(f"{path}: unknown section(s): {', '.join(unknown)}")
    if "tenant" not in raw:
        raise ConfigError(f"{path}: missing [tenant] section")
    missing = [k for k in REQUIRED_DEFAULT_KEYS if k not in raw.get("defaults", {})]
    if missing:
        raise ConfigError(
            f"{path}: [defaults] must set {', '.join(missing)} explicitly -- the access window (days_of_week, from_hour/to_hour; "
            "\"\" = all day) and target_set_cert_validation are organizational decisions, not tool defaults")
    cfg = Config(
        tenant=_build(TenantConfig, raw["tenant"], "tenant"),
        defaults=_build(Defaults, raw.get("defaults", {}), "defaults"),
        auth=_build(AuthConfig, raw.get("auth", {}), "auth"),
        http=_build(HttpConfig, raw.get("http", {}), "http"),
        connect=_build(ConnectConfig, raw.get("connect", {}), "connect"),
        pvwa=_build(PVWAConfig, raw.get("pvwa", {}), "pvwa"),
    )
    validate(cfg)
    return cfg


_ENV_LINE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def load_dotenv(path: str | Path, *, override: bool = False) -> dict[str, str]:
    """Minimal .env loader (KEY=VALUE, '#' comments, optional single/double quotes). Missing file is fine."""
    path = Path(path)
    loaded: dict[str, str] = {}
    if not path.is_file():
        return loaded
    _warn_if_readable_by_others(path)
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ENV_LINE.match(stripped)
        if not match:
            raise ConfigError(f"{path}:{lineno}: expected KEY=VALUE")
        key, value = match.group(1), match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        loaded[key] = value
        if override or key not in os.environ:
            os.environ[key] = value
    return loaded


def _warn_if_readable_by_others(path: Path) -> None:
    if os.name == "nt":
        return
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        logging.getLogger("sia.config").warning(
            "%s is readable by other users (mode %o); run: chmod 600 %s", path, stat.S_IMODE(mode), path)


def require_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ConfigError(f"environment variable {name} is not set (put it in .env or export it)")
    return value


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
    problems: list[str] = []
    with path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        header = [h.strip() for h in (reader.fieldnames or [])]
        if "name" not in header or "password" not in header:
            raise ConfigError(f"{path.name}: header must contain the columns name,password")
        for raw in reader:
            line = reader.line_num
            name = (raw.get("name") or "").strip()
            password = (raw.get("password") or "")
            if not name and not password.strip():
                continue
            if not name:
                problems.append(f"{path.name}:{line}: name is required")
            elif name in passwords:
                problems.append(f"{path.name}:{line}: duplicate name {name!r}")
            elif not password:
                problems.append(f"{path.name}:{line}: password for {name!r} is empty")
            else:
                passwords[name] = password
                register_secret(password)
    if problems:
        raise ConfigError("\n".join(problems))
    return passwords


def env_var_for_password(account_name: str) -> str:
    """Default env var name for a credentials-type strong account: SIA_SA_<NAME>_PASSWORD."""
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", account_name).strip("_").upper()
    return f"SIA_SA_{normalized}_PASSWORD"
