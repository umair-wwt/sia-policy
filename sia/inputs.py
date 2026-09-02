"""CSV inputs: servers.csv (mapping), strong_accounts.csv, groups.csv (optional). Validation reports every problem.

One server may appear on several rows (one access policy each, e.g. one per Identity group): the rows must agree
on the strong account, domain and protocol, and every row must end up with a distinct policy name.
"""
from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

from .config import StrongAccountTemplate, env_var_for_password

FQDN_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
FQDN_RE = re.compile(rf"^(?:{FQDN_LABEL}\.)+{FQDN_LABEL}$")
STRONG_ACCOUNT_TYPES = ("existing", "vault", "credentials")
PROTOCOLS = ("rdp", "ssh")
LIST_SEPARATOR = ";"
MAX_POLICY_NAME = 200          # UAP: metadata.name is 1..200 characters
MAX_WINDOWS_USERNAME = 20      # SAM account names longer than this cannot log on
TRUE_WORDS = ("yes", "y", "true", "1")
FALSE_WORDS = ("no", "n", "false", "0")


class InputError(Exception):
    """One or more input problems; the message lists all of them with file:line."""


@dataclass(frozen=True)
class ServerRow:
    fqdn: str
    strong_account: str | None          # None for protocol=ssh (Linux ZSP uses an SSH certificate, no strong account)
    groups: tuple[str, ...]
    policy_name: str | None
    assign_groups: tuple[str, ...] | None
    domain: str | None
    description: str | None
    line: int
    protocol: str = "rdp"               # rdp (Windows, ephemeral local user) | ssh (Linux, SSH certificate)
    ssh_username: str | None = None     # protocol=ssh: username on the certificate; falls back to defaults.ssh_username
    policy_suffix: str | None = None    # appended to the templated policy name (second policy for the same server)
    domain_joined: bool = True          # False: the target is not joined to a domain (connect-info adds "/d local")

    @property
    def hostname(self) -> str:
        return self.fqdn.split(".", 1)[0]

    @property
    def dns_domain(self) -> str:
        return self.domain or self.fqdn.split(".", 1)[1]

    @property
    def is_ssh(self) -> bool:
        return self.protocol == "ssh"


@dataclass(frozen=True)
class StrongAccountRow:
    name: str
    type: str
    safe: str | None
    account_name: str | None
    username: str | None
    account_domain: str
    password_env: str | None
    line: int
    address: str | None = None          # Vault onboarding only: the account's address (server FQDN or AD domain)

    @property
    def secret_type(self) -> str | None:
        return {"vault": "PCloudAccount", "credentials": "ProvisionerUser"}.get(self.type)

    @property
    def sia_name(self) -> str:
        """Name of the secret in SIA. Vault-referenced accounts are always named <account_name>_<safe> (the platform
        generates that name and rejects a custom one); the CSV `name` is only the key used by servers.csv."""
        if self.type == "vault":
            return f"{self.account_name}_{self.safe}"
        return self.name

    @property
    def is_local(self) -> bool:
        return (self.account_domain or "local").lower() == "local"


@dataclass(frozen=True)
class GroupRow:
    name: str
    directory: str | None
    line: int


@dataclass(frozen=True)
class Inputs:
    servers: tuple[ServerRow, ...]
    strong_accounts: dict[str, StrongAccountRow]
    groups: dict[str, GroupRow]
    warnings: tuple[str, ...] = field(default=())

    def strong_account_for(self, server: ServerRow) -> StrongAccountRow:
        if server.strong_account is None:
            raise KeyError(f"{server.fqdn} ({server.protocol}) has no strong account")
        return self.strong_accounts[server.strong_account]

    def pinned_directory(self, group_name: str) -> str | None:
        row = self.groups.get(group_name)
        return row.directory if row else None

    @property
    def referenced_strong_accounts(self) -> list[StrongAccountRow]:
        names = {s.strong_account for s in self.servers if s.strong_account}
        return [sa for name, sa in self.strong_accounts.items() if name in names]

    @property
    def referenced_groups(self) -> list[str]:
        seen: dict[str, None] = {}
        for server in self.servers:
            for group in server.groups:
                seen.setdefault(group, None)
        return list(seen)

    @property
    def unique_fqdns(self) -> tuple[str, ...]:
        seen: dict[str, None] = {}
        for server in self.servers:
            seen.setdefault(server.fqdn, None)
        return tuple(seen)

    def rows_for(self, fqdn: str) -> tuple[ServerRow, ...]:
        return tuple(s for s in self.servers if s.fqdn == fqdn)

    @property
    def target_rows(self) -> tuple[ServerRow, ...]:
        """One row per Windows server (the first rdp row of each FQDN): the strong account / target set unit."""
        seen: dict[str, ServerRow] = {}
        for server in self.servers:
            if not server.is_ssh:
                seen.setdefault(server.fqdn, server)
        return tuple(seen.values())

    def window(self, offset: int = 0, limit: int | None = None) -> Inputs:
        """Slice by server (all rows of a server travel together), for waves: --offset/--limit."""
        fqdns = self.unique_fqdns[offset:(offset + limit) if limit else None]
        keep = set(fqdns)
        return replace(self, servers=tuple(s for s in self.servers if s.fqdn in keep))


def _split_list(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(part.strip() for part in value.split(LIST_SEPARATOR) if part.strip())


def _parse_bool(value: str | None, default: bool) -> bool | None:
    """yes/no style cell -> bool; None when the value is not recognised."""
    text = (value or "").strip().lower()
    if not text:
        return default
    if text in TRUE_WORDS:
        return True
    if text in FALSE_WORDS:
        return False
    return None


def read_csv(path: Path, required: tuple[str, ...], optional: tuple[str, ...]) -> list[tuple[int, dict[str, str]]]:
    """Read a CSV with a header row. Returns (line_number, row) pairs; cells stripped; blank rows skipped."""
    problems: list[str] = []
    with path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        header = [h.strip() for h in (reader.fieldnames or [])]
        if not header:
            raise InputError(f"{path.name}: file is empty (expected a header row)")
        missing = [c for c in required if c not in header]
        unknown = [c for c in header if c and c not in required + optional]
        if missing:
            problems.append(f"{path.name}: missing required column(s): {', '.join(missing)}")
        if unknown:
            problems.append(f"{path.name}: unknown column(s): {', '.join(unknown)} (allowed: {', '.join(required + optional)})")
        if problems:
            raise InputError("\n".join(problems))
        rows: list[tuple[int, dict[str, str]]] = []
        for raw in reader:
            line = reader.line_num
            cells = {(k or "").strip(): (v or "").strip() for k, v in raw.items() if k is not None}
            if None in raw and any((x or "").strip() for x in raw[None]):  # type: ignore[index]
                problems.append(f"{path.name}:{line}: more cells than header columns")
            if not any(cells.values()):
                continue
            rows.append((line, cells))
    if problems:
        raise InputError("\n".join(problems))
    return rows


def _render_name(template: str, fqdn: str, domain: str) -> str:
    hostname = fqdn.split(".", 1)[0]
    return template.format(hostname=hostname, fqdn=fqdn, domain=domain)


def effective_policy_name(template: str, fqdn: str, dns_domain: str, policy_name: str | None,
                          policy_suffix: str | None = None) -> str:
    """The policy name a row ends up with: an explicit policy_name wins; otherwise the template plus the suffix."""
    if policy_name:
        return policy_name
    return _render_name(template, fqdn, dns_domain) + (policy_suffix or "")


def _templated_account(spec: StrongAccountTemplate, fqdn: str, dns_domain: str, warnings: list[str], where: str) -> StrongAccountRow:
    name = _render_name(spec.name, fqdn, dns_domain)
    username = _render_name(spec.username, fqdn, dns_domain) if spec.username else None
    if username and len(username) > MAX_WINDOWS_USERNAME:
        warnings.append(f"{where}: strong account user name {username!r} is longer than {MAX_WINDOWS_USERNAME} characters")
    domain = spec.account_domain or "local"
    address = fqdn if domain.lower() == "local" else domain
    if spec.type == "vault":
        return StrongAccountRow(name=name, type="vault", safe=_render_name(spec.safe, fqdn, dns_domain),
                                account_name=_render_name(spec.account_name, fqdn, dns_domain), username=username,
                                account_domain=domain, password_env=None, line=0, address=address)
    if spec.type == "credentials":
        return StrongAccountRow(name=name, type="credentials", safe=None, account_name=None, username=username,
                                account_domain=domain, password_env=env_var_for_password(name), line=0, address=address)
    return StrongAccountRow(name=name, type="existing", safe=None, account_name=None, username=None,
                            account_domain=domain, password_env=None, line=0)


def _parse_servers(path: Path, problems: list[str], warnings: list[str], spec: StrongAccountTemplate | None,
                   ssh_username_default: str, policy_name_template: str) -> tuple[list[ServerRow], dict[str, StrongAccountRow]]:
    rows = read_csv(path, ("fqdn", "strong_account", "group"),
                    ("policy_name", "policy_suffix", "assign_groups", "domain", "description", "protocol", "ssh_username",
                     "domain_joined"))
    servers: list[ServerRow] = []
    templated: dict[str, StrongAccountRow] = {}
    first_row: dict[str, ServerRow] = {}
    policy_names: dict[str, tuple[str, int]] = {}
    for line, c in rows:
        where = f"{path.name}:{line}"
        fqdn = c["fqdn"].lower().rstrip(".")
        if not FQDN_RE.match(fqdn) or all(label.isdigit() for label in fqdn.split(".")):
            problems.append(f"{where}: fqdn {c['fqdn']!r} is not a valid FQDN (host.domain.tld; IPs not supported)")
        protocol = (c.get("protocol") or "rdp").lower()
        if protocol not in PROTOCOLS:
            problems.append(f"{where}: protocol must be one of {', '.join(PROTOCOLS)}, got {c['protocol']!r}")
            protocol = "rdp"
        domain = c.get("domain", "").lower().rstrip(".") or None
        if domain and not all(re.fullmatch(FQDN_LABEL, label) for label in domain.split(".")):
            problems.append(f"{where}: domain {c['domain']!r} is not a valid DNS name")
        dns_domain = domain or (fqdn.split(".", 1)[1] if "." in fqdn else "")

        strong_account: str | None = c["strong_account"] or None
        ssh_username: str | None = c.get("ssh_username") or None
        assign_groups = _split_list(c.get("assign_groups")) or None
        if protocol == "ssh":
            if strong_account:
                warnings.append(f"{where}: strong_account {strong_account!r} ignored for protocol=ssh (Linux ZSP uses an SSH certificate)")
                strong_account = None
            if assign_groups:
                warnings.append(f"{where}: assign_groups ignored for protocol=ssh")
                assign_groups = None
            if not ssh_username and not ssh_username_default:
                problems.append(f"{where}: protocol=ssh needs ssh_username (or set defaults.ssh_username in config.toml)")
        else:
            if ssh_username:
                warnings.append(f"{where}: ssh_username ignored for protocol=rdp")
                ssh_username = None
            if not strong_account:
                if spec:
                    account = _templated_account(spec, fqdn, dns_domain, warnings, where)
                    strong_account = account.name
                    templated.setdefault(account.name, account)
                else:
                    problems.append(f"{where}: strong_account is required (or set defaults.strong_account_template in config.toml)")
        groups = _split_list(c["group"])
        if not groups:
            problems.append(f"{where}: group is required (separate several with '{LIST_SEPARATOR}')")

        policy_name = c.get("policy_name") or None
        policy_suffix = c.get("policy_suffix") or None
        if policy_name and policy_suffix:
            warnings.append(f"{where}: policy_suffix {policy_suffix!r} ignored because policy_name is set")
            policy_suffix = None
        try:
            effective = effective_policy_name(policy_name_template, fqdn, dns_domain, policy_name, policy_suffix)
        except (KeyError, IndexError, ValueError) as exc:
            problems.append(f"{where}: policy_name_template {policy_name_template!r} is invalid: {exc}")
            effective = f"{fqdn}#{line}"
        if not 1 <= len(effective) <= MAX_POLICY_NAME:
            problems.append(f"{where}: policy name {effective!r} must be 1..{MAX_POLICY_NAME} characters")
        if effective in policy_names:
            other_fqdn, other_line = policy_names[effective]
            hint = ("set policy_suffix (or policy_name) per row" if other_fqdn == fqdn
                    else "use {fqdn} in policy_name_template or set policy_name per row")
            problems.append(f"{where}: policy name {effective!r} ({fqdn}) collides with line {other_line} ({other_fqdn}); {hint}")
        else:
            policy_names[effective] = (fqdn, line)
        domain_joined = _parse_bool(c.get("domain_joined"), True)
        if domain_joined is None:
            problems.append(f"{where}: domain_joined must be yes or no, got {c['domain_joined']!r}")
            domain_joined = True

        row = ServerRow(
            fqdn=fqdn, strong_account=strong_account, groups=groups,
            policy_name=policy_name, assign_groups=assign_groups,
            domain=domain, description=c.get("description") or None, line=line,
            protocol=protocol, ssh_username=ssh_username, policy_suffix=policy_suffix, domain_joined=domain_joined,
        )
        first = first_row.get(fqdn)
        if first is None:
            first_row[fqdn] = row
        else:
            for label, mine, theirs in (("strong_account", row.strong_account, first.strong_account),
                                        ("domain", row.domain, first.domain), ("protocol", row.protocol, first.protocol)):
                if mine != theirs:
                    problems.append(f"{where}: {label} {mine!r} conflicts with line {first.line} ({theirs!r}) for the same fqdn {fqdn}")
        servers.append(row)
    return servers, templated


def _parse_strong_accounts(path: Path, problems: list[str]) -> dict[str, StrongAccountRow]:
    rows = read_csv(path, ("name", "type"), ("safe", "account_name", "username", "account_domain", "password_env", "address"))
    accounts: dict[str, StrongAccountRow] = {}
    lowered: dict[str, str] = {}
    for line, c in rows:
        name, kind = c["name"], c["type"].lower()
        if not name:
            problems.append(f"{path.name}:{line}: name is required")
            continue
        if name.lower() in lowered:
            problems.append(f"{path.name}:{line}: duplicate strong account name {name!r} (also {lowered[name.lower()]!r})")
            continue
        lowered[name.lower()] = name
        if kind not in STRONG_ACCOUNT_TYPES:
            problems.append(f"{path.name}:{line}: type must be one of {', '.join(STRONG_ACCOUNT_TYPES)}, got {c['type']!r}")
        if kind == "vault" and not (c.get("safe") and c.get("account_name")):
            problems.append(f"{path.name}:{line}: type=vault requires safe and account_name")
        if kind == "credentials" and not c.get("username"):
            problems.append(f"{path.name}:{line}: type=credentials requires username")
        if kind == "existing" and any(c.get(k) for k in ("safe", "account_name", "username", "password_env", "address")):
            problems.append(f"{path.name}:{line}: type=existing rows must not set safe/account_name/username/password_env/address")
        password_env = c.get("password_env") or (env_var_for_password(name) if kind == "credentials" else None)
        accounts[name] = StrongAccountRow(
            name=name, type=kind, safe=c.get("safe") or None, account_name=c.get("account_name") or None,
            username=c.get("username") or None, account_domain=(c.get("account_domain") or "local"),
            password_env=password_env, line=line, address=c.get("address") or None,
        )
    return accounts


def _parse_groups(path: Path, problems: list[str]) -> dict[str, GroupRow]:
    if not path.is_file():
        return {}
    rows = read_csv(path, ("name",), ("directory",))
    groups: dict[str, GroupRow] = {}
    for line, c in rows:
        if not c["name"]:
            problems.append(f"{path.name}:{line}: name is required")
            continue
        if c["name"] in groups:
            problems.append(f"{path.name}:{line}: duplicate group {c['name']!r}")
            continue
        groups[c["name"]] = GroupRow(name=c["name"], directory=c.get("directory") or None, line=line)
    return groups


def load_inputs(input_dir: str | Path, *, strong_account_template: str | StrongAccountTemplate = "",
                ssh_username_default: str = "", policy_name_template: str = "{fqdn}") -> Inputs:
    """Load and validate the three CSVs.

    strong_account_template: used when an rdp row leaves strong_account blank. A plain string (e.g. "ADM-{hostname}")
    means "look the rendered name up in SIA as an existing strong account"; a StrongAccountTemplate can also describe
    a Vault reference or stored credentials to create per server. Names typed explicitly in servers.csv must always
    be declared in strong_accounts.csv (typo protection); explicit rows win over templated ones.
    policy_name_template: needed here so duplicate policy names are rejected before any tenant contact.
    """
    input_dir = Path(input_dir)
    problems: list[str] = []
    warnings: list[str] = []
    for required in ("servers.csv", "strong_accounts.csv"):
        if not (input_dir / required).is_file():
            problems.append(f"{input_dir / required}: file not found")
    if problems:
        raise InputError("\n".join(problems))
    spec: StrongAccountTemplate | None
    if isinstance(strong_account_template, StrongAccountTemplate):
        spec = strong_account_template
    else:
        spec = StrongAccountTemplate(name=strong_account_template) if strong_account_template else None

    servers, templated = _parse_servers(input_dir / "servers.csv", problems, warnings, spec, ssh_username_default,
                                        policy_name_template)
    accounts = _parse_strong_accounts(input_dir / "strong_accounts.csv", problems)
    groups = _parse_groups(input_dir / "groups.csv", problems)

    for name in sorted(templated):
        if name not in accounts:
            accounts[name] = templated[name]
    for server in servers:
        if server.strong_account and server.strong_account not in accounts:
            problems.append(
                f"servers.csv:{server.line}: strong_account {server.strong_account!r} is not defined in strong_accounts.csv "
                f"(add a row with type=existing if it already exists in SIA)")
    if problems:
        raise InputError("\n".join(problems))
    return Inputs(servers=tuple(servers), strong_accounts=accounts, groups=groups, warnings=tuple(warnings))
