"""CSV inputs: servers.csv (mapping), domains.csv, strong_accounts.csv, groups.csv. Only servers.csv is required;
validation reports every problem at once.

One server may appear on several rows (one access policy each, e.g. one per Identity group): the rows must agree
on the strong account, domain and protocol, and every row must end up with a distinct policy name.

Two things a row can leave blank are filled in by convention:
  * `group`          from domains.csv `group_template`, else [defaults] group_template;
  * `strong_account` from domains.csv for a domain-joined server (its domain's shared account), else the
                     [defaults] strong_account_template (the per-host local administrator).
Which of those two routes supplied the account also decides how wide the server's target set is -- see
`_resolve_target_set`.
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
# SIA target-set types (ArkSIATargetSetType). "Target" is one machine, "Domain" every machine in an AD domain,
# "Suffix" every machine under a DNS suffix. Keys are lower-cased for tolerant CSV matching.
TARGET_SET_TYPES = {"target": "Target", "domain": "Domain", "suffix": "Suffix"}
DEFAULT_TARGET_SET_TYPE = "Target"
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
    target_set_name: str = ""           # "" = the server's own FQDN; else a set shared with other servers (a domain)
    target_set_type: str = DEFAULT_TARGET_SET_TYPE   # Target (this machine) | Domain | Suffix

    @property
    def hostname(self) -> str:
        return self.fqdn.split(".", 1)[0]

    @property
    def dns_domain(self) -> str:
        # partition, not split: an invalid fqdn without a dot must still report cleanly, not raise IndexError
        return self.domain or self.fqdn.partition(".")[2]

    @property
    def is_ssh(self) -> bool:
        return self.protocol == "ssh"

    @property
    def target_set_key(self) -> str:
        """The target set this server needs, lower-cased. Several servers may share one (a Domain set)."""
        return (self.target_set_name or self.fqdn).lower()

    @property
    def shares_target_set(self) -> bool:
        return bool(self.target_set_name) and self.target_set_name.lower() != self.fqdn.lower()


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
class DomainRow:
    """One AD domain: the strong account shared by every server in it, and how those servers are grouped."""
    domain: str
    strong_account: str | None
    target_set: str | None              # None = the domain name itself
    target_set_type: str                # Domain (default) | Suffix | Target
    group_template: str | None          # overrides [defaults] group_template for servers in this domain
    line: int

    @property
    def target_set_name(self) -> str:
        return self.target_set or self.domain


@dataclass(frozen=True)
class Inputs:
    servers: tuple[ServerRow, ...]
    strong_accounts: dict[str, StrongAccountRow]
    groups: dict[str, GroupRow]
    warnings: tuple[str, ...] = field(default=())
    domains: dict[str, DomainRow] = field(default_factory=dict)

    def domain_for(self, dns_domain: str) -> DomainRow | None:
        return self.domains.get((dns_domain or "").lower())

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
        """One row per Windows server (the first rdp row of each FQDN). Note this is not the target-set unit:
        several servers can share one set -- group by `ServerRow.target_set_key` for that."""
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
    """Render a name template. Keep the placeholder set in step with config.TEMPLATE_PLACEHOLDERS and payloads.render.

    The *_upper / *_lower variants exist because FQDNs are lower-cased on the way in while Identity group names are
    often written in upper case; group lookup is case-insensitive either way, but the rendered name should read right.
    """
    hostname = fqdn.split(".", 1)[0]
    return template.format(hostname=hostname, fqdn=fqdn, domain=domain,
                           hostname_upper=hostname.upper(), hostname_lower=hostname.lower(),
                           domain_upper=domain.upper())


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
    domain = _render_name(spec.account_domain, fqdn, dns_domain) if spec.account_domain else "local"
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


@dataclass(frozen=True)
class ParseContext:
    """Everything a server row needs beyond its own cells, so the CSV and inline (--server) paths cannot diverge."""
    spec: StrongAccountTemplate | None = None
    ssh_username_default: str = ""
    policy_name_template: str = "{fqdn}"
    group_template: str = ""
    target_set_scope: str = "server"
    domains: dict[str, DomainRow] = field(default_factory=dict)

    def domain_row(self, dns_domain: str) -> DomainRow | None:
        return self.domains.get((dns_domain or "").lower())


def _resolve_groups(cell: str | None, fqdn: str, dns_domain: str, entry: DomainRow | None, ctx: ParseContext,
                    where: str, problems: list[str]) -> tuple[str, ...]:
    """The `group` cell, else the domain's group_template, else [defaults] group_template."""
    groups = _split_list(cell)
    if groups:
        return groups
    template = (entry.group_template if entry and entry.group_template else ctx.group_template)
    if not template:
        problems.append(f"{where}: group is required (separate several with '{LIST_SEPARATOR}'), or set "
                        "[defaults] group_template (or a group_template for this domain in domains.csv) to derive it "
                        "from the server name")
        return ()
    try:
        rendered = _render_name(template, fqdn, dns_domain)
    except (KeyError, IndexError, ValueError) as exc:
        problems.append(f"{where}: group_template {template!r} is invalid: {exc}")
        return ()
    groups = _split_list(rendered)
    if not groups:
        problems.append(f"{where}: group_template {template!r} rendered an empty group name")
    return groups


def _resolve_strong_account(cell: str | None, domain_joined: bool, fqdn: str, dns_domain: str,
                            entry: DomainRow | None, ctx: ParseContext, where: str, problems: list[str],
                            warnings: list[str], templated: dict[str, StrongAccountRow]) -> tuple[str | None, bool]:
    """The `strong_account` cell, else the domain's shared account, else the per-host template.

    Returns (name, from_domains_csv). The second value decides target-set width: only a server that took its
    account from domains.csv can share that domain's target set.
    """
    if cell:
        return cell, False
    if domain_joined and entry is not None and entry.strong_account:
        return entry.strong_account, True
    if ctx.spec:
        account = _templated_account(ctx.spec, fqdn, dns_domain, warnings, where)
        templated.setdefault(account.name, account)
        return account.name, False
    # A workgroup server can never take its domain's account, so don't send the operator to domains.csv for one.
    via_domain = ("" if not domain_joined else
                  f"add {dns_domain!r} to domains.csv with its domain strong account, ")
    problems.append(f"{where}: strong_account is required -- name it in the row, {via_domain}"
                    "or set [defaults] strong_account_template in config.toml")
    return None, False


def _resolve_target_set(from_domains_csv: bool, explicit_account: bool, domain_joined: bool, dns_domain: str,
                        entry: DomainRow | None, ctx: ParseContext, where: str,
                        problems: list[str]) -> tuple[str, str]:
    """(target_set_name, target_set_type). "" means the server's own FQDN, i.e. a target set of its own."""
    if ctx.target_set_scope == "server":
        return "", DEFAULT_TARGET_SET_TYPE
    if from_domains_csv and entry is not None:
        return entry.target_set_name, entry.target_set_type
    if ctx.target_set_scope == "domain" and domain_joined and not explicit_account:
        problems.append(f"{where}: [defaults] target_set_scope = \"domain\" but domain {dns_domain!r} has no row in "
                        "domains.csv with a strong_account; add one, name a strong_account on this row, or use "
                        "target_set_scope = \"auto\"")
    return "", DEFAULT_TARGET_SET_TYPE


def _build_server_row(c: dict[str, str], where: str, line: int, ctx: ParseContext, problems: list[str],
                      warnings: list[str], templated: dict[str, StrongAccountRow]) -> ServerRow:
    """One servers.csv row (or one --server invocation) -> a validated ServerRow. Problems are collected, not raised."""
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
    domain_joined = _parse_bool(c.get("domain_joined"), True)
    if domain_joined is None:
        problems.append(f"{where}: domain_joined must be yes or no, got {c['domain_joined']!r}")
        domain_joined = True
    entry = ctx.domain_row(dns_domain)

    explicit_account = bool(c.get("strong_account"))
    strong_account: str | None = c.get("strong_account") or None
    from_domains_csv = False
    ssh_username: str | None = c.get("ssh_username") or None
    assign_groups = _split_list(c.get("assign_groups")) or None
    target_set_name, target_set_type = "", DEFAULT_TARGET_SET_TYPE
    if protocol == "ssh":
        if strong_account:
            warnings.append(f"{where}: strong_account {strong_account!r} ignored for protocol=ssh (Linux ZSP uses an SSH certificate)")
            strong_account = None
        if assign_groups:
            warnings.append(f"{where}: assign_groups ignored for protocol=ssh")
            assign_groups = None
        if not ssh_username and not ctx.ssh_username_default:
            problems.append(f"{where}: protocol=ssh needs ssh_username (or set defaults.ssh_username in config.toml)")
    else:
        if ssh_username:
            warnings.append(f"{where}: ssh_username ignored for protocol=rdp")
            ssh_username = None
        strong_account, from_domains_csv = _resolve_strong_account(
            strong_account, domain_joined, fqdn, dns_domain, entry, ctx, where, problems, warnings, templated)
        target_set_name, target_set_type = _resolve_target_set(
            from_domains_csv, explicit_account, domain_joined, dns_domain, entry, ctx, where, problems)
    groups = _resolve_groups(c.get("group"), fqdn, dns_domain, entry, ctx, where, problems)

    policy_name = c.get("policy_name") or None
    policy_suffix = c.get("policy_suffix") or None
    if policy_name and policy_suffix:
        warnings.append(f"{where}: policy_suffix {policy_suffix!r} ignored because policy_name is set")
        policy_suffix = None
    return ServerRow(
        fqdn=fqdn, strong_account=strong_account, groups=groups,
        policy_name=policy_name, assign_groups=assign_groups,
        domain=domain, description=c.get("description") or None, line=line,
        protocol=protocol, ssh_username=ssh_username, policy_suffix=policy_suffix, domain_joined=domain_joined,
        target_set_name=target_set_name, target_set_type=target_set_type,
    )


def _check_policy_name(row: ServerRow, where: str, ctx: ParseContext, seen: dict[str, tuple[str, int]],
                       problems: list[str]) -> None:
    """The effective policy name must render, fit, and be unique across the whole file."""
    try:
        effective = effective_policy_name(ctx.policy_name_template, row.fqdn, row.dns_domain, row.policy_name,
                                          row.policy_suffix)
    except (KeyError, IndexError, ValueError) as exc:
        problems.append(f"{where}: policy_name_template {ctx.policy_name_template!r} is invalid: {exc}")
        effective = f"{row.fqdn}#{row.line}"
    if not 1 <= len(effective) <= MAX_POLICY_NAME:
        problems.append(f"{where}: policy name {effective!r} must be 1..{MAX_POLICY_NAME} characters")
    if effective in seen:
        other_fqdn, other_line = seen[effective]
        hint = ("set policy_suffix (or policy_name) per row" if other_fqdn == row.fqdn
                else "use {fqdn} in policy_name_template or set policy_name per row")
        problems.append(f"{where}: policy name {effective!r} ({row.fqdn}) collides with line {other_line} ({other_fqdn}); {hint}")
    else:
        seen[effective] = (row.fqdn, row.line)


def _check_row_agreement(row: ServerRow, where: str, first_row: dict[str, ServerRow], problems: list[str]) -> None:
    """Every row of one server must describe the same server."""
    first = first_row.get(row.fqdn)
    if first is None:
        first_row[row.fqdn] = row
        return
    for label, mine, theirs in (("strong_account", row.strong_account, first.strong_account),
                                ("domain", row.domain, first.domain), ("protocol", row.protocol, first.protocol),
                                ("target set", row.target_set_key, first.target_set_key)):
        if mine != theirs:
            problems.append(f"{where}: {label} {mine!r} conflicts with line {first.line} ({theirs!r}) for the same fqdn {row.fqdn}")


def _parse_servers(path: Path, problems: list[str], warnings: list[str],
                   ctx: ParseContext) -> tuple[list[ServerRow], dict[str, StrongAccountRow]]:
    rows = read_csv(path, ("fqdn",),
                    ("strong_account", "group", "policy_name", "policy_suffix", "assign_groups", "domain",
                     "description", "protocol", "ssh_username", "domain_joined"))
    servers: list[ServerRow] = []
    templated: dict[str, StrongAccountRow] = {}
    first_row: dict[str, ServerRow] = {}
    policy_names: dict[str, tuple[str, int]] = {}
    for line, c in rows:
        where = f"{path.name}:{line}"
        row = _build_server_row(c, where, line, ctx, problems, warnings, templated)
        _check_policy_name(row, where, ctx, policy_names, problems)
        _check_row_agreement(row, where, first_row, problems)
        servers.append(row)
    return servers, templated


def _parse_strong_accounts(path: Path, problems: list[str]) -> dict[str, StrongAccountRow]:
    """Optional: accounts may instead come from domains.csv or the [defaults] template."""
    if not path.is_file():
        return {}
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


def _parse_domains(path: Path, problems: list[str]) -> dict[str, DomainRow]:
    """domains.csv (optional): one row per AD domain -- its shared strong account, target set and group convention."""
    if not path.is_file():
        return {}
    rows = read_csv(path, ("domain",), ("strong_account", "target_set", "target_set_type", "group_template", "description"))
    domains: dict[str, DomainRow] = {}
    for line, c in rows:
        where = f"{path.name}:{line}"
        domain = c["domain"].lower().rstrip(".")
        if not domain:
            problems.append(f"{where}: domain is required")
            continue
        if not all(re.fullmatch(FQDN_LABEL, label) for label in domain.split(".")):
            problems.append(f"{where}: domain {c['domain']!r} is not a valid DNS name")
            continue
        if domain in domains:
            problems.append(f"{where}: duplicate domain {domain!r} (also line {domains[domain].line})")
            continue
        raw_type = (c.get("target_set_type") or "domain").lower()
        if raw_type not in TARGET_SET_TYPES:
            problems.append(f"{where}: target_set_type must be one of {', '.join(TARGET_SET_TYPES.values())}, "
                            f"got {c['target_set_type']!r}")
            raw_type = "domain"
        elif raw_type == "target" and not c.get("target_set"):
            # "Target" scopes a set to one machine, so a set named after the domain would match nothing and the
            # failure would only surface at the first user login.
            problems.append(f"{where}: target_set_type = Target names a single machine, but this row's target set is "
                            f"the domain {domain!r}; use Domain (or Suffix), or name a specific target_set")
            raw_type = "domain"
        group_template = c.get("group_template") or None
        if group_template:
            try:
                _render_name(group_template, f"host.{domain}", domain)
            except (KeyError, IndexError, ValueError) as exc:
                problems.append(f"{where}: group_template {group_template!r} is invalid: {exc}")
                group_template = None
        domains[domain] = DomainRow(
            domain=domain, strong_account=c.get("strong_account") or None, target_set=c.get("target_set") or None,
            target_set_type=TARGET_SET_TYPES[raw_type], group_template=group_template, line=line)
    _check_shared_target_sets(path, domains, problems)
    return domains


def _check_target_set_accounts(servers: list[ServerRow], origin: str, problems: list[str]) -> None:
    """Every server sharing a target set must share its strong account -- a target set holds exactly one secret_id.

    This is the invariant `Reconciler._rows_by_target_set` relies on when it lets the first row of a group decide
    the whole group's account, so it is checked over the rows themselves: a domains.csv `target_set` naming one
    server's FQDN would otherwise collide with that server's own set without any of the domains.csv checks firing.
    """
    first: dict[str, ServerRow] = {}
    for server in servers:
        if server.is_ssh or not server.strong_account:
            continue
        owner = first.setdefault(server.target_set_key, server)
        if owner is not server and owner.strong_account != server.strong_account:
            problems.append(
                f"{origin}:{server.line}: {server.fqdn} shares target set {server.target_set_key!r} with "
                f"{owner.fqdn} (line {owner.line}) but uses strong account {server.strong_account!r} instead of "
                f"{owner.strong_account!r}; a target set holds exactly one strong account")


def _check_shared_target_sets(path: Path, domains: dict[str, DomainRow], problems: list[str]) -> None:
    """Two domains may point at one target set, but only if they also share its strong account -- a target set
    carries exactly one secret_id, so disagreeing rows would silently fight over it."""
    by_set: dict[str, DomainRow] = {}
    for row in domains.values():
        first = by_set.setdefault(row.target_set_name.lower(), row)
        if first is not row and first.strong_account != row.strong_account:
            problems.append(
                f"{path.name}:{row.line}: domain {row.domain!r} shares target set {row.target_set_name!r} with "
                f"{first.domain!r} (line {first.line}) but names strong account {row.strong_account!r} instead of "
                f"{first.strong_account!r}; a target set can only hold one strong account")


def _domain_strong_accounts(domains: dict[str, DomainRow]) -> dict[str, StrongAccountRow]:
    """Strong accounts named only in domains.csv: pre-existing domain accounts, onboarded by hand into SIA.

    They are type=existing, so the tool only looks them up -- a missing one fails the run with a clear message
    rather than being created behind the operator's back.
    """
    accounts: dict[str, StrongAccountRow] = {}
    for row in domains.values():
        if row.strong_account and row.strong_account not in accounts:
            accounts[row.strong_account] = StrongAccountRow(
                name=row.strong_account, type="existing", safe=None, account_name=None, username=None,
                account_domain=row.domain, password_env=None, line=row.line, address=None)
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


def _parse_context(input_dir: Path, problems: list[str], *, strong_account_template: str | StrongAccountTemplate,
                   ssh_username_default: str, policy_name_template: str, group_template: str,
                   target_set_scope: str) -> ParseContext:
    if isinstance(strong_account_template, StrongAccountTemplate):
        spec: StrongAccountTemplate | None = strong_account_template
    else:
        spec = StrongAccountTemplate(name=strong_account_template) if strong_account_template else None
    return ParseContext(spec=spec, ssh_username_default=ssh_username_default,
                        policy_name_template=policy_name_template, group_template=group_template,
                        target_set_scope=target_set_scope,
                        domains=_parse_domains(input_dir / "domains.csv", problems))


def _finish(servers: list[ServerRow], templated: dict[str, StrongAccountRow], ctx: ParseContext, input_dir: Path,
            problems: list[str], warnings: list[str], origin: str) -> Inputs:
    """Merge the account sources, check every referenced account is declared, and raise all problems at once."""
    accounts = _parse_strong_accounts(input_dir / "strong_accounts.csv", problems)
    groups = _parse_groups(input_dir / "groups.csv", problems)
    # Explicit strong_accounts.csv rows win over accounts derived from domains.csv or a template.
    for source in (_domain_strong_accounts(ctx.domains), templated):
        for name, account in sorted(source.items()):
            accounts.setdefault(name, account)
    for server in servers:
        if server.strong_account and server.strong_account not in accounts:
            problems.append(
                f"{origin}:{server.line}: strong_account {server.strong_account!r} is not defined in strong_accounts.csv "
                f"or domains.csv (add a row with type=existing if it already exists in SIA)")
    _check_target_set_accounts(servers, origin, problems)
    if problems:
        raise InputError("\n".join(problems))
    return Inputs(servers=tuple(servers), strong_accounts=accounts, groups=groups, warnings=tuple(warnings),
                  domains=ctx.domains)


def load_inputs(input_dir: str | Path, *, strong_account_template: str | StrongAccountTemplate = "",
                ssh_username_default: str = "", policy_name_template: str = "{fqdn}", group_template: str = "",
                target_set_scope: str = "server") -> Inputs:
    """Load and validate the CSVs. Only servers.csv is required; domains, strong_accounts and groups are optional.

    strong_account_template: used when an rdp row leaves strong_account blank and its domain is not in domains.csv.
    A plain string (e.g. "ADM-{hostname}") means "look the rendered name up in SIA as an existing strong account";
    a StrongAccountTemplate can also describe a Vault reference or stored credentials to create per server. Names
    typed explicitly in servers.csv must be declared in strong_accounts.csv or domains.csv (typo protection);
    explicit rows win over derived ones.
    policy_name_template: needed here so duplicate policy names are rejected before any tenant contact.
    """
    input_dir = Path(input_dir)
    problems: list[str] = []
    warnings: list[str] = []
    if not (input_dir / "servers.csv").is_file():
        raise InputError(f"{input_dir / 'servers.csv'}: file not found")
    ctx = _parse_context(input_dir, problems, strong_account_template=strong_account_template,
                         ssh_username_default=ssh_username_default, policy_name_template=policy_name_template,
                         group_template=group_template, target_set_scope=target_set_scope)
    servers, templated = _parse_servers(input_dir / "servers.csv", problems, warnings, ctx)
    return _finish(servers, templated, ctx, input_dir, problems, warnings, "servers.csv")


def inline_inputs(input_dir: str | Path, servers: list[dict[str, str]], *,
                  strong_account_template: str | StrongAccountTemplate = "", ssh_username_default: str = "",
                  policy_name_template: str = "{fqdn}", group_template: str = "",
                  target_set_scope: str = "server") -> Inputs:
    """Servers given on the command line (--server) instead of servers.csv, validated by the same code path.

    domains.csv, strong_accounts.csv and groups.csv are still read from `input_dir` when present, so a single-server
    run from Ansible resolves its group and strong account exactly as a bulk run would.
    """
    input_dir = Path(input_dir)
    problems: list[str] = []
    warnings: list[str] = []
    ctx = _parse_context(input_dir, problems, strong_account_template=strong_account_template,
                         ssh_username_default=ssh_username_default, policy_name_template=policy_name_template,
                         group_template=group_template, target_set_scope=target_set_scope)
    rows: list[ServerRow] = []
    templated: dict[str, StrongAccountRow] = {}
    policy_names: dict[str, tuple[str, int]] = {}
    first_row: dict[str, ServerRow] = {}
    for line, cells in enumerate(servers, start=1):
        where = f"--server {cells.get('fqdn', '?')}"
        row = _build_server_row(cells, where, line, ctx, problems, warnings, templated)
        _check_policy_name(row, where, ctx, policy_names, problems)
        _check_row_agreement(row, where, first_row, problems)
        rows.append(row)
    return _finish(rows, templated, ctx, input_dir, problems, warnings, "--server")
