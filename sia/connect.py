"""The consuming side: what an end user needs to connect to an onboarded server through SIA.

Everything here is pure and secret-free. The formats follow the documented "Connect to a Windows target via an RDP
client" flow: RD Gateway = <subdomain>.rdp.<root domain>, gateway user `secureaccess@cyberark`, access token
`secureaccess`, and a zero-standing-privileges user name of the form
    secureaccess /i <user>@<login suffix> /s <subdomain> /a <target FQDN> [/d local] [/n <network>]
"""
from __future__ import annotations

import csv
import io
import hashlib
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable

from .config import Config, ConfigError, validate_connection_token, validate_dns_name
from .inputs import Inputs, ServerRow
from .artifacts import ArtifactWriteError, available_path, write_artifacts

GATEWAY_USER = "secureaccess@cyberark"
GATEWAY_TOKEN = "secureaccess"
PORTAL_PATH = "/dpa"
CONNECT_COLUMNS = ("fqdn", "hostname", "policy_name", "principals", "protocol", "strong_account", "secret_status",
                   "target_set_status", "policy_status", "policy_id", "portal_url", "gateway_host", "rdp_username", "rdp_file")
_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True)
class ConnectRow:
    fqdn: str
    hostname: str
    policy_name: str
    principals: str
    protocol: str
    strong_account: str
    secret_status: str
    target_set_status: str
    policy_status: str
    policy_id: str
    portal_url: str
    gateway_host: str
    rdp_username: str
    rdp_file: str

    def as_list(self) -> list[str]:
        return [getattr(self, column) for column in CONNECT_COLUMNS]


def gateway_host(cfg: Config) -> str:
    value = cfg.connect.gateway_host or f"{cfg.tenant.subdomain}.rdp.{cfg.tenant.root_domain}"
    return validate_dns_name("RDP gateway host", value)


def portal_url(cfg: Config) -> str:
    return cfg.tenant.portal_url + PORTAL_PATH


def login_suffix(cfg: Config, client_id: str = "") -> str:
    """The part after '@' in users' login names: [connect] login_suffix, else derived from the service user's id,
    else <subdomain>.<root domain>."""
    if cfg.connect.login_suffix:
        return validate_dns_name("RDP login suffix", cfg.connect.login_suffix)
    if "@" in client_id:
        return validate_dns_name("RDP login suffix derived from SIA_CLIENT_ID", client_id.split("@", 1)[1])
    return validate_dns_name("RDP login suffix", f"{cfg.tenant.subdomain}.{cfg.tenant.root_domain}")


def zsp_username(user: str, suffix: str, subdomain: str, fqdn: str, *, domain_joined: bool = True,
                 network: str = "") -> str:
    """The user name an RDP client sends for zero-standing-privileges access."""
    validate_connection_token("RDP login user", user)
    validate_dns_name("tenant subdomain", subdomain)
    if "." in subdomain:
        raise ConfigError("tenant subdomain must be one DNS label, not a domain name")
    validate_dns_name("RDP target FQDN", fqdn)
    if "@" in user:
        local, separator, user_suffix = user.rpartition("@")
        if not separator or not local:
            raise ConfigError("RDP login user must contain text before '@'")
        validate_dns_name("RDP login suffix", user_suffix)
        login = user
    else:
        validate_dns_name("RDP login suffix", suffix)
        login = f"{user}@{suffix}"
    parts = [GATEWAY_TOKEN, "/i", login, "/s", subdomain, "/a", fqdn]
    if not domain_joined:
        parts += ["/d", "local"]
    if network:
        validate_connection_token("RDP connector network", network)
        parts += ["/n", network]
    return " ".join(parts)


def rdp_file_text(fqdn: str, gateway: str, username: str) -> str:
    """A static .rdp file with the documented RD Gateway parameters (no token, no secrets: the client asks the user to
    authenticate). Windows expects CRLF line endings."""
    validate_dns_name("RDP target FQDN", fqdn)
    validate_dns_name("RDP gateway host", gateway)
    if not username or any(not char.isprintable() for char in username):
        raise ConfigError("RDP username must be non-empty printable text with no control characters")
    lines = [
        f"full address:s:{fqdn}",
        f"gatewayhostname:s:{gateway}",
        "gatewayusagemethod:i:1",
        "gatewaycredentialssource:i:5",
        "gatewayprofileusagemethod:i:1",
        f"gatewayaccesstoken:s:{GATEWAY_TOKEN}",
        f"username:s:{username}",
        "prompt for credentials:i:1",
        "authentication level:i:2",
    ]
    return "\r\n".join(lines) + "\r\n"


def rdp_file_name(server: ServerRow, policy_name: str, multiple: bool) -> str:
    base = server.hostname if not multiple else f"{server.hostname}-{policy_name}"
    base = _UNSAFE_FILENAME.sub("_", base).rstrip(". ")
    if base.split(".", 1)[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                                       *(f"LPT{i}" for i in range(1, 10))}:
        base = "_" + base
    if len(base) > 210:
        token = hashlib.sha256(f"{server.fqdn}|{policy_name}".encode()).hexdigest()[:12]
        base = base[:210] + "-" + token
    return base + ".rdp"


def build_rows(inputs: Inputs, cfg: Config, policy_names: dict[tuple[str, int], str], statuses: dict[str, Any] | None,
               *, user: str = "<user>", suffix: str = "", network: str | None = None, rdp_dir: Path | None = None) -> list[ConnectRow]:
    """One ConnectRow per servers.csv row. `policy_names` maps (fqdn, line) -> effective policy name;
    `statuses` maps (fqdn, policy_name) -> a ServerResult-like object (secret/target_set/policy outcomes) or is None."""
    gateway = gateway_host(cfg)
    portal = portal_url(cfg)
    net = cfg.connect.network if network is None else network
    # Treat callers such as the CLI as untrusted boundaries too.  Validate even
    # for an all-SSH input so a bad option never appears to have been accepted.
    validate_connection_token("RDP login user", user)
    validate_connection_token("RDP connector network", net, allow_empty=True)
    counts: dict[str, int] = {}
    for server in inputs.servers:
        counts[server.fqdn] = counts.get(server.fqdn, 0) + 1
    rows: list[ConnectRow] = []
    for server in inputs.servers:
        policy_name = policy_names[(server.fqdn, server.line)]
        result = (statuses or {}).get((server.fqdn, policy_name))
        secret = target_set = policy = policy_id = ""
        if result is not None:
            secret, target_set, policy = result.secret.status, result.target_set.status, result.policy.status
            policy_id = result.policy.ref or ""
        username = "" if server.is_ssh else zsp_username(user, suffix, cfg.tenant.subdomain, server.fqdn,
                                                         domain_joined=server.domain_joined, network=net)
        rdp_file = ""
        if rdp_dir is not None and not server.is_ssh:
            rdp_file = str(rdp_dir / rdp_file_name(server, policy_name, counts[server.fqdn] > 1))
        rows.append(ConnectRow(
            fqdn=server.fqdn, hostname=server.hostname, policy_name=policy_name, principals=";".join(server.principals),
            protocol=server.protocol, strong_account=server.strong_account or "-", secret_status=secret,
            target_set_status=target_set, policy_status=policy, policy_id=policy_id, portal_url=portal,
            gateway_host=gateway, rdp_username=username, rdp_file=rdp_file))
    # Different DNS domains can have the same hostname, and filename sanitizing
    # can collapse distinct policy names. Disambiguate all colliding names.
    by_path: dict[str, list[int]] = {}
    for index, row in enumerate(rows):
        if row.rdp_file:
            by_path.setdefault(str(Path(row.rdp_file).resolve()).casefold(), []).append(index)
    for indices in by_path.values():
        if len(indices) > 1:
            for index in indices:
                row = rows[index]
                path = Path(row.rdp_file)
                token = hashlib.sha256(f"{row.fqdn}|{row.policy_name}".encode()).hexdigest()[:12]
                rows[index] = replace(row, rdp_file=str(path.with_name(f"{path.stem}-{token}{path.suffix}")))
    return rows


def _csv_bytes(rows: Iterable[ConnectRow]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(CONNECT_COLUMNS)
    for row in rows:
        writer.writerow(row.as_list())
    return stream.getvalue().encode("utf-8")


def write_connect_csv(rows: Iterable[ConnectRow], path: str | Path) -> Path:
    path = Path(path).expanduser()
    write_artifacts([(path, _csv_bytes(rows))])
    return path


def write_rdp_files(rows: Iterable[ConnectRow]) -> list[Path]:
    return write_artifacts(_rdp_payloads(rows))


def _rdp_payloads(rows: Iterable[ConnectRow]) -> list[tuple[Path, bytes]]:
    return [(Path(row.rdp_file), rdp_file_text(row.fqdn, row.gateway_host, row.rdp_username).encode("utf-8"))
            for row in rows if row.rdp_file]


def write_connection_outputs(rows: list[ConnectRow], path: str | Path, *, generated: bool = False,
                             generated_rdp: bool = False) -> tuple[Path, list[Path]]:
    """Stage the CSV and every RDP file before publishing any of them."""
    base = Path(path).expanduser()
    if generated_rdp:
        reserved = {str(base.resolve()).casefold()}
        for index, row in enumerate(rows):
            if row.rdp_file:
                destination = available_path(Path(row.rdp_file).expanduser(), reserved=reserved)
                reserved.add(str(destination.resolve()).casefold())
                rows[index] = replace(row, rdp_file=str(destination))
    csv_data, rdp = _csv_bytes(rows), _rdp_payloads(rows)
    for _ in range(100):
        destination = available_path(base) if generated else base
        try:
            exclusive = ([destination] if generated else []) + ([p for p, _ in rdp] if generated_rdp else [])
            written = write_artifacts([(destination, csv_data), *rdp], exclusive=exclusive)
        except ArtifactWriteError as exc:
            if generated and isinstance(exc.cause, FileExistsError) and not exc.completed_paths:
                continue
            raise
        return destination, written[1:]
    raise FileExistsError(f"Could not reserve a unique output beside {base}; try again.")
