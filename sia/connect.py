"""The consuming side: what an end user needs to connect to an onboarded server through SIA.

Everything here is pure and secret-free. The formats follow the documented "Connect to a Windows target via an RDP
client" flow: RD Gateway = <subdomain>.rdp.<root domain>, gateway user `secureaccess@cyberark`, access token
`secureaccess`, and a zero-standing-privileges user name of the form
    secureaccess /i <user>@<login suffix> /s <subdomain> /a <target FQDN> [/d local] [/n <network>]
"""
from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .config import Config
from .inputs import Inputs, ServerRow

GATEWAY_USER = "secureaccess@cyberark"
GATEWAY_TOKEN = "secureaccess"
PORTAL_PATH = "/dpa"
CONNECT_COLUMNS = ("fqdn", "hostname", "policy_name", "groups", "protocol", "strong_account", "secret_status",
                   "target_set_status", "policy_status", "policy_id", "portal_url", "gateway_host", "rdp_username", "rdp_file")
_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True)
class ConnectRow:
    fqdn: str
    hostname: str
    policy_name: str
    groups: str
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
    return cfg.connect.gateway_host or f"{cfg.tenant.subdomain}.rdp.{cfg.tenant.root_domain}"


def portal_url(cfg: Config) -> str:
    return cfg.tenant.portal_url + PORTAL_PATH


def login_suffix(cfg: Config, client_id: str = "") -> str:
    """The part after '@' in users' login names: [connect] login_suffix, else derived from the service user's id,
    else <subdomain>.<root domain>."""
    if cfg.connect.login_suffix:
        return cfg.connect.login_suffix
    if "@" in client_id:
        return client_id.split("@", 1)[1]
    return f"{cfg.tenant.subdomain}.{cfg.tenant.root_domain}"


def zsp_username(user: str, suffix: str, subdomain: str, fqdn: str, *, domain_joined: bool = True,
                 network: str = "") -> str:
    """The user name an RDP client sends for zero-standing-privileges access."""
    login = user if "@" in user else f"{user}@{suffix}"
    parts = [GATEWAY_TOKEN, "/i", login, "/s", subdomain, "/a", fqdn]
    if not domain_joined:
        parts += ["/d", "local"]
    if network:
        parts += ["/n", network]
    return " ".join(parts)


def rdp_file_text(fqdn: str, gateway: str, username: str) -> str:
    """A static .rdp file with the documented RD Gateway parameters (no token, no secrets: the client asks the user to
    authenticate). Windows expects CRLF line endings."""
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
    return _UNSAFE_FILENAME.sub("_", base) + ".rdp"


def build_rows(inputs: Inputs, cfg: Config, policy_names: dict[tuple[str, int], str], statuses: dict[str, Any] | None,
               *, user: str = "<user>", suffix: str = "", network: str | None = None, rdp_dir: Path | None = None) -> list[ConnectRow]:
    """One ConnectRow per servers.csv row. `policy_names` maps (fqdn, line) -> effective policy name;
    `statuses` maps (fqdn, policy_name) -> a ServerResult-like object (secret/target_set/policy outcomes) or is None."""
    gateway = gateway_host(cfg)
    portal = portal_url(cfg)
    net = cfg.connect.network if network is None else network
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
            fqdn=server.fqdn, hostname=server.hostname, policy_name=policy_name, groups=";".join(server.groups),
            protocol=server.protocol, strong_account=server.strong_account or "-", secret_status=secret,
            target_set_status=target_set, policy_status=policy, policy_id=policy_id, portal_url=portal,
            gateway_host=gateway, rdp_username=username, rdp_file=rdp_file))
    return rows


def write_connect_csv(rows: Iterable[ConnectRow], path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(CONNECT_COLUMNS)
        for row in rows:
            writer.writerow(row.as_list())
    return path


def write_rdp_files(rows: Iterable[ConnectRow]) -> list[Path]:
    written: list[Path] = []
    for row in rows:
        if not row.rdp_file:
            continue
        path = Path(row.rdp_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rdp_file_text(row.fqdn, row.gateway_host, row.rdp_username), encoding="utf-8", newline="")
        written.append(path)
    return written
