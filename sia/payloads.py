"""Pure functions that build API payloads. No I/O here so everything is unit-testable offline.

Shapes follow the documented Access Control Policies (UAP) API, the SIA strong-account and target-set APIs, and
CyberArk's official SDKs (ark-sdk-python, idsec-sdk-golang); the PVWA payload follows the PAM Self-Hosted REST API.
"""
from __future__ import annotations

import copy
import html
from typing import Any

from .config import Defaults
from .inputs import ServerRow, StrongAccountRow, effective_policy_name

TARGET_SET_TYPE_TARGET = "Target"
MAX_POLICY_TAGS = 20
APPROVED_CONDITION_KEYS = ("accessWindow", "maxSessionDuration", "idleTime", "accessApproval")
APPROVED_RDP_KEYS = ("localEphemeralUser", "domainEphemeralUser")


def split_fqdn(fqdn: str) -> tuple[str, str]:
    """'web01.corp.example.com' -> ('web01', 'corp.example.com')."""
    host, _, domain = fqdn.partition(".")
    return host, domain


def render(template: str, server: ServerRow) -> str:
    try:
        return template.format(hostname=server.hostname, fqdn=server.fqdn, domain=server.dns_domain,
                               protocol=server.protocol.upper())
    except (KeyError, IndexError, ValueError) as exc:
        raise ValueError(f"template {template!r} is invalid: {exc}; use {{hostname}}, {{fqdn}}, {{domain}}, {{protocol}}") from exc


def policy_name_for(server: ServerRow, defaults: Defaults) -> str:
    try:
        return effective_policy_name(defaults.policy_name_template, server.fqdn, server.dns_domain,
                                     server.policy_name, server.policy_suffix)
    except (KeyError, IndexError, ValueError) as exc:
        raise ValueError(f"template {defaults.policy_name_template!r} is invalid: {exc}; use {{hostname}}, {{fqdn}}, {{domain}}") from exc


def description_for(server: ServerRow, defaults: Defaults) -> str:
    return server.description or render(defaults.description_template, server)


# --- ownership markers ------------------------------------------------------------------------

def ownership_marker(owner_tag: str) -> str:
    return f"managed-by:{owner_tag}"


def is_owned_policy(policy: dict[str, Any], owner_tag: str) -> bool:
    tags = (policy.get("metadata") or {}).get("policyTags") or []
    return owner_tag in tags


def is_owned_target_set(target_set: dict[str, Any], owner_tag: str) -> bool:
    return ownership_marker(owner_tag) in str(target_set.get("description") or "")


# --- strong accounts (SIA VM secrets) -------------------------------------------------------------

def build_secret_payload(account: StrongAccountRow, password: str | None = None) -> dict[str, Any]:
    """POST /api/secrets[/public/v1] body. Vault-referenced accounts (PAM Self-Hosted or Privilege Cloud) use
    PCloudAccount and are named <account_name>_<safe>, the name the platform generates (a custom name is rejected)."""
    if account.type == "vault":
        secret_data: dict[str, Any] = {"safe": account.safe, "account_name": account.account_name}
    elif account.type == "credentials":
        if not password:
            raise ValueError(f"strong account {account.name!r} needs a password (env var {account.password_env})")
        secret_data = {"username": account.username, "password": password}
    else:
        raise ValueError(f"strong account {account.name!r} has type={account.type}; only vault/credentials can be created")
    return {
        "secret_name": account.sia_name,
        "secret_type": account.secret_type,
        "is_active": True,
        "secret": {"secret_data": secret_data, "tenant_encrypted": False},
        "secret_details": {"account_domain": account.account_domain or "local", "ephemeral_domain_user_data": {}},
    }


# --- Vault onboarding (PAM Self-Hosted PVWA REST API) ----------------------------------------------

def build_vault_account(account: StrongAccountRow, password: str, *, platform_id: str, address: str,
                        cpm_managed: bool = True) -> dict[str, Any]:
    """POST /PasswordVault/API/Accounts body for a type=vault strong account that is not in the Vault yet.

    `name` is set explicitly to the templated account name so SIA's reference (<account_name>_<safe>) matches.
    """
    if account.type != "vault":
        raise ValueError(f"strong account {account.name!r} has type={account.type}; only vault accounts are onboarded")
    if not account.username:
        raise ValueError(f"strong account {account.name!r} needs a username to be onboarded into the Vault")
    if not password:
        raise ValueError(f"strong account {account.name!r} needs its current password to be onboarded into the Vault")
    return {
        "name": account.account_name,
        "address": address,
        "userName": account.username,
        "platformId": platform_id,
        "safeName": account.safe,
        "secretType": "password",
        "secret": password,
        "secretManagement": {"automaticManagementEnabled": bool(cpm_managed)},
    }


# --- target sets --------------------------------------------------------------------------------

def target_set_description(server: ServerRow, owner_tag: str) -> str:
    base = server.description or f"RDP ZSP target {server.fqdn} via {server.strong_account}"
    marker = ownership_marker(owner_tag)
    return base if marker in base else f"{base} [{marker}]"


def build_target_set(server: ServerRow, secret_id: str, secret_type: str, defaults: Defaults) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": server.fqdn,
        "type": TARGET_SET_TYPE_TARGET,
        "secret_type": secret_type,
        "secret_id": secret_id,
        "description": target_set_description(server, defaults.owner_tag),
        "enable_certificate_validation": bool(defaults.target_set_cert_validation),
    }
    if defaults.provision_format:
        payload["provision_format"] = defaults.provision_format
    return payload


def build_bulk_target_sets(items: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """{secret_id: [target_set, ...]} -> target_sets_mapping list for POST .../targetsets/bulk."""
    return [{"strong_account_id": secret_id, "target_sets": sets} for secret_id, sets in items.items() if sets]


def build_target_set_update(server: ServerRow, secret_id: str, secret_type: str, defaults: Defaults) -> dict[str, Any]:
    """PUT .../targetsets/{name} body to re-point a target set at another strong account (and mark it managed)."""
    return {"type": TARGET_SET_TYPE_TARGET, "secret_type": secret_type, "secret_id": secret_id,
            "description": target_set_description(server, defaults.owner_tag)}


# --- policies (UAP) -----------------------------------------------------------------------------

def build_fqdn_rule(server: ServerRow) -> dict[str, Any]:
    return {"operator": "EXACTLY", "computernamePattern": server.fqdn, "domain": server.dns_domain}


def build_principal(group_row: dict[str, Any]) -> dict[str, Any]:
    """Identity DirectoryServiceQuery group row -> UAP principal."""
    return {
        "id": group_row["InternalName"],
        "name": group_row.get("SystemName") or group_row.get("DisplayName"),
        "type": "GROUP",
        "sourceDirectoryId": group_row["DirectoryServiceUuid"],
        "sourceDirectoryName": group_row["ServiceInstanceLocalized"],
    }


def _default_conditions(defaults: Defaults) -> dict[str, Any]:
    window: dict[str, Any] = {"daysOfTheWeek": list(defaults.days_of_week)}
    if defaults.from_hour and defaults.to_hour:
        window["fromHour"] = defaults.from_hour
        window["toHour"] = defaults.to_hour
    return {"accessWindow": window, "maxSessionDuration": defaults.max_session_hours, "idleTime": defaults.idle_minutes}


def _ssh_username(server: ServerRow, defaults: Defaults) -> str:
    username = server.ssh_username or defaults.ssh_username
    if not username:
        raise ValueError(f"{server.fqdn}: protocol=ssh needs ssh_username (row) or defaults.ssh_username (config)")
    return username


def _default_behavior(server: ServerRow, defaults: Defaults) -> dict[str, Any]:
    if server.is_ssh:
        return {"connectAs": {"ssh": {"username": _ssh_username(server, defaults)}}}
    groups = list(server.assign_groups or defaults.assign_local_groups)
    return {"connectAs": {"rdp": {"localEphemeralUser": {
        "assignGroups": groups, "enableEphemeralUserReconnect": defaults.enable_reconnect}}}}


def validate_template(template: dict[str, Any]) -> list[str]:
    """Reasons a policy cannot serve as a template for generated Windows/RDP policies (empty list = OK)."""
    errors: list[str] = []
    entitlement = (template.get("metadata") or {}).get("policyEntitlement") or {}
    if entitlement.get("targetCategory") != "VM":
        errors.append(f"targetCategory is {entitlement.get('targetCategory')!r}, expected 'VM'")
    if entitlement.get("locationType") != "FQDN/IP":
        errors.append(f"locationType is {entitlement.get('locationType')!r}, expected 'FQDN/IP'")
    connect_as = (template.get("behavior") or {}).get("connectAs") or {}
    rdp = connect_as.get("rdp") or {}
    has_rdp = any(key in rdp for key in APPROVED_RDP_KEYS)
    has_ssh = bool((connect_as.get("ssh") or {}).get("username"))
    if not (has_rdp or has_ssh):
        errors.append("no connection profile (behavior.connectAs.rdp.localEphemeralUser/domainEphemeralUser or connectAs.ssh.username)")
    if not template.get("conditions"):
        errors.append("no conditions")
    return errors


def sanitize_template(template: dict[str, Any]) -> dict[str, Any]:
    """Copy only the approved fields of an existing policy: conditions, the RDP ephemeral-user profile, the SSH
    profile's username, timeZone, policyTags and delegationClassification. Names, ids, principals, targets and
    read-only metadata never carry over. build_policy() then uses the profile matching the row's protocol."""
    meta = template.get("metadata") or {}
    conditions = {k: copy.deepcopy(v) for k, v in (template.get("conditions") or {}).items() if k in APPROVED_CONDITION_KEYS}
    connect_as = (template.get("behavior") or {}).get("connectAs") or {}
    rdp = connect_as.get("rdp") or {}
    profiles: dict[str, Any] = {}
    rdp_profile = {k: copy.deepcopy(v) for k, v in rdp.items() if k in APPROVED_RDP_KEYS}
    if rdp_profile:
        profiles["rdp"] = rdp_profile
    ssh_username = (connect_as.get("ssh") or {}).get("username")
    if ssh_username:
        profiles["ssh"] = {"username": ssh_username}
    out: dict[str, Any] = {"metadata": {}, "conditions": conditions, "behavior": {"connectAs": profiles}}
    if meta.get("timeZone"):
        out["metadata"]["timeZone"] = meta["timeZone"]
    if meta.get("policyTags"):
        out["metadata"]["policyTags"] = list(meta["policyTags"])
    if template.get("delegationClassification"):
        out["delegationClassification"] = template["delegationClassification"]
    return out


def build_policy(server: ServerRow, principals: list[dict[str, Any]], defaults: Defaults,
                 template: dict[str, Any] | None = None) -> dict[str, Any]:
    """POST https://<sub>.uap.cyberark.cloud/api/policies body.

    With `template` (an existing policy as returned by GET), its approved fields are cloned (see sanitize_template)
    and the profile matching the row's protocol is used: rdp rows take the RDP ephemeral-user profile (a per-row
    assign_groups still overrides its local groups), ssh rows take the SSH profile (a per-row ssh_username still
    overrides the username). The owner tag is always added. metadata.status is read-only in the API and never sent.
    """
    if not principals:
        raise ValueError(f"policy for {server.fqdn} has no principals")
    template = sanitize_template(template) if template else None  # deep-copies: never mutates the caller's template
    tmeta = (template or {}).get("metadata") or {}
    conditions = (template or {}).get("conditions") or _default_conditions(defaults)
    if template:
        profiles = template["behavior"]["connectAs"]
        if server.is_ssh:
            if "ssh" not in profiles:
                raise ValueError(f"{server.fqdn}: template policy has no SSH profile but the row is protocol=ssh")
            username = server.ssh_username or profiles["ssh"]["username"]
            behavior: dict[str, Any] = {"connectAs": {"ssh": {"username": username}}}
        else:
            if "rdp" not in profiles:
                raise ValueError(f"{server.fqdn}: template policy has no RDP profile but the row is protocol=rdp")
            rdp = profiles["rdp"]
            if server.assign_groups:
                rdp = {key: ({**value, "assignGroups": list(server.assign_groups)} if key in APPROVED_RDP_KEYS else value)
                       for key, value in rdp.items()}
            behavior = {"connectAs": {"rdp": rdp}}
    else:
        behavior = _default_behavior(server, defaults)
    tags = list(tmeta.get("policyTags") or []) if template else list(defaults.policy_tags)
    if defaults.owner_tag not in tags:
        tags.append(defaults.owner_tag)
    if len(tags) > MAX_POLICY_TAGS:
        raise ValueError(f"policy for {server.fqdn} would carry {len(tags)} tags; the maximum is {MAX_POLICY_TAGS}")
    return {
        "metadata": {
            "name": policy_name_for(server, defaults),
            "description": description_for(server, defaults),
            "timeFrame": {},
            "policyEntitlement": {"targetCategory": "VM", "locationType": "FQDN/IP", "policyType": "Recurring"},
            "policyTags": tags,
            "timeZone": tmeta.get("timeZone") or defaults.time_zone,
        },
        "principals": principals,
        "delegationClassification": (template or {}).get("delegationClassification") or "Unrestricted",
        "conditions": conditions,
        "targets": {"FQDN/IP": {"fqdnRules": [build_fqdn_rule(server)]}},
        "behavior": behavior,
    }


def build_policy_update(existing: dict[str, Any], desired: dict[str, Any]) -> dict[str, Any]:
    """PUT /api/policies/{id} body: desired policy carrying the existing policyId."""
    return {**desired, "metadata": {**desired["metadata"], "policyId": existing["metadata"]["policyId"]}}


def policy_status(policy: dict[str, Any]) -> str:
    """The read-only status ('Active', 'Validating', 'Error', ...) or '' when the object does not carry it."""
    status = ((policy.get("metadata") or {}).get("status") or {})
    if isinstance(status, str):
        return status.capitalize()
    return str(status.get("status") or "").capitalize()


def policy_signature(policy: dict[str, Any]) -> dict[str, Any]:
    """Normalized view used for drift detection (principals + FQDN targets). Keys absent from a partial policy
    object (the list endpoint omits targets) are reported as None so callers can skip the comparison."""
    principals = None
    if policy.get("principals") is not None:
        principals = sorted(str(p.get("id")) for p in policy.get("principals") or [])
    rules_block = (policy.get("targets") or {}).get("FQDN/IP") if policy.get("targets") is not None else None
    normalized_rules = None
    if rules_block is not None:
        rules = rules_block.get("fqdnRules") or []
        normalized_rules = sorted(
            (str(r.get("operator", "")).upper(), str(r.get("computernamePattern", "")).lower(), str(r.get("domain") or "").lower())
            for r in rules
        )
    return {"principals": principals, "fqdn_rules": normalized_rules}


def exact_fqdns(policy: dict[str, Any]) -> list[str]:
    """FQDNs targeted by EXACTLY rules (lower-cased); used to recognise a managed policy that was renamed."""
    rules = (((policy.get("targets") or {}).get("FQDN/IP") or {}).get("fqdnRules")) or []
    return [str(r.get("computernamePattern", "")).lower() for r in rules
            if str(r.get("operator", "")).upper() == "EXACTLY" and r.get("computernamePattern")]


def names_match(a: str | None, b: str | None) -> bool:
    """Policy names may come back HTML-escaped (the SDK escapes them); compare tolerant of that."""
    if a is None or b is None:
        return False
    return html.unescape(a) == html.unescape(b)
