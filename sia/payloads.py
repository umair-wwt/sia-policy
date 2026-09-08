"""Pure functions that build API payloads. No I/O here so everything is unit-testable offline.

Shapes follow the documented Access Control Policies (UAP) API, the SIA strong-account and target-set APIs, and
CyberArk's official SDKs (ark-sdk-python, idsec-sdk-golang); the PVWA payload follows the PAM Self-Hosted REST API.
"""
from __future__ import annotations

import copy
import html
import math
from collections.abc import Mapping
from typing import Any

from .config import Defaults
from .inputs import ServerRow, StrongAccountRow, effective_policy_name

TARGET_SET_TYPE_TARGET = "Target"
MAX_POLICY_TAGS = 20
APPROVED_CONDITION_KEYS = ("accessWindow", "maxSessionDuration", "idleTime", "accessApproval")
# metadata.status is REQUIRED on create (ArkUAPMetadata.status has no default); the platform then owns the value,
# reporting Validating/Error/Warning back. Only these two are meaningful to ask for.
POLICY_STATUSES = ("Active", "Suspended")
APPROVED_RDP_KEYS = ("localEphemeralUser", "domainEphemeralUser")


def _finite_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _nonempty_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value)


def _rdp_profile_errors(profile: Mapping[str, Any], path: str) -> list[str]:
    errors: list[str] = []
    for key in ("assignGroups", "assignDomainGroups"):
        if key in profile and not _nonempty_string_list(profile[key]):
            errors.append(f"{path}.{key} must be a list of non-empty strings")
    if ("enableEphemeralUserReconnect" in profile
            and not isinstance(profile["enableEphemeralUserReconnect"], bool)):
        errors.append(f"{path}.enableEphemeralUserReconnect must be a boolean")
    return errors


def _condition_errors(conditions: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    window = conditions.get("accessWindow")
    if "accessWindow" in conditions:
        if not isinstance(window, Mapping):
            errors.append("conditions.accessWindow must be an object")
        else:
            days = window.get("daysOfTheWeek")
            if ("daysOfTheWeek" in window
                    and (not isinstance(days, list)
                         or any(not isinstance(day, int) or isinstance(day, bool) or day not in range(7)
                                for day in days))):
                errors.append("conditions.accessWindow.daysOfTheWeek must be a list of integers from 0 through 6")
            for key in ("fromHour", "toHour"):
                if key in window and not isinstance(window[key], str):
                    errors.append(f"conditions.accessWindow.{key} must be a string")
    for key in ("maxSessionDuration", "idleTime"):
        if key in conditions and not _finite_number(conditions[key]):
            errors.append(f"conditions.{key} must be a finite number")
    if "accessApproval" in conditions and not isinstance(conditions["accessApproval"], Mapping):
        errors.append("conditions.accessApproval must be an object")
    return errors


def _condition_is_safe(key: str, value: Any) -> bool:
    return not _condition_errors({key: value})


def split_fqdn(fqdn: str) -> tuple[str, str]:
    """'web01.corp.example.com' -> ('web01', 'corp.example.com')."""
    host, _, domain = fqdn.partition(".")
    return host, domain


def render(template: str, server: ServerRow) -> str:
    """Keep the placeholder set in step with config.TEMPLATE_PLACEHOLDERS and inputs._render_name."""
    try:
        return template.format(hostname=server.hostname, fqdn=server.fqdn, domain=server.dns_domain,
                               hostname_upper=server.hostname.upper(), hostname_lower=server.hostname.lower(),
                               domain_upper=server.dns_domain.upper(), protocol=server.protocol.upper())
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

def target_set_name_for(server: ServerRow) -> str:
    """The target set a server needs: its own FQDN, or a wider set (a Domain) shared with its whole domain."""
    return server.target_set_name or server.fqdn


def target_set_description(server: ServerRow, owner_tag: str) -> str:
    """A shared target set describes its scope, never one server -- `description` is a per-server column."""
    if server.shares_target_set:
        base = f"RDP ZSP {server.target_set_type.lower()} {target_set_name_for(server)} via {server.strong_account}"
    else:
        base = server.description or f"RDP ZSP target {server.fqdn} via {server.strong_account}"
    marker = ownership_marker(owner_tag)
    return base if marker in base else f"{base} [{marker}]"


def build_target_set(server: ServerRow, secret_id: str, secret_type: str, defaults: Defaults) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": target_set_name_for(server),
        "type": server.target_set_type or TARGET_SET_TYPE_TARGET,
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


def build_target_set_update(server: ServerRow, secret_id: str, secret_type: str, defaults: Defaults,
                            current: dict[str, Any] | None = None) -> dict[str, Any]:
    """PUT .../targetsets/{name} body to re-point a target set at another strong account (and mark it managed).

    A PUT replaces the object, so every field the tool has an opinion on is re-sent rather than left to fall back
    to the platform default. `provision_format` is the exception: an empty [defaults] provision_format means "SIA
    default naming", not "reset it", so a value already on the target set (`current`) is carried over.
    """
    payload: dict[str, Any] = {
        "type": server.target_set_type or TARGET_SET_TYPE_TARGET,
        "secret_type": secret_type,
        "secret_id": secret_id,
        "description": target_set_description(server, defaults.owner_tag),
        "enable_certificate_validation": bool(defaults.target_set_cert_validation),
    }
    existing = current or {}
    fmt = defaults.provision_format or existing.get("provision_format") or existing.get("provisionFormat") or ""
    if fmt:
        payload["provision_format"] = fmt
    return payload


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
    """Reasons a policy cannot safely serve as a template (empty list = OK).

    Tenant responses are external input.  Validate the shape of every subtree
    that :func:`sanitize_template` copies so a malformed response becomes one
    actionable template error instead of an ``AttributeError`` or a corrupt
    create payload.
    """
    errors: list[str] = []
    if not isinstance(template, Mapping):
        return ["template policy must be an object"]

    metadata = template.get("metadata")
    if not isinstance(metadata, Mapping):
        errors.append("metadata must be an object")
        metadata = {}
    entitlement = metadata.get("policyEntitlement")
    if not isinstance(entitlement, Mapping):
        errors.append("metadata.policyEntitlement must be an object")
    else:
        if entitlement.get("targetCategory") != "VM":
            errors.append(f"targetCategory is {entitlement.get('targetCategory')!r}, expected 'VM'")
        if entitlement.get("locationType") != "FQDN/IP":
            errors.append(f"locationType is {entitlement.get('locationType')!r}, expected 'FQDN/IP'")

    time_zone = metadata.get("timeZone")
    if "timeZone" in metadata and (not isinstance(time_zone, str) or not time_zone.strip()):
        errors.append("metadata.timeZone must be a non-empty string")
    tags = metadata.get("policyTags")
    if "policyTags" in metadata and not _nonempty_string_list(tags):
        errors.append("metadata.policyTags must be a list of non-empty strings")

    behavior = template.get("behavior")
    if not isinstance(behavior, Mapping):
        errors.append("behavior must be an object")
        behavior = {}
    connect_as = behavior.get("connectAs")
    if not isinstance(connect_as, Mapping):
        errors.append("behavior.connectAs must be an object")
        connect_as = {}

    rdp = connect_as.get("rdp")
    if rdp is not None and not isinstance(rdp, Mapping):
        errors.append("behavior.connectAs.rdp must be an object")
        rdp = {}
    elif rdp is None:
        rdp = {}
    has_rdp = False
    for key in APPROVED_RDP_KEYS:
        if key not in rdp:
            continue
        if not isinstance(rdp[key], Mapping):
            errors.append(f"behavior.connectAs.rdp.{key} must be an object")
        else:
            has_rdp = True
            errors.extend(_rdp_profile_errors(rdp[key], f"behavior.connectAs.rdp.{key}"))

    ssh = connect_as.get("ssh")
    if ssh is not None and not isinstance(ssh, Mapping):
        errors.append("behavior.connectAs.ssh must be an object")
        ssh = {}
    elif ssh is None:
        ssh = {}
    username = ssh.get("username")
    has_ssh = isinstance(username, str) and bool(username.strip())
    if username is not None and not has_ssh:
        errors.append("behavior.connectAs.ssh.username must be a non-empty string")
    if not (has_rdp or has_ssh):
        errors.append("no connection profile (behavior.connectAs.rdp.localEphemeralUser/domainEphemeralUser or connectAs.ssh.username)")

    conditions = template.get("conditions")
    if conditions is not None and not isinstance(conditions, Mapping):
        errors.append("conditions must be an object")
    elif not conditions:
        errors.append("no conditions")
    else:
        errors.extend(_condition_errors(conditions))

    delegation = template.get("delegationClassification")
    if ("delegationClassification" in template
            and (not isinstance(delegation, str) or not delegation.strip())):
        errors.append("delegationClassification must be a non-empty string")
    return errors


def sanitize_template(template: dict[str, Any]) -> dict[str, Any]:
    """Copy only the approved fields of an existing policy: conditions, the RDP ephemeral-user profile, the SSH
    profile's username, timeZone, policyTags and delegationClassification. Names, ids, principals, targets and
    read-only metadata never carry over. build_policy() then uses the profile matching the row's protocol."""
    source = template if isinstance(template, Mapping) else {}
    raw_meta = source.get("metadata")
    meta = raw_meta if isinstance(raw_meta, Mapping) else {}
    raw_conditions = source.get("conditions")
    conditions_source = raw_conditions if isinstance(raw_conditions, Mapping) else {}
    conditions = {k: copy.deepcopy(v) for k, v in conditions_source.items()
                  if k in APPROVED_CONDITION_KEYS and _condition_is_safe(k, v)}
    raw_behavior = source.get("behavior")
    behavior = raw_behavior if isinstance(raw_behavior, Mapping) else {}
    raw_connect_as = behavior.get("connectAs")
    connect_as = raw_connect_as if isinstance(raw_connect_as, Mapping) else {}
    raw_rdp = connect_as.get("rdp")
    rdp = raw_rdp if isinstance(raw_rdp, Mapping) else {}
    profiles: dict[str, Any] = {}
    rdp_profile = {
        k: copy.deepcopy(dict(v)) for k, v in rdp.items()
        if k in APPROVED_RDP_KEYS and isinstance(v, Mapping)
        and not _rdp_profile_errors(v, f"behavior.connectAs.rdp.{k}")
    }
    if rdp_profile:
        profiles["rdp"] = rdp_profile
    raw_ssh = connect_as.get("ssh")
    ssh = raw_ssh if isinstance(raw_ssh, Mapping) else {}
    ssh_username = ssh.get("username")
    if isinstance(ssh_username, str) and ssh_username.strip():
        profiles["ssh"] = {"username": ssh_username}
    out: dict[str, Any] = {"metadata": {}, "conditions": conditions, "behavior": {"connectAs": profiles}}
    time_zone = meta.get("timeZone")
    if isinstance(time_zone, str) and time_zone.strip():
        out["metadata"]["timeZone"] = time_zone
    tags = meta.get("policyTags")
    if isinstance(tags, list) and all(isinstance(tag, str) and tag.strip() for tag in tags):
        out["metadata"]["policyTags"] = list(tags)
    delegation = source.get("delegationClassification")
    if isinstance(delegation, str) and delegation.strip():
        out["delegationClassification"] = delegation
    return out


def build_policy(server: ServerRow, principals: list[dict[str, Any]], defaults: Defaults,
                 template: dict[str, Any] | None = None) -> dict[str, Any]:
    """POST https://<sub>.uap.cyberark.cloud/api/policies body.

    With `template` (an existing policy as returned by GET), its approved fields are cloned (see sanitize_template)
    and the profile matching the row's protocol is used: rdp rows take the RDP ephemeral-user profile (a per-row
    assign_groups still overrides its local groups), ssh rows take the SSH profile (a per-row ssh_username still
    overrides the username). The owner tag is always added.

    metadata.status is required by the API (CyberArk's own SDK sends it on every create); the platform validates the
    policy and then reports Validating/Active/Error back on read.
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
            "status": {"status": defaults.policy_status},
        },
        "principals": principals,
        "delegationClassification": (template or {}).get("delegationClassification") or "Unrestricted",
        "conditions": conditions,
        "targets": {"FQDN/IP": {"fqdnRules": [build_fqdn_rule(server)]}},
        "behavior": behavior,
    }


def build_policy_update(existing: dict[str, Any], desired: dict[str, Any], *, status: str | None = None) -> dict[str, Any]:
    """PUT /api/policies/{id} body: desired policy carrying the existing policyId.

    The existing status is carried over rather than reset to defaults.policy_status. A caller may explicitly request
    Active or Suspended with ``status``; this is the only way an update changes policy status.
    """
    meta = {**desired["metadata"], "policyId": existing["metadata"]["policyId"]}
    current = (existing.get("metadata") or {}).get("status")
    if status is not None:
        if status not in POLICY_STATUSES:
            raise ValueError(f"policy status must be one of {', '.join(POLICY_STATUSES)}")
        meta["status"] = {"status": status}
    elif current:
        meta["status"] = {"status": current} if isinstance(current, str) else current
    return {**desired, "metadata": meta}


def policy_status(policy: dict[str, Any]) -> str:
    """The read-only status ('Active', 'Validating', 'Error', ...) or '' when the object does not carry it."""
    status = ((policy.get("metadata") or {}).get("status") or {})
    if isinstance(status, str):
        return status.capitalize()
    return str(status.get("status") or "").capitalize()


def _normalized(value: Any, key: str = "") -> Any:
    """Stable nested representation for API fields whose dictionary ordering is irrelevant.

    ``null``, empty strings and empty containers are dropped: the API echoes unset optional fields that way
    (``accessWindow.fromHour``, ``timeFrame.fromTime``, ``connectAs.rdp.domainEphemeralUser`` ...) while the tool
    simply leaves them out, and both mean the same setting, not drift.
    """
    if isinstance(value, dict):
        entries = []
        for name, item in value.items():
            normalized = _normalized(item, str(name))
            if normalized is None or normalized == "" or normalized == ():
                continue
            entries.append((str(name), normalized))
        return tuple(sorted(entries))
    if isinstance(value, list):
        items = tuple(_normalized(item) for item in value)
        return tuple(sorted(set(items), key=repr)) if key in ("assignGroups", "daysOfTheWeek") else items
    return value


def policy_signature(policy: dict[str, Any]) -> dict[str, Any]:
    """Normalized view of every policy field this tool writes.

    Missing top-level fields are ``None`` so a list endpoint's partial object is never mistaken for drift. Callers
    performing a full ``--drift`` comparison fetch the complete object first.
    """
    meta = policy.get("metadata") or {}
    principals = None
    principal_details = None
    if policy.get("principals") is not None:
        principal_details = sorted(
            (str(p.get("id") or ""), str(p.get("type") or ""), str(p.get("sourceDirectoryId") or ""),
             str(p.get("sourceDirectoryName") or ""))
            for p in policy.get("principals") or []
        )
        principals = [item[0] for item in principal_details]
    rules_block = (policy.get("targets") or {}).get("FQDN/IP") if policy.get("targets") is not None else None
    normalized_rules = None
    if rules_block is not None:
        rules = rules_block.get("fqdnRules") or []
        normalized_rules = sorted(
            (str(r.get("operator", "")).upper(), str(r.get("computernamePattern", "")).lower(), str(r.get("domain") or "").lower())
            for r in rules
        )
    return {
        "name": html.unescape(str(meta.get("name") or "")) if "name" in meta else None,
        "description": str(meta.get("description") or "") if "description" in meta else None,
        "time_frame": _normalized(meta.get("timeFrame")) if "timeFrame" in meta else None,
        "entitlement": _normalized(meta.get("policyEntitlement")) if "policyEntitlement" in meta else None,
        "tags": tuple(sorted(str(tag) for tag in (meta.get("policyTags") or []))) if "policyTags" in meta else None,
        "time_zone": str(meta.get("timeZone") or "") if "timeZone" in meta else None,
        "principals": principals,
        "principal_details": principal_details,
        "delegation": str(policy.get("delegationClassification") or "") if "delegationClassification" in policy else None,
        "conditions": _normalized(policy.get("conditions")) if "conditions" in policy else None,
        "fqdn_rules": normalized_rules,
        "behavior": _normalized(policy.get("behavior")) if "behavior" in policy else None,
    }


def target_set_signature(target_set: dict[str, Any]) -> dict[str, Any]:
    """Normalized view of every target-set field this tool writes, tolerant of API key casing."""
    cert = target_set.get("enable_certificate_validation", target_set.get("enableCertificateValidation", False))
    provision = target_set.get("provision_format", target_set.get("provisionFormat", ""))
    return {
        "type": str(target_set.get("type") or "Target"),
        "secret_type": str(target_set.get("secret_type") or target_set.get("secretType") or ""),
        "secret_id": str(target_set.get("secret_id") or target_set.get("secretId") or ""),
        "description": str(target_set.get("description") or ""),
        "certificate_validation": bool(cert),
        "provision_format": str(provision or ""),
    }


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
