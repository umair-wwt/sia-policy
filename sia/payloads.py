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
# Policy-level session-setting overrides (rolling out per SIA tenant; absent from the SDK condition models). A tenant
# with the feature derives them from the request -- a policy that sends idleTime reads back overrideIdleTime: true,
# one that sends maxSessionDuration reads back overrideMaxSessionDuration: true, and with no recording setting sent
# overrideRecording: false -- so the tool never sends them (a tenant without the feature may reject unknown keys) and
# compares each against the setting it is derived from. Recognised on read only.
SESSION_OVERRIDE_FLAGS: dict[str, str | None] = {
    "overrideIdleTime": "idleTime", "overrideMaxSessionDuration": "maxSessionDuration", "overrideRecording": None}
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
    """Shape problems in a policy's conditions. ``null`` is how a GET echoes an unset optional field (``fromHour``,
    ``accessApproval`` ...), so it is never an error."""
    errors: list[str] = []
    window = conditions.get("accessWindow")
    if window is not None:
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
                if window.get(key) is not None and not isinstance(window[key], str):
                    errors.append(f"conditions.accessWindow.{key} must be a string")
    for key in ("maxSessionDuration", "idleTime"):
        if conditions.get(key) is not None and not _finite_number(conditions[key]):
            errors.append(f"conditions.{key} must be a finite number")
    if conditions.get("accessApproval") is not None and not isinstance(conditions["accessApproval"], Mapping):
        errors.append("conditions.accessApproval must be an object")
    return errors


def _approval_unset(value: Any) -> bool:
    """True when an ``accessApproval`` value means "no dual control": null, ``{}``, or ``required`` false/null with
    no approvers. A tenant with dual control enabled echoes ``{"required": false, "approvers": []}`` for a policy
    created without the key (CyberArk's SDKs leave the field out for that state), so it must equal absent."""
    if value is None:
        return True
    if not isinstance(value, Mapping):
        return False
    return not value.get("required") and not value.get("approvers")


def implied_session_overrides(conditions: Mapping[str, Any] | None) -> dict[str, bool]:
    """The session-override flags a tenant derives for a conditions block: true for a setting the block carries."""
    conditions = conditions if isinstance(conditions, Mapping) else {}
    return {flag: setting is not None and conditions.get(setting) not in (None, "")
            for flag, setting in SESSION_OVERRIDE_FLAGS.items()}


def _session_override_echo(flag: str, value: Any, conditions: Mapping[str, Any]) -> bool:
    """True when an ``override*`` flag carries the value the tenant derives from the same ``conditions`` (null, or
    ``overrideIdleTime``/``overrideMaxSessionDuration`` true exactly when ``idleTime``/``maxSessionDuration`` is set,
    ``overrideRecording`` false), so it equals absent like ``_approval_unset``. A flag that contradicts its sibling
    (``overrideIdleTime: false`` beside an idle time, ``overrideRecording: true``) means the policy is not applying
    what was sent and stays a difference."""
    if value is None:
        return True
    return isinstance(value, bool) and value == implied_session_overrides(conditions)[flag]


def _without_unset(value: Any) -> Any:
    """A copied condition without the null/empty members a GET echoes for unset settings (``fromHour: null``)."""
    if isinstance(value, Mapping):
        return {k: v for k, v in value.items() if v is not None and v != ""}
    return value


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
    """The owner tag is an identifier: a tenant that normalises tag casing must not make a policy look unmanaged."""
    tags = (policy.get("metadata") or {}).get("policyTags") or []
    return owner_tag.casefold() in {str(tag).casefold() for tag in tags}


def is_owned_target_set(target_set: dict[str, Any], owner_tag: str) -> bool:
    return ownership_marker(owner_tag).casefold() in str(target_set.get("description") or "").casefold()


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
        # CyberArk's strong-account API documents a local account as account_domain "local"; the input keeps the
        # operator's spelling (LOCAL, Local) so checkpoint fingerprints do not move with it.
        "secret_details": {"account_domain": "local" if account.is_local else account.account_domain,
                           "ephemeral_domain_user_data": {}},
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


def build_group_principal(group_row: dict[str, Any]) -> dict[str, Any]:
    """Identity DirectoryServiceQuery group row -> UAP principal (principal_type = group)."""
    return {
        "id": group_row["InternalName"],
        "name": group_row.get("SystemName") or group_row.get("DisplayName"),
        "type": "GROUP",
        "sourceDirectoryId": group_row["DirectoryServiceUuid"],
        "sourceDirectoryName": group_row["ServiceInstanceLocalized"],
    }


def build_role_principal(role_row: dict[str, Any], directory: dict[str, Any] | None = None) -> dict[str, Any]:
    """Identity DirectoryServiceQuery role row -> UAP principal (principal_type = role, the default).

    The Access Control Policies API marks sourceDirectoryName/sourceDirectoryId optional for ROLE principals (every
    Identity role lives in the CyberArk Cloud Directory). They are sent when that directory row is known, so the
    principal reads like one created in the portal, and ignored by policy_signature so a tenant that drops or
    rewrites them never shows drift.
    """
    principal: dict[str, Any] = {"id": role_row["_ID"], "name": role_row["Name"], "type": "ROLE"}
    if directory:
        uuid = directory.get("directoryServiceUuid") or directory.get("DirectoryServiceUuid")
        if uuid:
            principal["sourceDirectoryId"] = uuid
            principal["sourceDirectoryName"] = (directory.get("DisplayName") or directory.get("Name")
                                                or "CyberArk Cloud Directory")
    return principal


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
    read-only metadata never carry over. build_policy() then uses the profile matching the row's protocol.

    Null/empty echoes of unset settings are dropped rather than sent back, and ``accessApproval`` is copied only when
    it actually requires approval or names approvers: the "not required" form is what a dual-control tenant echoes
    for every policy, and a tenant without the feature may reject the key. The ``override*`` session flags a tenant
    adds are never copied either: the tenant derives them again from the settings that are sent."""
    source = template if isinstance(template, Mapping) else {}
    raw_meta = source.get("metadata")
    meta = raw_meta if isinstance(raw_meta, Mapping) else {}
    raw_conditions = source.get("conditions")
    conditions_source = raw_conditions if isinstance(raw_conditions, Mapping) else {}
    conditions = {k: _without_unset(copy.deepcopy(v)) for k, v in conditions_source.items()
                  if k in APPROVED_CONDITION_KEYS and v is not None and _condition_is_safe(k, v)
                  and not (k == "accessApproval" and _approval_unset(v))}
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


def build_policy_update(existing: dict[str, Any], desired: dict[str, Any], *, status: str | None = None,
                        preserve: bool = True) -> dict[str, Any]:
    """PUT /api/policies/{id} body: desired policy carrying the existing policyId.

    The existing status is carried over rather than reset to defaults.policy_status. A caller may explicitly request
    Active or Suspended with ``status``; this is the only way an update changes policy status. With ``preserve``
    (the default) leaves only the tenant carries are copied over too (see ``preserve_unmanaged``); strict tenants
    (``[defaults] readback_extra_keys = "fail"``) send the desired body as is.
    """
    meta = {**desired["metadata"], "policyId": existing["metadata"]["policyId"]}
    current = (existing.get("metadata") or {}).get("status")
    if status is not None:
        if status not in POLICY_STATUSES:
            raise ValueError(f"policy status must be one of {', '.join(POLICY_STATUSES)}")
        meta["status"] = {"status": status}
    elif current:
        meta["status"] = {"status": current} if isinstance(current, str) else current
    body = {**desired, "metadata": meta}
    return preserve_unmanaged(existing, body) if preserve else body


KNOWN_POLICY_STATUSES = ("Active", "Suspended", "Validating", "Error", "Warning", "Expired", "Inactive", "Draft")
_CANONICAL_STATUS = {name.casefold(): name for name in KNOWN_POLICY_STATUSES}


def policy_status(policy: dict[str, Any]) -> str:
    """The read-only status ('Active', 'Validating', 'Error', ...) or '' when the object does not carry it.

    Known statuses are matched case-insensitively and returned in their canonical spelling (``ACTIVE`` -> ``Active``);
    a status this tool does not know is returned as the tenant spells it, never reshaped.
    """
    status = ((policy.get("metadata") or {}).get("status") or {})
    raw = status if isinstance(status, str) else str(status.get("status") or "")
    return _CANONICAL_STATUS.get(raw.strip().casefold(), raw.strip())


ORDER_FREE_LISTS = ("assignGroups", "assignDomainGroups", "daysOfTheWeek", "approvers")   # sets the API may reorder


def _normalized(value: Any, key: str = "") -> Any:
    """Stable nested representation for API fields whose dictionary ordering is irrelevant.

    ``null``, empty strings and empty containers are dropped: the API echoes unset optional fields that way
    (``accessWindow.fromHour``, ``timeFrame.fromTime``, ``connectAs.rdp.domainEphemeralUser`` ...) while the tool
    simply leaves them out, and both mean the same setting, not drift. An ``accessApproval`` that only says "not
    required" is dropped for the same reason (see ``_approval_unset``); ``required: true`` or any approver counts.
    A session-override flag that carries the value the tenant derives from the setting beside it is dropped too
    (see ``SESSION_OVERRIDE_FLAGS``); one that contradicts that setting counts.
    """
    if isinstance(value, dict):
        entries = []
        for name, item in value.items():
            if str(name) == "accessApproval" and _approval_unset(item):
                continue
            if str(name) in SESSION_OVERRIDE_FLAGS and _session_override_echo(str(name), item, value):
                continue    # ``value`` is the conditions block itself: the setting the flag derives from is beside it
            normalized = _normalized(item, str(name))
            if normalized is None or normalized == "" or normalized == ():
                continue
            entries.append((str(name), normalized))
        return tuple(sorted(entries))
    if isinstance(value, list):
        items = tuple(_normalized(item) for item in value)
        return tuple(sorted(set(items), key=repr)) if key in ORDER_FREE_LISTS else items
    return value


def normalize_field(value: Any, key: str = "") -> Any:
    """One field normalized the way policy_signature() compares it (unset echoes dropped, order-free lists)."""
    return _normalized(value, key)


def plain(normalized: Any) -> Any:
    """Display form of a normalized value: ``((name, value), ...)`` back to a dict, other tuples to lists.

    For messages and diagnostics only; comparisons always use the normalized form itself.
    """
    if isinstance(normalized, (tuple, list)):
        if normalized and all(isinstance(e, tuple) and len(e) == 2 and isinstance(e[0], str) for e in normalized):
            return {name: plain(item) for name, item in normalized}
        return [plain(item) for item in normalized]
    return normalized


LeafDifference = tuple[str, Any, Any]      # (dotted path within the block, tenant value, requested value)

# --- the ownership boundary ----------------------------------------------------------------------
# The tool manages the leaves it writes and preserves the leaves it does not. A leaf only the tenant carries is a
# tenant-only difference (a note, never a failure) unless the tool's silence about it is deliberate:
MANAGED_ABSENT_LEAVES = frozenset({
    "conditions.accessWindow.fromHour", "conditions.accessWindow.toHour",       # no hours configured = full days
    "conditions.overrideIdleTime", "conditions.overrideMaxSessionDuration",     # derived from what the tool sent
})
MANAGED_ABSENT_PREFIXES = ("targets", "target_extras")    # an extra IP rule or target category grants access


def _managed_absent(full_path: str) -> bool:
    return full_path in MANAGED_ABSENT_LEAVES or any(
        full_path == prefix or full_path.startswith(prefix + ".") for prefix in MANAGED_ABSENT_PREFIXES)


def leaf_differences(current: Any, desired: Any, path: str = "") -> list[tuple[str, Any, Any]]:
    """``(dotted path, current, desired)`` for every leaf that differs between two plain() values.

    A side that lacks the key reports ``None`` -- unambiguous, because normalized values never contain null. An
    empty block (``plain(())`` is ``[]``) against a populated one is walked leaf by leaf, so every extra key is named.
    """
    if isinstance(current, dict) and desired == []:
        desired = {}
    elif isinstance(desired, dict) and current == []:
        current = {}
    if isinstance(current, dict) and isinstance(desired, dict):
        out: list[tuple[str, Any, Any]] = []
        for name in sorted(set(current) | set(desired)):
            child = f"{path}.{name}" if path else name
            out.extend(leaf_differences(current.get(name), desired.get(name), child))
        return out
    return [] if current == desired else [(path, current, desired)]


def partition_differences(key: str, current: Any, desired: Any) -> tuple[list[LeafDifference], list[LeafDifference]]:
    """Split one signature block's leaf differences into ``(managed, tenant_only)`` along the ownership boundary.

    ``managed``: a value the tool wrote that the tenant stored differently, a leaf the tenant dropped, a list-shaped
    block (principals, FQDN rules) or a leaf the tool is deliberately silent about (``MANAGED_ABSENT_LEAVES``,
    ``MANAGED_ABSENT_PREFIXES``). ``tenant_only``: a leaf only the tenant carries. The tool never wrote it, so it
    cannot be a failed write: it is reported as a note and ``build_policy_update`` preserves it. Policy tags compare
    as a set: a tag the tool writes that the tenant lacks is managed, a tag only the tenant carries is tenant-only.
    """
    if key == "tags":       # identifiers: a tenant that normalises their case has not changed them
        current_tags, desired_tags = [str(tag) for tag in current or []], [str(tag) for tag in desired or []]
        current_fold, desired_fold = {t.casefold() for t in current_tags}, {t.casefold() for t in desired_tags}
        missing = [tag for tag in desired_tags if tag.casefold() not in current_fold]
        extra = [tag for tag in current_tags if tag.casefold() not in desired_fold]
        return ([("", current_tags, desired_tags)] if missing else []), [(tag, tag, None) for tag in extra]
    managed: list[LeafDifference] = []
    tenant_only: list[LeafDifference] = []
    for path, old, new in leaf_differences(current, desired):
        if new is None and path and not _managed_absent(f"{key}.{path}"):
            tenant_only.append((path, old, new))
        else:
            managed.append((path, old, new))
    return managed, tenant_only


_PRESERVED_BLOCKS = {("conditions",): "conditions", ("behavior",): "behavior",
                     ("metadata", "timeFrame"): "time_frame", ("metadata", "policyEntitlement"): "entitlement"}


def _copy_missing_leaves(source: Mapping[str, Any], target: dict[str, Any], path: str) -> None:
    for name, value in source.items():
        full = f"{path}.{name}"
        if value is None or value == "" or value == [] or value == {} or _managed_absent(full):
            continue                    # null/empty echoes of unset settings; leaves the tool is silent about on purpose
        if (name == "accessApproval" and _approval_unset(value)) or (
                name in SESSION_OVERRIDE_FLAGS and _session_override_echo(name, value, source)):
            continue                    # the benign echoes policy_signature already treats as unset (see _normalized)
        if name not in target:
            target[name] = copy.deepcopy(value)
        elif isinstance(value, Mapping) and isinstance(target[name], dict):
            _copy_missing_leaves(value, target[name], full)


def preserve_unmanaged(existing: Mapping[str, Any], body: dict[str, Any]) -> dict[str, Any]:
    """``body`` with every leaf only the tenant carries copied over from ``existing``.

    A PUT replaces the object, so a leaf the tool does not write (a dual-control block, a session setting a newer
    tenant adds, a portal tag) would otherwise be reset by every update. Leaves the tool sets always win; leaves it
    is deliberately silent about (``MANAGED_ABSENT_LEAVES``) and null/empty echoes are not copied; tags are unioned.
    """
    out = copy.deepcopy(body)
    for block_path, key in _PRESERVED_BLOCKS.items():
        source: Any = existing
        target: Any = out
        for segment in block_path:
            source = source.get(segment) if isinstance(source, Mapping) else None
            target = target.get(segment) if isinstance(target, dict) else None
        if isinstance(source, Mapping) and isinstance(target, dict):
            _copy_missing_leaves(source, target, key)
    existing_tags = (existing.get("metadata") or {}).get("policyTags") if isinstance(existing, Mapping) else None
    if isinstance(existing_tags, list) and isinstance(out.get("metadata"), dict):
        tags = list(out["metadata"].get("policyTags") or [])
        known = {str(tag).casefold() for tag in tags}
        out["metadata"]["policyTags"] = tags + [tag for tag in existing_tags
                                                if isinstance(tag, str) and tag.casefold() not in known]
    return out


def _principal_detail(principal: dict[str, Any]) -> tuple[str, str, str, str]:
    """(id, TYPE, directory id, "") as compared for drift.

    Ids are GUIDs whose case carries no meaning, so they are casefolded. The type is upper-cased (tenants echo ``Role``
    as readily as ``ROLE``). For GROUP principals the source directory is compared by id only: its display name is a
    label the tenant may rewrite. For ROLE principals both directory fields are optional in the Access Control
    Policies API -- a tenant may omit, echo or rewrite them -- so they are left out of the comparison.
    """
    kind = str(principal.get("type") or "").upper()
    principal_id = str(principal.get("id") or "").casefold()
    if kind == "ROLE":
        return (principal_id, kind, "", "")
    return (principal_id, kind, str(principal.get("sourceDirectoryId") or "").casefold(), "")


def _rule_fqdn(pattern: Any, domain: Any) -> str:
    """The FQDN a rule targets, whether the tenant stores the full name or splits host and DNS domain."""
    host, dns = str(pattern or "").strip().lower(), str(domain or "").strip().lower()
    return host if "." in host or not dns else f"{host}.{dns}"


def policy_signature(policy: dict[str, Any]) -> dict[str, Any]:
    """Normalized view of every policy field this tool writes.

    Missing top-level fields are ``None`` so a list endpoint's partial object is never mistaken for drift. Callers
    performing a full ``--drift`` comparison fetch the complete object first.
    """
    meta = policy.get("metadata") or {}
    principals = None
    principal_details = None
    if policy.get("principals") is not None:
        principal_details = sorted(_principal_detail(p) for p in policy.get("principals") or [])
        principals = [item[0] for item in principal_details]
    targets = policy.get("targets")
    rules_block = (targets or {}).get("FQDN/IP") if targets is not None else None
    normalized_rules = None
    target_extras = None
    if isinstance(rules_block, Mapping):
        rules = rules_block.get("fqdnRules") or []
        normalized_rules = sorted(
            (str(r.get("operator", "")).upper(), _rule_fqdn(r.get("computernamePattern"), r.get("domain")),
             str(r.get("domain") or "").lower())
            for r in rules
        )
    if targets is not None:
        # Everything under targets other than the FQDN rules: IP rules, other location categories. The tool writes
        # none of it, but every target rule grants access, so it is compared and always managed (never a note).
        extras: dict[str, Any] = {category: block for category, block in (targets or {}).items() if category != "FQDN/IP"}
        if isinstance(rules_block, Mapping):
            rest = {name: value for name, value in rules_block.items() if name != "fqdnRules"}
            if rest:
                extras["FQDN/IP"] = rest
        target_extras = _normalized(extras)
    return {
        "name": html.unescape(str(meta.get("name") or "")) if "name" in meta else None,
        # CyberArk's SDK HTML-escapes both metadata strings before sending, so a tenant may echo either escaped
        "description": html.unescape(str(meta.get("description") or "")) if "description" in meta else None,
        # a GET may echo an unset time frame as null; the tool sends {} and both mean "no time frame"
        "time_frame": _normalized(meta.get("timeFrame") or {}) if "timeFrame" in meta else None,
        "entitlement": _normalized(meta.get("policyEntitlement")) if "policyEntitlement" in meta else None,
        "tags": tuple(sorted(str(tag) for tag in (meta.get("policyTags") or []))) if "policyTags" in meta else None,
        "time_zone": str(meta.get("timeZone") or "") if "timeZone" in meta else None,
        "principals": principals,
        "principal_details": principal_details,
        "delegation": str(policy.get("delegationClassification") or "") if "delegationClassification" in policy else None,
        "conditions": _normalized(policy.get("conditions")) if "conditions" in policy else None,
        "fqdn_rules": normalized_rules,
        "target_extras": target_extras,
        "behavior": _normalized(policy.get("behavior")) if "behavior" in policy else None,
    }


TARGET_SET_SECRET_KEYS = ("secret_id", "secretId", "strong_account_id", "strongAccountId")   # the API spells it three ways


def _present(mapping: Mapping[str, Any], *names: str) -> Any:
    """The first of ``names`` the mapping carries (even as null), or ``MISSING`` when it carries none."""
    for name in names:
        if name in mapping:
            return mapping[name]
    return MISSING


MISSING = object()


_PROBE_ROW = dict(fqdn="probe.fixture.example.com", strong_account="probe", principals=("probe",), policy_name=None,
                  assign_groups=None, domain=None, description=None, line=0)
_PROBE_PRINCIPAL = {"id": "probe", "name": "probe", "type": "ROLE"}
_BLOCK_PREFIXES = {"conditions": "conditions", "behavior": "behavior", "time_frame": "metadata.timeFrame",
                   "entitlement": "metadata.policyEntitlement", "target_extras": "targets"}


def tenant_only_fields(policy: dict[str, Any], defaults: Defaults) -> tuple[list[str], list[str]]:
    """``(unknown, recognised)`` fields a tenant's policy carries that this tool never writes, by JSON path.

    The reference is the body ``build_policy`` would send for a probe row under the current defaults; every leaf the
    policy carries beyond it is tenant-side. ``recognised`` are the echoes this tool already understands (a
    dual-control block, the derived session-override flags); ``unknown`` is everything else -- what a read-back would
    report as a note (or as drift, under ``targets``). Read-only: the preflight schema probe runs this on one existing
    policy so a tenant's extra fields are seen before the first bulk apply, not during it."""
    reference = build_policy(ServerRow(**_PROBE_ROW), [dict(_PROBE_PRINCIPAL)], defaults)
    tenant_sig, reference_sig = policy_signature(policy), policy_signature(reference)
    unknown: list[str] = []
    for key, prefix in _BLOCK_PREFIXES.items():
        tenant_plain, reference_plain = plain(tenant_sig.get(key)), plain(reference_sig.get(key))
        if not isinstance(tenant_plain, dict):
            continue
        for path, _old, new in leaf_differences(tenant_plain, reference_plain if isinstance(reference_plain, (dict, list)) else {}):
            if new is None and path:
                unknown.append(f"{prefix}.{path}")
    conditions = policy.get("conditions") if isinstance(policy.get("conditions"), Mapping) else {}
    recognised = sorted(f"conditions.{name}" for name in conditions
                        if (name in SESSION_OVERRIDE_FLAGS or name == "accessApproval") and f"conditions.{name}" not in unknown
                        and conditions.get(name) is not None)
    return sorted(unknown), recognised


TARGET_SET_KNOWN_KEYS = frozenset({
    "id", "targetSetId", "target_set_id", "name", "type", "description", "secret_type", "secretType",
    "enable_certificate_validation", "enableCertificateValidation", "provision_format", "provisionFormat",
    *TARGET_SET_SECRET_KEYS,
})
TARGET_SET_WRITTEN_FIELDS = {          # what build_target_set_update sends, by the names a listing may use
    "secret type": ("secret_type", "secretType"), "description": ("description",),
    "certificate validation": ("enable_certificate_validation", "enableCertificateValidation"),
    "provision format": ("provision_format", "provisionFormat"),
}


def target_set_field_report(target_set: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    """``(unknown keys, written fields the object does not carry)`` for one listed target set: the first are fields
    this tool never writes, the second are values a read-back could not verify (see ``target_set_differences``)."""
    unknown = sorted(str(key) for key in target_set if str(key) not in TARGET_SET_KNOWN_KEYS)
    missing = [label for label, names in TARGET_SET_WRITTEN_FIELDS.items() if not any(name in target_set for name in names)]
    return unknown, missing


def target_set_signature(target_set: dict[str, Any]) -> dict[str, Any]:
    """Normalized view of every target-set field this tool writes, tolerant of API key casing.

    The account link (``secret_id``) is always present, "" when the object has none: it is what a target set is for.
    Every other field the response does not carry at all is ``None`` -- unknown, not a default: list projections and
    tenants differ in what they echo, and an absent field must never read as ``false`` or ``""``. Callers compare only
    the fields both sides carry (see ``target_set_differences``).
    """
    def text(value: Any, *, fold: bool = False) -> str | None:
        if value is MISSING:
            return None
        text_value = str(value or "").strip()
        return text_value.casefold() if fold else text_value

    cert = _present(target_set, "enable_certificate_validation", "enableCertificateValidation")
    return {
        "type": text(_present(target_set, "type") if "type" in target_set else "Target", fold=True),
        "secret_type": text(_present(target_set, "secret_type", "secretType"), fold=True),
        "secret_id": str(next((target_set[k] for k in TARGET_SET_SECRET_KEYS if target_set.get(k)), "") or ""),
        "description": text(_present(target_set, "description")),
        "certificate_validation": None if cert is MISSING else bool(cert),
        "provision_format": text(_present(target_set, "provision_format", "provisionFormat")),
    }


# What the platform applies for a field the tool configures when a target set does not carry it. A drift check
# compares the tool's opinion against these, so a configured setting is set even on a tenant that omits unset
# fields; descriptive fields (type, secret_type, description) are simply unknown when absent and never drift.
TARGET_SET_UNKNOWN_DEFAULTS: dict[str, Any] = {"certificate_validation": False, "provision_format": ""}


def target_set_differences(current: dict[str, Any], desired: dict[str, Any], keys: tuple[str, ...], *,
                           unknown_defaults: Mapping[str, Any] | None = None) -> list[str]:
    """Signature keys whose values differ. A field the current object does not carry is unknown: skipped, unless
    ``unknown_defaults`` names the value the platform applies for it (drift checks pass TARGET_SET_UNKNOWN_DEFAULTS;
    a read-back passes nothing, because a listing that does not echo a field cannot verify it either way)."""
    defaults = unknown_defaults or {}
    changed: list[str] = []
    for key in keys:
        current_value, desired_value = current.get(key), desired.get(key)
        if current_value is None:
            if key not in defaults:
                continue
            current_value = defaults[key]
        if desired_value is None:
            desired_value = defaults.get(key)
        if current_value != desired_value:
            changed.append(key)
    return changed


def exact_fqdns(policy: dict[str, Any]) -> list[str]:
    """FQDNs targeted by EXACTLY rules (lower-cased); used to recognise a managed policy that was renamed."""
    rules = (((policy.get("targets") or {}).get("FQDN/IP") or {}).get("fqdnRules")) or []
    return [_rule_fqdn(r.get("computernamePattern"), r.get("domain")) for r in rules
            if str(r.get("operator", "")).upper() == "EXACTLY" and r.get("computernamePattern")]


def names_match(a: str | None, b: str | None) -> bool:
    """Policy names may come back HTML-escaped (the SDK escapes them); compare tolerant of that."""
    if a is None or b is None:
        return False
    return html.unescape(a) == html.unescape(b)
