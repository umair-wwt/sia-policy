"""Structured, redacted diagnostics shared by the CLI, reports, and doctor.

The classifier deliberately reports only causes it can support with evidence.
When a create or update may have reached the service, ``mutation_state`` is
``unknown`` and the recovery action is reconciliation rather than blind retry.
"""
from __future__ import annotations

import csv
import errno
import json
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any, Mapping, TextIO

import requests

from .redact import sanitize

MUTATION_STATES = frozenset({"not_applied", "applied", "unknown", "not_applicable"})
SEVERITIES = frozenset({"error", "warning", "info"})
_CREDENTIAL_NAME = re.compile(
    r"\b(?:SIA_CLIENT_ID|SIA_CLIENT_SECRET|PVWA_USER|PVWA_PASSWORD|[A-Z][A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|CLIENT_ID))\b"
)


@dataclass(frozen=True)
class Diagnostic:
    """One safe, actionable problem that can be rendered as text or JSON."""

    code: str
    message: str
    actions: tuple[str, ...] = ()
    stage: str = ""
    object_name: str = ""
    severity: str = "error"
    mutation_state: str = "not_applicable"
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.mutation_state not in MUTATION_STATES:
            raise ValueError(f"invalid mutation_state {self.mutation_state!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid diagnostic severity {self.severity!r}")

    def to_dict(self) -> dict[str, Any]:
        return sanitize({
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "stage": self.stage,
            "object_name": self.object_name,
            "mutation_state": self.mutation_state,
            "actions": list(self.actions),
            "details": dict(self.details),
        })


# The catalogue powers ``help error <code>`` and keyword search.  Per-error
# diagnostics may refine the message while retaining these recovery actions.
HELP_CATALOGUE: dict[str, dict[str, Any]] = {
    "SIA-MISSING": {
        "summary": "A required object is missing from the selected tenant.",
        "actions": ("Run plan with the same configuration and input/server options.", "Review and apply the missing objects, then verify again."),
        "keywords": ("missing", "verify", "onboard"),
    },
    "SIA-TENANT-MISMATCH": {
        "summary": "The authenticated token identifies a different tenant from the configuration.",
        "actions": ("Correct the tenant configuration or credential source before applying changes.",),
        "keywords": ("tenant", "wrong", "mismatch", "auth"),
    },
    "SIA-CANCELLED": {
        "summary": "The operator cancelled before the requested changes began.",
        "actions": ("Review the plan and run apply again when ready.",),
        "keywords": ("cancel", "confirmation", "apply"),
    },
    "SIA-INTERRUPTED": {
        "summary": "The process was interrupted before the run completed.",
        "actions": ("Review the checkpoint notice, then run apply with --resume.",
                    "Run `sia plan` first if any mutation was reported as unknown."),
        "keywords": ("interrupt", "keyboard", "resume", "checkpoint"),
    },
    "SIA-CONFIG": {
        "summary": "The settings file or environment is missing or invalid.",
        "actions": ("Run `sia settings --show` to see effective values and their sources.",
                    "Correct the named setting, then run `sia doctor` again."),
        "keywords": ("config", "toml", "environment", "setting"),
    },
    "SIA-INPUT": {
        "summary": "An input CSV or command value is invalid.",
        "actions": ("Correct every file and line listed in the error.",
                    "Run `sia doctor` to validate the inputs before planning."),
        "keywords": ("input", "csv", "server", "principal", "role", "group", "account"),
    },
    "SIA-FILE-NOT-FOUND": {
        "summary": "A required local file could not be found.",
        "actions": ("Check the displayed path and file name.",
                    "Remember that paths in TOML are relative to the settings file."),
        "keywords": ("file", "path", "missing"),
    },
    "SIA-LOCAL-PERMISSION": {
        "summary": "The operating system denied access to a local file or directory.",
        "actions": ("Check ownership and read/write permissions for the displayed path.",
                    "Choose a report or checkpoint directory your account can write to."),
        "keywords": ("permission", "file", "directory", "denied"),
    },
    "SIA-DISK-FULL": {
        "summary": "The local disk has no space for the requested file.",
        "actions": ("Free space or choose another report/checkpoint directory.",
                    "Run the command again; tenant changes already reported as applied remain applied."),
        "keywords": ("disk", "space", "report", "checkpoint"),
    },
    "SIA-LOCAL-IO": {
        "summary": "A local file operation failed.",
        "actions": ("Check the path, available space, and file permissions.",),
        "keywords": ("file", "io", "operating system"),
    },
    "SIA-DEPENDENCY": {
        "summary": "A required Python package or runtime component is unavailable.",
        "actions": ("Install the project with `pip install -e .` in the active environment.",
                    "Run `sia doctor` again from that environment."),
        "keywords": ("dependency", "module", "package", "python", "install"),
    },
    "SIA-AUTH-MISSING": {
        "summary": "Authentication settings are missing.",
        "actions": ("Run `sia setup` or set SIA_CLIENT_ID and SIA_CLIENT_SECRET.",
                    "Use `sia settings --show` to confirm which source wins."),
        "keywords": ("auth", "credential", "client id", "secret", "missing"),
    },
    "SIA-AUTH-REJECTED": {
        "summary": "CyberArk rejected the supplied identity credentials.",
        "actions": ("Confirm the tenant URL, client ID, and client secret.",
                    "Confirm the service user is enabled and configured as an OAuth confidential client.",
                    "Check how the secret is written in .env: quotes are taken literally, so a backslash "
                    "needs no doubling, and an unquoted value ends at its first ' #'. Re-entering it under "
                    "Settings > Credentials always stores it exactly as typed."),
        "keywords": ("auth", "401", "credential", "login", "oauth"),
    },
    "SIA-PERMISSION": {
        "summary": "The remote service refused this request.",
        "actions": ("Confirm the credential is valid for this endpoint and has the required role.",
                    "Check the selected authentication method and token audience, then run `sia doctor --online`."),
        "keywords": ("403", "forbidden", "permission", "role"),
    },
    "SIA-DNS": {
        "summary": "The tenant host name could not be resolved.",
        "actions": ("Check the tenant URLs for spelling.",
                    "Check DNS and VPN connectivity, then run `sia doctor --online`."),
        "keywords": ("dns", "name resolution", "host", "network"),
    },
    "SIA-PROXY": {
        "summary": "The configured network proxy could not complete the connection.",
        "actions": ("Check HTTPS_PROXY, HTTP_PROXY, and NO_PROXY in this shell.",
                    "Confirm the proxy permits the CyberArk tenant hosts."),
        "keywords": ("proxy", "network", "connect"),
    },
    "SIA-TLS": {
        "summary": "The server certificate could not be verified.",
        "actions": ("Check the computer clock and the certificate host name.",
                    "For TLS inspection, set http.ca_bundle to the approved corporate CA bundle."),
        "keywords": ("tls", "ssl", "certificate", "ca"),
    },
    "SIA-TIMEOUT": {
        "summary": "The remote service did not answer before the timeout.",
        "actions": ("Check network and tenant service health.",
                    "For an unknown mutation, run `sia plan` to reconcile before trying again."),
        "keywords": ("timeout", "slow", "network"),
    },
    "SIA-NETWORK": {
        "summary": "A network connection to the remote service failed.",
        "actions": ("Check internet, VPN, firewall, and tenant URL access.",
                    "Run `sia doctor --online` for independent endpoint results."),
        "keywords": ("network", "connection", "reset", "unreachable"),
    },
    "SIA-NOT-FOUND": {
        "summary": "The requested endpoint or object was not found.",
        "actions": ("Check the object name, tenant URL, and selected API family.",
                    "Run `sia plan` to rediscover current tenant state."),
        "keywords": ("404", "not found", "endpoint", "object"),
    },
    "SIA-CONFLICT": {
        "summary": "The service rejected the operation because an object already exists or changed concurrently.",
        "actions": ("Run `sia plan` to reconcile the object by name.",
                    "Review ownership and use --adopt only for an object you intend this tool to manage."),
        "keywords": ("409", "conflict", "duplicate", "exists"),
    },
    "SIA-RATE-LIMIT": {
        "summary": "The service is temporarily limiting requests.",
        "actions": ("Wait for the Retry-After interval before running again.",
                    "Lower http.max_requests_per_second or reduce --workers for large runs."),
        "keywords": ("429", "rate", "throttle", "retry"),
    },
    "SIA-SERVICE": {
        "summary": "The remote service returned a server or gateway error.",
        "actions": ("Check CyberArk service health and try the read-only doctor checks later.",
                    "For an unknown mutation, run `sia plan` before retrying."),
        "keywords": ("500", "502", "503", "504", "service", "outage", "gateway"),
    },
    "SIA-API-RESPONSE": {
        "summary": "The service response did not have the expected format.",
        "actions": ("Run again with --verbose and retain the diagnostic code for support.",
                    "For a mutation, run `sia plan` to reconcile before trying it again."),
        "keywords": ("json", "response", "format", "schema"),
    },
    "SIA-TENANT-FIELDS": {
        "summary": "The tenant carries policy fields this tool does not manage; the write itself converged.",
        "actions": ("Nothing to fix: fields the tool never sends are preserved on update and reported as notes.",
                    "To silence a field set [defaults] ignore_readback_keys; to fail on unknown fields set "
                    "[defaults] readback_extra_keys = \"fail\".",
                    "`show-policy NAME` prints the raw policy; --verbose or the JSON report shows the values."),
        "keywords": ("note", "tenant", "unmanaged", "extra", "fields", "echo"),
    },
    "SIA-DISCOVERY-INCOMPLETE": {
        "summary": "The service did not return a complete inventory; discovery stopped.",
        "actions": ("No missing-object decisions can be made from this partial inventory.",
                    "Run again with --verbose: the detail line names the endpoint and which check stopped the walk.",
                    "A repeated or cycled continuation token is a service-side fault worth reporting with that "
                    "detail. Pinning [http] secrets_api or targetsets_api to one family avoids the paginated "
                    "endpoint in the meantime."),
        "keywords": ("pagination", "inventory", "incomplete", "cycle", "page"),
    },
    "SIA-AMBIGUOUS": {
        "summary": "More than one object or conflicting definition matches the requested name.",
        "actions": ("Resolve the conflicting names or mappings; pin an Identity directory in groups.csv "
                    "(group principals only).",
                    "Run plan again before applying changes."),
        "keywords": ("ambiguous", "duplicate", "name", "directory", "role"),
    },
    "SIA-API": {
        "summary": "The remote API rejected the request.",
        "actions": ("Review the operation and HTTP status in verbose details.",
                    "Run `sia plan` after correcting the reported problem."),
        "keywords": ("api", "http", "request"),
    },
    "SIA-DRIFT": {
        "summary": "The tenant object differs from the requested settings.",
        "actions": ("Review the displayed differences.",
                    "Use --update only when this tool owns the object, or explicitly adopt the intended object."),
        "keywords": ("drift", "different", "update", "adopt"),
    },
    "SIA-INACTIVE": {
        "summary": "A required tenant object exists but is not active.",
        "actions": ("Use the diagnostic stage and object name to review its current platform status.",
                    "Change the status deliberately, then run `sia plan` again."),
        "keywords": ("inactive", "suspended", "strong account", "policy", "blocked"),
    },
    "SIA-BLOCKED": {
        "summary": "This item was not attempted because a prerequisite failed.",
        "actions": ("Correct the earlier failed prerequisite shown in the report.",
                    "Run `sia plan` again before applying the remaining work."),
        "keywords": ("blocked", "prerequisite", "not attempted"),
    },
    "SIA-UNCERTAIN": {
        "summary": "The service did not provide enough evidence to know whether the change was applied.",
        "actions": ("Do not repeat the mutation yet; run `sia plan` to reconcile by object name.",
                    "Verify current tenant state before continuing the apply."),
        "keywords": ("uncertain", "unknown", "mutation", "reconcile"),
    },
    "SIA-UNVERIFIED": {
        "summary": "The requested state could not be verified from the service response or read-back.",
        "actions": ("Run `sia plan --drift` to read the object again.",
                    "Do not treat the object as complete until its identifier and requested state are confirmed."),
        "keywords": ("unverified", "read back", "identifier", "validation"),
    },
    "SIA-ITEM-FAILED": {
        "summary": "An item could not be completed.",
        "actions": ("Use the item detail and earlier diagnostic to correct the cause.",
                    "Run `sia plan` again before retrying the apply."),
        "keywords": ("failed", "item", "object"),
    },
    "SIA-UNKNOWN": {
        "summary": "The program encountered an error it could not classify safely.",
        "actions": ("Run again with --verbose and retain the diagnostic code and technical details.",
                    "Use `sia doctor` to rule out settings and input problems."),
        "keywords": ("unknown", "unexpected", "error"),
    },
}


def get_diagnostic_help(code: str) -> dict[str, Any] | None:
    """Return one catalogue entry as plain, safe data (case-insensitive)."""
    normalized = (code or "").strip().upper()
    entry = HELP_CATALOGUE.get(normalized)
    return sanitize({"code": normalized, **entry}) if entry else None


def search_diagnostic_help(query: str = "") -> list[dict[str, Any]]:
    """Search diagnostic codes, summaries, actions, and keywords."""
    terms = [part.lower() for part in (query or "").split() if part]
    matches: list[dict[str, Any]] = []
    for code in sorted(HELP_CATALOGUE):
        entry = HELP_CATALOGUE[code]
        haystack = " ".join((code, entry["summary"], *entry["actions"], *entry["keywords"])).lower()
        if all(term in haystack for term in terms):
            matches.append(sanitize({"code": code, **entry}))
    return matches


# Convenient names for callers implementing an interactive help browser.
diagnostic_help = get_diagnostic_help
search_help = search_diagnostic_help


def _entry(code: str) -> tuple[str, tuple[str, ...]]:
    item = HELP_CATALOGUE[code]
    return str(item["summary"]), tuple(item["actions"])


def _chain(exc: BaseException):
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        attached = getattr(current, "cause", None)
        current = attached if isinstance(attached, BaseException) else (current.__cause__ or current.__context__)


def _network_code(exc: BaseException) -> str | None:
    chain = tuple(_chain(exc))
    text = " ".join(f"{item.__class__.__name__}: {item}" for item in chain).lower()
    if any(isinstance(item, requests.exceptions.ProxyError) for item in chain) or "proxyerror" in text:
        return "SIA-PROXY"
    # isinstance first and ssl.SSLError included: on Windows the verification message comes from
    # FormatMessageW and is localised, so the phrase list below cannot be relied on there.
    if any(isinstance(item, (requests.exceptions.SSLError, ssl.SSLError)) for item in chain) or any(
            phrase in text for phrase in ("certificate verify failed", "sslerror", "tlsv")):
        return "SIA-TLS"
    if any(isinstance(item, (requests.exceptions.Timeout, TimeoutError)) for item in chain) or "timed out" in text:
        return "SIA-TIMEOUT"
    if any(isinstance(item, socket.gaierror) for item in chain) or any(
            phrase in text for phrase in ("name resolution", "failed to resolve", "nodename nor servname", "getaddrinfo failed")):
        return "SIA-DNS"
    if any(isinstance(item, requests.exceptions.ConnectionError) for item in chain):
        return "SIA-NETWORK"
    if any(isinstance(item, requests.exceptions.RequestException) for item in chain):
        return "SIA-NETWORK"
    return None


# Network failures that are OSError subclasses and must never be read as local filesystem errors.
# ssl.SSLError is the dangerous one: OpenSSL sets errno = SSL_ERROR_SSL = 1, which is numerically
# identical to errno.EPERM, so a TLS failure otherwise classifies as SIA-LOCAL-PERMISSION and hands
# the operator file-permission advice for a certificate problem. requests.RequestException subclasses
# OSError too, and socket.gaierror carries unrelated EAI_* codes in the same errno field.
_NETWORK_OSERROR = (ssl.SSLError, socket.gaierror, socket.herror, requests.exceptions.RequestException,
                    ConnectionError, TimeoutError)


def _local_error(exc: BaseException) -> OSError | None:
    """The first genuine local filesystem error in the chain, or None.

    Filesystem failures are identified by the OSError subclass Python already maps them to, not by
    errno: EACCES and EPERM always arrive as PermissionError, so testing errno adds only false
    positives. ENOSPC is the exception -- it has no dedicated subclass -- so SIA-DISK-FULL still
    needs the errno test.
    """
    for item in _chain(exc):
        if not isinstance(item, OSError) or isinstance(item, _NETWORK_OSERROR):
            continue
        if isinstance(item, (FileNotFoundError, PermissionError)):
            return item
        if getattr(item, "errno", None) == errno.ENOSPC:
            return item
    return None


def _http_status(exc: BaseException) -> int:
    value = getattr(exc, "status", 0)
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return 0
    try:
        status = int(value)
    except (ValueError, TypeError, OverflowError):
        return 0
    return status if 100 <= status <= 599 else 0


def _mutation_state(exc: BaseException, requested: str | None) -> str:
    if requested is not None:
        return requested if requested in MUTATION_STATES else "unknown"
    recorded = getattr(exc, "mutation_state", None)
    if isinstance(recorded, str) and recorded in MUTATION_STATES:
        return recorded
    method = str(getattr(exc, "method", "")).upper()
    if method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return "not_applicable"
    if bool(getattr(exc, "uncertain", False)):
        return "unknown"
    status = _http_status(exc)
    if status == 0 or status >= 500 or 200 <= status < 300:
        return "unknown"
    return "not_applied"


def _details(exc: BaseException, *, auth: bool = False) -> dict[str, Any]:
    from .checkpoint import CheckpointWriteError

    details: dict[str, Any] = {
        "exception_type": exc.__class__.__name__,
        "error": str(exc),
    }
    for name in ("operation", "method", "url", "status", "path", "row_key", "statuses", "refs",
                 "intended_paths", "completed_paths"):
        value = getattr(exc, name, None)
        if value not in (None, "", 0):
            if isinstance(exc, CheckpointWriteError) and name in ("statuses", "refs"):
                # This is our stage name, not a credential field. Preserve the
                # completed account evidence without exempting API secret keys
                # from the shared redactor.
                value = {("strong_account" if key == "secret" else key): item
                         for key, item in value.items()}
            details[name] = value
    # Authentication endpoints sometimes echo submitted fields.  Status,
    # operation, and exception type are sufficient evidence; never copy a
    # response body into output, even verbose output.
    if not auth:
        body = getattr(exc, "body", None)
        if body:
            compact = " ".join(str(body).split())
            details["response"] = compact[:2_000] + ("..." if len(compact) > 2_000 else "")
    cause = getattr(exc, "cause", None) or exc.__cause__
    if isinstance(cause, BaseException):
        details["cause_type"] = cause.__class__.__name__
        if not auth or isinstance(cause, requests.exceptions.RequestException):
            details["cause"] = str(cause)
    elif cause:
        details["cause"] = str(cause)
    return sanitize(details)


def diagnose(
    exc: BaseException,
    *,
    stage: str = "",
    object_name: str = "",
    mutation_state: str | None = None,
) -> Diagnostic:
    """Classify an exception without guessing beyond the available evidence."""
    status = _http_status(exc)
    name = exc.__class__.__name__
    module = exc.__class__.__module__
    state = _mutation_state(exc, mutation_state)
    local_error = _local_error(exc)
    actions_override: tuple[str, ...] | None = None

    is_auth = name == "AuthError" and module.startswith("sia")
    is_api = name == "SIAApiError" and module.startswith("sia")
    is_config = any(base.__name__ == "ConfigError" and base.__module__.startswith("sia")
                    for base in type(exc).__mro__)

    if isinstance(local_error, FileNotFoundError):
        code = "SIA-FILE-NOT-FOUND"
        message = f"Required file not found: {sanitize(str(exc))}"
    elif isinstance(local_error, PermissionError):
        code = "SIA-LOCAL-PERMISSION"
        message = f"Local access was denied: {sanitize(str(exc))}"
    elif local_error is not None and getattr(local_error, "errno", None) == errno.ENOSPC:
        code = "SIA-DISK-FULL"
        message = f"The local disk has no space left for this operation: {sanitize(str(exc))}"
    elif is_config:
        credential_names = tuple(dict.fromkeys(_CREDENTIAL_NAME.findall(str(exc))))
        missing = any(phrase in str(exc).lower() for phrase in ("not set", "must be set", "missing", "not available"))
        code = "SIA-AUTH-MISSING" if credential_names and missing else "SIA-CONFIG"
        message = str(sanitize(str(exc)))
        if code == "SIA-AUTH-MISSING":
            joined = ", ".join(credential_names)
            actions_override = (f"Set {joined} in the session, approved environment, or credentials file.",
                                "Run `sia settings --show` to confirm which source is active.")
    elif name in ("ReconcileError", "ResolveError") and module.startswith("sia"):
        message = str(sanitize(str(exc)))
        code = ("SIA-AMBIGUOUS" if "ambiguous" in message.lower() else
                "SIA-NOT-FOUND" if any(phrase in message.lower() for phrase in ("not found", "missing", "no policy")) else "SIA-ITEM-FAILED")
    elif ((name == "InputError" and module.startswith("sia")) or isinstance(exc, csv.Error)
          or (isinstance(exc, ValueError) and stage.lower() in {"input", "inputs", "server input"})):
        code = "SIA-INPUT"
        message = str(sanitize(str(exc)))
    elif isinstance(exc, (ModuleNotFoundError, ImportError)) or name == "PackageNotFoundError":
        code = "SIA-DEPENDENCY"
        message = f"A required component could not be loaded: {sanitize(str(exc))}"
    elif is_auth:
        text = str(exc).lower()
        if status == 403:
            code = "SIA-PERMISSION"
        elif status == 401:
            code = "SIA-AUTH-REJECTED"
        elif status in (404, 405, 501):
            code = "SIA-NOT-FOUND"
        elif status == 429:
            code = "SIA-RATE-LIMIT"
        elif status >= 500:
            code = "SIA-SERVICE"
        elif 200 <= status < 300:
            code = "SIA-API-RESPONSE"
        elif "must be set" in text or "missing" in text:
            code = "SIA-AUTH-MISSING"
        elif "unknown identity_auth method" in text:
            code = "SIA-CONFIG"
        else:
            code = _network_code(exc) or "SIA-AUTH-REJECTED"
        if code == "SIA-AUTH-MISSING":
            message = str(sanitize(str(exc)))
            credential_names = tuple(dict.fromkeys(_CREDENTIAL_NAME.findall(str(exc))))
            if credential_names:
                joined = ", ".join(credential_names)
                actions_override = (f"Set {joined} in the session, approved environment, or credentials file.",
                                    "Run `sia settings --show` to confirm which source is active.")
        elif code == "SIA-CONFIG":
            message = str(sanitize(str(exc)))
        else:
            message, _ = _entry(code)
        state = "not_applicable"
    elif is_api:
        network = _network_code(exc) if status == 0 else None
        if getattr(exc, "cause", None) == "incomplete_pagination":
            code = "SIA-DISCOVERY-INCOMPLETE"
        elif getattr(exc, "cause", None) == "ambiguous_response":
            code = "SIA-AMBIGUOUS"
        elif network:
            code = network
        elif status == 401:
            code = "SIA-AUTH-REJECTED"
        elif status == 403:
            code = "SIA-PERMISSION"
        elif status in (404, 405, 501):
            code = "SIA-NOT-FOUND"
        elif status == 409:
            code = "SIA-CONFLICT"
        elif status == 429:
            code = "SIA-RATE-LIMIT"
        elif status >= 500:
            code = "SIA-SERVICE"
        elif 200 <= status < 300:
            code = "SIA-API-RESPONSE"
        else:
            code = "SIA-API"
        message, _ = _entry(code)
    else:
        network = _network_code(exc)
        if network:
            code = network
            message, _ = _entry(code)
        elif isinstance(exc, OSError):
            code = "SIA-LOCAL-IO"
            message = f"A local operation failed: {sanitize(str(exc))}"
        else:
            code = "SIA-UNKNOWN"
            message = str(sanitize(str(exc))) or _entry(code)[0]

    _, actions = _entry(code)
    actions = actions_override or actions
    if state == "unknown":
        reconcile = "Do not repeat the mutation yet; run `sia plan` to determine whether it was applied."
        if reconcile not in actions:
            actions = (reconcile, *actions)
    return Diagnostic(
        code=code,
        message=str(sanitize(message)),
        actions=tuple(str(sanitize(action)) for action in actions),
        stage=str(sanitize(stage)),
        object_name=str(sanitize(object_name)),
        mutation_state=state,
        details=_details(exc, auth=is_auth),
    )


_CHANGE_TEXT = {
    "not_applied": "This operation did not apply a tenant change.",
    "applied": "The requested change was confirmed as applied before this error occurred.",
    "unknown": "The result is unknown. The service may or may not have applied the change.",
    "not_applicable": "This operation did not make a tenant change.",
}


def render_diagnostic(diag: Diagnostic, out: TextIO, verbose: bool = False) -> None:
    """Render a diagnostic using the same three plain-language sections everywhere."""
    data = diag.to_dict()
    print(f"\n[{data['code']}] {str(data['severity']).upper()}", file=out)
    if data["stage"] or data["object_name"]:
        parts = []
        if data["stage"]:
            parts.append(f"stage: {data['stage']}")
        if data["object_name"]:
            parts.append(f"object: {data['object_name']}")
        print("Context: " + ", ".join(parts), file=out)
    print(f"\nWhat happened\n  {data['message']}", file=out)
    print(f"\nWhat changed\n  {_CHANGE_TEXT[data['mutation_state']]}", file=out)
    print("\nWhat to do next", file=out)
    for action in data["actions"]:
        print(f"  - {action}", file=out)
    if verbose and data["details"]:
        print("\nTechnical details", file=out)
        rendered = json.dumps(data["details"], indent=2, sort_keys=True, ensure_ascii=False)
        for line in rendered.splitlines():
            print(f"  {line}", file=out)

