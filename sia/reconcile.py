"""Desired state (CSVs) vs tenant state -> per-row actions.

Units of work
  * one strong account per referenced account row (shared by every server that names it);
  * one target set per distinct target-set name: normally that is one per Windows server (FQDN), but a "Domain" set
    covers every server in one AD domain, so its outcome is copied to all of them;
  * one access policy per servers.csv row (a server may have several, e.g. one per Identity role or group).

Safety rules
  * dry_run computes everything and writes nothing.
  * Objects are matched by name (vault secrets by the platform's <account>_<safe> name). A managed policy that was
    renamed in the UI is still recognised through its owner tag + EXACTLY FQDN rule and reported as drift.
  * `update` only modifies objects that carry the owner marker (policy tag / target-set description) or that the
    operator adopted explicitly (--adopt <fqdn|policy name>, --adopt-all). Nothing is ever deleted.
  * fail_fast (default): the first 4xx from a create/update (a payload or permission defect that would repeat for every
    row) aborts the run; remaining changes are reported as blocked. Per-item 207 results and 5xx keep going.
  * A non-idempotent request that failed uncertainly (5xx/network) is not retried; the next run finds the object by name.
  * workers > 1 parallelises creation, but the first item of each stage always runs alone (a canary) so a systematic
    defect surfaces before anything fans out.

Scale
  * snapshot() reads the tenant once; reconcile() can then run twice (preview, then apply) without re-reading.
  * Lookups are either targeted per server (`search`: q=<fqdn>, secret_name=, name=) or one filtered listing
    (`list`: only policies tagged as ours). Full policy objects are fetched only when drift checking asks for it.
  * A checkpoint file records finished rows so an interrupted apply resumes without repeating lookups.

Linux (protocol=ssh) rows need only a policy: SIA's Linux ZSP uses a short-lived SSH certificate, so their strong
account and target set are reported as n/a.
"""
from __future__ import annotations

import html
import json
import logging
import os
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable, NamedTuple

from .checkpoint import Checkpoint, fingerprint, is_done, row_key
from .clients import UAP_VM_FILTER, SIAClient, UAPClient, owned_vm_filter
from .config import Defaults
from .diagnostics import Diagnostic, diagnose
from .http import SIAApiError
from .inputs import Inputs, ServerRow, StrongAccountRow
from .payloads import (
    build_bulk_target_sets, build_policy, build_policy_update, build_secret_payload, build_target_set,
    build_target_set_update, build_vault_account, exact_fqdns, is_owned_policy, is_owned_target_set, leaf_differences,
    normalize_field, plain, policy_name_for, policy_signature, policy_status, sanitize_template, target_set_name_for,
    validate_template, target_set_signature, implied_session_overrides,
)
from .redact import register_secret
from .resolve import PrincipalResolver, ResolveError, SecretIndex, pick, secret_id_of, secret_type_of

STAGES = ("all", "vault", "secrets", "targetsets", "policies")
LOOKUP_MODES = ("auto", "search", "list")
BULK_CHUNK = 50
MAX_WORKERS = 16
POLICY_STATUS_POLL_SECONDS = 2.0
MAX_CHANGE_ENTRIES = 8            # named values per differing policy field in a drift or read-back message
# Condition leaves outside the named settings that still deserve an operator's name. Compared on the normalized block
# only (payloads.SESSION_OVERRIDE_FLAGS drops a flag carrying the value the tenant derives), never raw: do not move
# them into _policy_change_values' paths, whose raw comparison would print a consistent echo beside every real change.
_LEAF_LABELS = {"overrideIdleTime": "idle time override", "overrideMaxSessionDuration": "max session override",
                "overrideRecording": "recording override"}
BAD = ("failed", "blocked", "inactive", "uncertain", "unverified")
NON_SYSTEMATIC_4XX = (404, 409, 429)
NOT_APPLICABLE = "n/a"
_CONFLICT_WORDS = ("already exist", "duplicate", "unique", "conflict")


def env_password(account: StrongAccountRow) -> str | None:
    return os.environ.get(account.password_env or "", "") or None


class ReconcileError(Exception):
    """A run-level problem that prevents any progress (e.g. the template policy is missing or unsuitable)."""


class WriteCancelled(ReconcileError):
    """The run stopped before this request was sent."""

    mutation_state = "not_applied"


def _principal_summary(policy: dict) -> list[str]:
    """`name (TYPE)` per principal, sorted, so a drift line says which principals changed and of what kind."""
    return sorted(f"{p.get('name') or p.get('id') or '?'} ({str(p.get('type') or '?').upper()})"
                  for p in policy.get("principals") or [] if isinstance(p, dict))


class PolicyReadBack(NamedTuple):
    policy: dict[str, Any]
    status: str
    description: str
    mismatch: str                 # "" once every managed field converged, else "still differs in ..." with values
    differences: dict[str, Any]   # {signature key: {"tenant": ..., "requested": ..., "changed": [paths]}}


def _unset(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _policy_change_values(key: str, current: dict, desired: dict,
                          current_sig: dict | None = None, desired_sig: dict | None = None) -> str:
    """Compact, named before/after values (tenant -> requested) for one differing signature key.

    Settings an operator recognises are named first; every other differing leaf of the block follows by its path
    (or its ``_LEAF_LABELS`` name), so a field the tool does not manage (a condition a newer tenant adds, an extra
    RDP setting) is never silent. A session-override flag the tenant derives shows the value the request implies.
    """
    if key == "principals":
        before, after = _principal_summary(current), _principal_summary(desired)
        return f" ({', '.join(before) or 'none'} -> {', '.join(after) or 'none'})" if before != after else ""
    paths = {
        "description": [("description", ("metadata", "description"))],
        "time_zone": [("time zone", ("metadata", "timeZone"))],
        "tags": [("tags", ("metadata", "policyTags"))],
        "conditions": [("max session hours", ("conditions", "maxSessionDuration")),
                       ("idle minutes", ("conditions", "idleTime")),
                       ("access days", ("conditions", "accessWindow", "daysOfTheWeek")),
                       ("from hour", ("conditions", "accessWindow", "fromHour")),
                       ("to hour", ("conditions", "accessWindow", "toHour"))],
        "behavior": [("SSH username", ("behavior", "connectAs", "ssh", "username"))],
    }.get(key, [])
    if key == "behavior":
        for profile in ("localEphemeralUser", "domainEphemeralUser"):
            paths += [("local groups", ("behavior", "connectAs", "rdp", profile, "assignGroups")),
                      ("reconnect", ("behavior", "connectAs", "rdp", profile, "enableEphemeralUserReconnect"))]

    def get(policy, path):
        for segment in path:
            policy = policy.get(segment) if isinstance(policy, dict) else None
        return policy

    def short(value):
        if value is None:
            return "absent"
        text = json.dumps(value, ensure_ascii=False)
        return text if len(text) <= 100 else text[:97] + "..."

    changed: list[str] = []
    covered: list[str] = []
    for label, path in paths:
        covered.append(".".join(path[1:]))
        old, new = get(current, path), get(desired, path)
        if (_unset(old) and _unset(new)) or normalize_field(old, path[-1]) == normalize_field(new, path[-1]):
            continue                    # null/empty echoes and order-only differences are not changes
        changed.append(f"{label}: {short(old)} -> {short(new)}")
    current_sig = policy_signature(current) if current_sig is None else current_sig
    desired_sig = policy_signature(desired) if desired_sig is None else desired_sig
    old_value, new_value = plain(current_sig.get(key)), plain(desired_sig.get(key))
    implied = implied_session_overrides(desired.get("conditions")) if key == "conditions" else {}
    if isinstance(old_value, dict) and isinstance(new_value, dict):
        for path, old, new in leaf_differences(old_value, new_value):
            if path in covered or any(path.startswith(prefix + ".") for prefix in covered):
                continue
            if new is None and path in implied:
                new = implied[path]         # the tool never writes the flag; the tenant derives it from the setting
            changed.append(f"{_LEAF_LABELS.get(path, path)}: {short(old)} -> {short(new)}")
    elif not changed and old_value != new_value:
        changed.append(f"{short(old_value)} -> {short(new_value)}")
    if len(changed) > MAX_CHANGE_ENTRIES:
        changed = changed[:MAX_CHANGE_ENTRIES] + [f"+{len(changed) - MAX_CHANGE_ENTRIES} more"]
    return " (" + "; ".join(changed) + ")" if changed else ""


@dataclass
class Outcome:
    status: str = "pending"   # created | exists | inactive | drift | updated | planned | skipped | failed | blocked | uncertain | unverified | n/a
    detail: str = ""
    ref: str | None = None
    diagnostic: dict[str, Any] | None = None

    @property
    def bad(self) -> bool:
        return self.status in BAD


@dataclass
class ServerResult:
    fqdn: str
    strong_account: str
    policy_name: str
    protocol: str = "rdp"
    line: int = 0
    target_set_name: str = ""     # the set this row needs; several rows may name the same one (a Domain set)
    secret: Outcome = field(default_factory=Outcome)
    target_set: Outcome = field(default_factory=Outcome)
    policy: Outcome = field(default_factory=Outcome)

    @property
    def ok(self) -> bool:
        return not (self.secret.bad or self.target_set.bad or self.policy.bad)

    @property
    def key(self) -> tuple[str, str]:
        return (self.fqdn, self.policy_name)

    @property
    def target_set_key(self) -> str:
        """Identity of this row's target set, for counting objects rather than rows."""
        return (self.target_set_name or self.fqdn).lower()


@dataclass
class RunResult:
    mode: str
    servers: list[ServerResult] = field(default_factory=list)
    secrets: dict[str, Outcome] = field(default_factory=dict)
    vault: dict[str, Outcome] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    aborted: list[str] = field(default_factory=list)
    resumed: int = 0
    lookup_mode: str = ""
    incomplete: bool = False
    interrupted: bool = False
    diagnostics: list[dict[str, Any]] = field(default_factory=list)

    @property
    def failures(self) -> int:
        """Rows that are not fully OK. A failed strong account always surfaces here through the rows it blocks."""
        return sum(1 for s in self.servers if not s.ok)

    def by_key(self) -> dict[tuple[str, str], ServerResult]:
        return {s.key: s for s in self.servers}


class Reconciler:
    def __init__(self, *, sia: SIAClient, uap: UAPClient, resolver: PrincipalResolver, inputs: Inputs,
                 defaults: Defaults, dry_run: bool, update: bool = False, only: str = "all", fail_fast: bool = True,
                 adopt: Iterable[str] = (), adopt_all: bool = False, workers: int = 1, status_polls: int = 1,
                 get_password: Callable[[StrongAccountRow], str | None] = env_password,
                 logger: logging.Logger | None = None, sleep: Callable[[float], None] = time.sleep,
                 drift: bool | None = None, lookup: str = "auto", lookup_search_max_rows: int = 2000,
                 checkpoint: Checkpoint | None = None, resume: bool = False, progress_every: int = 100,
                 pvwa: Any = None, pvwa_platform_id: str = "WinServerLocal", pvwa_cpm_managed: bool = True,
                 set_policy_status: str | None = None, suspended_ok: bool = False,
                 reconciliation_context: dict[str, Any] | None = None):
        if only not in STAGES:
            raise ValueError(f"only must be one of {STAGES}")
        if lookup not in LOOKUP_MODES:
            raise ValueError(f"lookup must be one of {LOOKUP_MODES}")
        if not 1 <= workers <= MAX_WORKERS:
            raise ValueError(f"workers must be between 1 and {MAX_WORKERS}")
        if set_policy_status not in (None, "Active", "Suspended"):
            raise ValueError("set_policy_status must be Active or Suspended")
        if set_policy_status is not None and not update:
            raise ValueError("set_policy_status requires update=True")
        if set_policy_status is not None and only not in ("all", "policies"):
            raise ValueError("set_policy_status requires only='all' or only='policies'")
        self.sia, self.uap, self.resolver, self.inputs, self.defaults = sia, uap, resolver, inputs, defaults
        self.dry_run, self.update, self.only, self.fail_fast = dry_run, update, only, fail_fast
        self.drift = update if drift is None else drift
        self.adopt, self.adopt_all = {a.lower() for a in adopt}, adopt_all
        self.workers, self.status_polls = workers, max(1, status_polls)
        self.lookup, self.lookup_search_max_rows = lookup, lookup_search_max_rows
        self.checkpoint, self.resume = checkpoint, resume
        self.progress_every = max(0, progress_every)
        self.pvwa, self.pvwa_platform_id, self.pvwa_cpm_managed = pvwa, pvwa_platform_id, pvwa_cpm_managed
        self.set_policy_status = set_policy_status
        # plan/apply with [defaults] policy_status = "Suspended" (a staged rollout): an existing Suspended policy is
        # the requested state. verify never sets this -- users still cannot connect through a suspended policy.
        self.suspended_ok = suspended_ok
        self.reconciliation_context = dict(reconciliation_context or {})
        self._get_password = get_password
        self._log = logger or logging.getLogger("sia.reconcile")
        self._sleep = sleep
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._fatal_error: BaseException | None = None
        self._abort_reason: str | None = None
        self._owned_by_fqdn: dict[str, list[dict[str, Any]]] | None = None
        self._policy_list: list[dict[str, Any]] = []
        self._policies: dict[str, dict[str, Any]] = {}
        self._target_sets: dict[str, dict[str, Any]] = {}
        self._refs: dict[str, tuple[str | None, str]] = {}
        self._secrets: SecretIndex = SecretIndex([])
        self._secret_listing: list[dict[str, Any]] | None = None
        self._template: dict[str, Any] | None = None
        self._principal_errors: dict[str, ResolveError] = {}
        self._checkpoint_context: dict[str, Any] = {}
        self._rows: list[tuple[ServerRow, ServerResult]] = []
        self._resumed: dict[tuple[str, str], tuple[ServerRow, ServerResult, dict[str, Any]]] = {}
        self._snapshotted = False
        self._snapshot_warnings: list[str] = []
        self._lookup_mode = ""
        self._result: RunResult | None = None
        self._progress: dict[str, list[int]] = {}
        self._started = time.monotonic()

    # ------------------------------------------------------------------ run
    def run(self) -> RunResult:
        self.snapshot()
        return self.reconcile()

    def snapshot(self) -> None:
        """Read the tenant once: template policy, strong accounts, target sets and policies for the rows to process."""
        self._snapshot_warnings = []
        self._secret_listing = None
        self._template = self._load_template()
        self._checkpoint_context = self._build_checkpoint_context()
        self._plan_rows()
        if self.checkpoint is not None:
            self._snapshot_warnings.extend(self.checkpoint.warnings)
        fqdns = list(dict.fromkeys(s.fqdn for s, _ in self._rows))
        # Windows servers may share one target set (a Domain set covers a whole AD domain), so look them up by
        # target-set name rather than by FQDN.
        target_set_names = list(dict.fromkeys(s.target_set_key for s, _ in self._rows if not s.is_ssh))
        accounts = self._active_accounts()
        self._lookup_mode = self._choose_lookup(len(fqdns))
        # Per-stage timings: a slow tenant read is otherwise a single unbroken gap in the log, with nothing to say
        # which of the four reads spent the time.
        timings: list[str] = []
        for label, read in (("secrets", lambda: self._snapshot_secrets(accounts)),
                            ("target sets", lambda: self._snapshot_target_sets(target_set_names, accounts)),
                            ("policies", lambda: self._snapshot_policies(fqdns)),
                            ("principals", self._snapshot_principals)):
            started = time.monotonic()
            read()
            timings.append(f"{label} {time.monotonic() - started:.1f}s")
        self._log.info("Tenant snapshot (%s lookup): %d strong accounts, %d target sets, %d policies read for %d rows "
                       "(%d resumed) [%s]",
                       self._lookup_mode, len(self._secrets), len(self._target_sets), len(self._policies), len(self._rows),
                       len(self._resumed), ", ".join(timings))
        self._snapshotted = True

    def reconcile(self, dry_run: bool | None = None) -> RunResult:
        """Decide and (unless dry_run) apply. May be called more than once after one snapshot()."""
        if dry_run is not None:
            self.dry_run = dry_run
        if not self._snapshotted:
            self.snapshot()
        result = RunResult(mode="plan" if self.dry_run else "apply", resumed=len(self._resumed), lookup_mode=self._lookup_mode)
        result.warnings.extend(self.inputs.warnings)
        result.warnings.extend(self._snapshot_warnings)
        self._result = result
        self._abort_reason = None
        self._stop.clear()
        self._fatal_error = None
        self._refs = {}
        self._progress = {}
        self._started = time.monotonic()
        fresh: list[tuple[ServerRow, ServerResult]] = []
        for server, old in self._rows:
            fresh.append((server, ServerResult(fqdn=old.fqdn, strong_account=old.strong_account, policy_name=old.policy_name,
                                               protocol=old.protocol, line=old.line,
                                               target_set_name=old.target_set_name)))
        self._rows = fresh
        ordered: dict[tuple[str, str], ServerResult] = {}
        for key, (_server, old, record) in self._resumed.items():
            sr = ServerResult(fqdn=old.fqdn, strong_account=old.strong_account, policy_name=old.policy_name,
                              protocol=old.protocol, line=old.line, target_set_name=old.target_set_name)
            statuses, refs, at = record.get("statuses") or {}, record.get("refs") or {}, record.get("at", "")
            for label in ("secret", "target_set", "policy"):
                status = statuses.get(label, "exists")
                note = f"checkpoint {at}: {status}"
                setattr(sr, label, Outcome(NOT_APPLICABLE if status == NOT_APPLICABLE else "exists", note, refs.get(label)))
            ordered[key] = sr
        for _server, sr in self._rows:
            ordered[sr.key] = sr
        # keep CSV order
        result.servers = [ordered[(s.fqdn, policy_name_for(s, self.defaults))] for s in self.inputs.servers
                          if (s.fqdn, policy_name_for(s, self.defaults)) in ordered]
        try:
            self._flag_duplicate_policy_names(result)
            self._ensure_vault(result)
            self._ensure_secrets(result)
            self._ensure_target_sets(result)
            self._ensure_policies(result)
        except (Exception, KeyboardInterrupt) as exc:
            self._abort("Interrupted by operator" if isinstance(exc, KeyboardInterrupt) else str(exc))
            self._finish_partial(result, exc)
            exc.partial_result = result
            raise
        return result

    def check_cancelled(self) -> None:
        """Called again by HTTP clients after rate-limit waits, just before sending a write."""
        if self._stop.is_set():
            raise WriteCancelled("Run stopped; this request was not sent.")

    def _finish_partial(self, result: RunResult, exc: BaseException) -> None:
        result.incomplete = True
        result.interrupted = isinstance(exc, KeyboardInterrupt)
        for server, sr in self._rows:
            if sr.secret.status == "pending":
                sr.secret = (Outcome(NOT_APPLICABLE, "SSH: no strong account needed") if server.is_ssh else
                             result.secrets.get(server.strong_account or "", self._blocked_by_abort()))
            if sr.target_set.status == "pending":
                sr.target_set = (Outcome(NOT_APPLICABLE, "SSH: no target set needed") if server.is_ssh else
                                 self._blocked_by_abort())
            if sr.policy.status == "pending":
                sr.policy = self._blocked_by_abort()
        outcomes = [o for sr in result.servers for o in (sr.secret, sr.target_set, sr.policy)]
        outcomes += list(result.secrets.values()) + list(result.vault.values())
        state = ("unknown" if any(o.status == "uncertain" for o in outcomes) else
                 "applied" if any(o.status in ("created", "updated") or
                                  (o.diagnostic or {}).get("mutation_state") == "applied" for o in outcomes) else
                 "unknown" if any(o.status == "unverified" for o in outcomes) else "not_applied")
        if isinstance(exc, KeyboardInterrupt):
            diagnostic = Diagnostic(code="SIA-INTERRUPTED", message="Run interrupted; in-flight results have been collected.",
                                    stage="Apply", mutation_state=state,
                                    actions=("Review the partial results and run plan --drift before apply --resume.",))
        else:
            diagnostic = diagnose(exc, stage="Completing run", mutation_state=state)
        result.diagnostics.append(diagnostic.to_dict())

    # ------------------------------------------------------------ snapshot
    def _build_checkpoint_context(self) -> dict[str, Any]:
        """Inputs outside one CSV row that can change the objects produced by reconciliation."""
        return {
            "caller": self.reconciliation_context,
            "defaults": asdict(self.defaults),
            "template": self._template,
            "input_mappings": {
                "strong_accounts": {key: asdict(value) for key, value in self.inputs.strong_accounts.items()},
                "groups": {key: asdict(value) for key, value in self.inputs.groups.items()},
                "domains": {key: asdict(value) for key, value in self.inputs.domains.items()},
            },
            "pvwa": {
                "enabled": self.pvwa is not None,
                "platform_id": self.pvwa_platform_id,
                "cpm_managed": self.pvwa_cpm_managed,
            },
            "set_policy_status": self.set_policy_status,
            # What a completed row was checked against: a row verified without --drift must be reconciled again by
            # an --update run, which compares every managed field.
            "update": self.update,
            "drift": self.drift,
        }

    def _plan_rows(self) -> None:
        self._rows, self._resumed = [], {}
        for server in self.inputs.servers:
            name = policy_name_for(server, self.defaults)
            sr = ServerResult(fqdn=server.fqdn, strong_account=server.strong_account or "-", policy_name=name,
                              protocol=server.protocol, line=server.line,
                              target_set_name=("" if server.is_ssh else target_set_name_for(server)))
            if self.resume and self.checkpoint is not None:
                account = self.inputs.strong_accounts.get(server.strong_account or "")
                record = self.checkpoint.get(
                    row_key(server.fqdn, name), fingerprint(server, account, name, self._checkpoint_context))
                if record and is_done(record):
                    self._resumed[sr.key] = (server, sr, record)
                    continue
            self._rows.append((server, sr))

    def _active_accounts(self) -> list[StrongAccountRow]:
        names = {s.strong_account for s, _ in self._rows if s.strong_account and not s.is_ssh}
        return [a for n, a in self.inputs.strong_accounts.items() if n in names]

    def _choose_lookup(self, unique_fqdns: int) -> str:
        if self.lookup != "auto":
            return self.lookup
        if self.adopt_all:
            return "list"
        return "search" if unique_fqdns <= self.lookup_search_max_rows else "list"

    def _parallel(self, items: list, fn: Callable[[Any], Any]) -> list:
        if not items:
            return []
        if self.workers <= 1 or len(items) == 1:
            return [fn(item) for item in items]
        pool = ThreadPoolExecutor(max_workers=min(self.workers, len(items)), thread_name_prefix="sia-read")
        pending = {}
        results = [None] * len(items)
        index = 0
        try:
            while index < len(items) or pending:
                while index < len(items) and len(pending) < self.workers:
                    pending[pool.submit(fn, items[index])] = index
                    index += 1
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    results[pending.pop(future)] = future.result()
            return results
        finally:
            for future in pending:
                future.cancel()
            pool.shutdown(wait=True, cancel_futures=True)

    def _secrets_family(self) -> str:
        caps = getattr(self.sia, "capabilities", None)
        return str(getattr(caps, "secrets_api", "") or "")

    def _filters_trusted(self) -> bool:
        """Whether this tenant's server-side name filters agree with an unfiltered listing."""
        caps = getattr(self.sia, "capabilities", None)
        return True if caps is None else bool(getattr(caps, "name_filter_reliable", True))

    def _distrust_name_filters(self, kind: str, recovered: list[str]) -> None:
        """A name filter missed objects the unfiltered listing serves: from here on nothing in this run is treated
        as missing on the strength of a filtered read, and the operator is told to pin list mode."""
        caps = getattr(self.sia, "capabilities", None)
        if caps is not None:
            caps.name_filter_reliable = False
        shown = ", ".join(repr(n) for n in recovered[:3])
        if len(recovered) > 3:
            shown += f" and {len(recovered) - 3} more"
        plural = len(recovered) != 1
        self._snapshot_warnings.append(
            f"this tenant matched nothing when filtering by name for {kind}{'s' if plural else ''} {shown}, but its "
            f"unfiltered listing serves {'them' if plural else 'it'}; nothing else in this run is treated as missing "
            "on the strength of a name-filtered read. Pin --lookup list (or [http] lookup_search_max_rows = 0) for "
            "this tenant.")

    def _list_all_secrets(self) -> list[dict[str, Any]]:
        """Share one complete listing between secret discovery and account-scoped target-set discovery."""
        if self._secret_listing is None:
            self._secret_listing = self.sia.list_secrets()
        return self._secret_listing

    def _snapshot_secrets(self, accounts: list[StrongAccountRow]) -> None:
        # The legacy secrets API has no server-side name filter: a per-account search would list every secret once
        # per account, so read the listing once and index it, whatever the lookup mode.
        if self._lookup_mode == "search" and self._secrets_family() != "legacy":
            self._secrets = SecretIndex([])
            found = self._parallel(accounts, lambda a: self.sia.find_secret(a.sia_name))
            for secret in found:
                if secret:
                    self._secrets.add(secret)
            # An empty server-side filtered read is not proof of absence: secret_name only narrows what the
            # client-side filter would pick out anyway, and some tenants match nothing for a name the unfiltered
            # listing serves. Confirm once for the whole batch before any miss becomes a failure or a create.
            if any(not self._secrets.has(a.sia_name) for a in accounts):
                listing = self._list_all_secrets()
                listed = SecretIndex(listing)
                recovered = sorted({a.sia_name for a in accounts
                                    if not self._secrets.has(a.sia_name) and listed.has(a.sia_name)})
                # Union, not replacement: the per-name reads are evidence too, and a listing endpoint that already
                # misbehaves (empty pages with live cursors) is not the only source of truth. The index collapses
                # an object seen by both reads through its id.
                for secret in listing:
                    self._secrets.add(secret)
                if recovered:
                    self._distrust_name_filters("strong account", recovered)
        else:
            self._secrets = SecretIndex(self._list_all_secrets())
        # Ambiguity must be discovered before any account or target-set write.
        for account in accounts:
            self._secrets.find(account)

    def _snapshot_principals(self) -> None:
        self._principal_errors = {}
        if not self._writes("policies"):
            return
        names = dict.fromkeys(name for server, _ in self._rows for name in server.principals)
        for name in names:
            try:
                self.resolver.resolve(name)
            except ResolveError as exc:
                # A valid empty search is a known per-row missing principal. A
                # malformed/ambiguous directory result cannot authorize a write.
                if "not found" not in str(exc).lower():
                    raise
                self._principal_errors[name.casefold()] = exc

    def _snapshot_target_sets(self, names: list[str], accounts: list[StrongAccountRow]) -> None:
        self._target_sets = {}
        if not names:
            return
        caps = getattr(self.sia, "capabilities", None)
        unfiltered = True if caps is None else bool(caps.targetsets_list_unfiltered)
        items: list[dict[str, Any]] = []
        if self._lookup_mode == "search" and unfiltered and self._filters_trusted():
            for chunk in self._parallel(names, lambda n: self.sia.list_target_sets(name=n)):
                items.extend(chunk)
            # As for strong accounts, an empty name-filtered read is not proof of absence: confirm every wanted
            # name still missing against one unfiltered listing before it becomes a bulk create, which on a set
            # that exists is either a false failure or a write to an object this run never inspected.
            missing = set(names) - {str(pick(ts, "name", default="")).lower() for ts in items}
            if missing:
                listing = self.sia.list_target_sets()
                recovered = [ts for ts in listing
                             if str(pick(ts, "name", default="")).lower() in missing]
                # Keep conflicting evidence for names already found, too: discarding it would bypass the
                # identity/signature ambiguity check below.
                items.extend(listing)
                if recovered:
                    self._distrust_name_filters("target set",
                                                sorted({str(pick(ts, "name")) for ts in recovered}, key=str.lower))
        elif unfiltered:
            items = self.sia.list_target_sets()
        else:
            secret_ids = sorted({sid for s in (self._secrets.find(a) for a in accounts) if s
                                 for sid in (secret_id_of(s),) if sid})
            for chunk in self._parallel(secret_ids, lambda sid: self.sia.list_target_sets(strong_account_id=sid)):
                items.extend(chunk)
            missing = set(names) - {str(pick(ts, "name", default="")).lower() for ts in items}
            if missing:
                # Absence under the desired account does not establish global absence: a set may still point
                # at an old account outside this wave. Read the remaining tenant accounts before any create.
                listing = self._list_all_secrets()
                for secret in listing:
                    self._secrets.add(secret)
                for account in accounts:
                    self._secrets.find(account)
                remaining_ids = sorted({sid for secret in listing if (sid := secret_id_of(secret))}
                                       - set(secret_ids))
                for chunk in self._parallel(remaining_ids, lambda sid: self.sia.list_target_sets(strong_account_id=sid)):
                    items.extend(chunk)
        for ts in items:
            name = str(pick(ts, "name", default="")).lower()
            if name:
                previous = self._target_sets.get(name)
                if previous is not None:
                    old_id = pick(previous, "id", "targetSetId", "target_set_id")
                    new_id = pick(ts, "id", "targetSetId", "target_set_id")
                    distinct_ids = old_id is not None and new_id is not None and str(old_id) != str(new_id)
                    if distinct_ids or target_set_signature(previous) != target_set_signature(ts):
                        raise ReconcileError(f"ambiguous target set {name!r}: the tenant returned conflicting identities or definitions; resolve them before applying")
                self._target_sets[name] = ts

    def _snapshot_policies(self, fqdns: list[str]) -> None:
        self._owned_by_fqdn = None
        # The UAP client stops trusting q= on its own once a template or conflict lookup was confirmed by the listing.
        if self._lookup_mode == "search" and self._filters_trusted() and getattr(self.uap, "search_reliable", True):
            # q= searches name + description: the FQDN finds policies named after the server (and renamed ones whose
            # description still names it); rows with a custom policy_name are searched by that name as well.
            queries = list(dict.fromkeys(fqdns))
            for server, sr in self._rows:
                if server.fqdn.lower() not in sr.policy_name.lower() and sr.policy_name not in queries:
                    queries.append(sr.policy_name)
            seen: dict[str, dict[str, Any]] = {}
            for chunk in self._parallel(queries, lambda f: self.uap.find_policies_for_fqdn(f)):
                for policy in chunk:
                    pid = str(pick(policy.get("metadata") or {}, "policyId", "policy_id", default="")) or str(id(policy))
                    seen.setdefault(pid, policy)
            found_names = self._policies_by_name(list(seen.values()))
            if any(sr.policy_name.casefold() not in found_names for _, sr in self._rows):
                # q= can fail independently of SIA's filters. A renamed owned policy cannot trigger the
                # same-name 409 recovery, so confirm before deciding to create and rebuild both indexes below.
                for policy in self.uap.list_policies(filter_query=UAP_VM_FILTER):
                    pid = str(pick(policy.get("metadata") or {}, "policyId", "policy_id", default="")) or str(id(policy))
                    seen.setdefault(pid, policy)
            self._policy_list = list(seen.values())
        else:
            filter_query = UAP_VM_FILTER if self.adopt_all else owned_vm_filter(self.defaults.owner_tag)
            self._policy_list = self.uap.list_policies(filter_query=filter_query)
        self._policies = self._policies_by_name(self._policy_list)
        wanted = {sr.policy_name.casefold() for _, sr in self._rows}
        required = ("principals", "targets", "conditions", "behavior")
        incomplete = []
        for name in sorted(wanted):
            policy = self._policies.get(name)
            if policy is not None and policy.get("principals") is None:
                incomplete.append(name)
            elif policy is not None and self.drift and any(policy.get(key) is None for key in required):
                incomplete.append(name)
        # One GET per existing policy: with --drift over a large tenant this dominates the snapshot, so fan out.
        # A principal-less list projection must also bypass _full_policy's targets-only shortcut: principals are part
        # of the lightweight safety check, so their absence is not permission to report the policy as up to date.
        fetched = self._parallel(incomplete, lambda n: self._full_policy(self._policies[n], force=True))
        for name, full in zip(incomplete, fetched, strict=True):
            self._policies[name] = full
        if any(sr.policy_name.casefold() not in self._policies for _, sr in self._rows):
            self._owned_by_fqdn = self._build_owned_index()
            claimed: dict[str, set[str]] = {}
            for server, sr in self._rows:
                claimed.setdefault(server.fqdn, set()).add(sr.policy_name.casefold())
            for server, sr in self._rows:
                if sr.policy_name.casefold() not in self._policies:
                    candidates = [p for p in self._owned_by_fqdn.get(server.fqdn, [])
                                  if html.unescape(str(p.get("metadata", {}).get("name", ""))).casefold() not in claimed[server.fqdn]]
                    if len(candidates) > 1:
                        raise ReconcileError(f"ambiguous managed policies for {server.fqdn}; resolve renamed policies before applying")

    # ------------------------------------------------------------ helpers
    def _writes(self, stage: str) -> bool:
        return self.only in ("all", stage)

    def _adopted(self, server: ServerRow, sr: ServerResult) -> bool:
        return self.adopt_all or server.fqdn.lower() in self.adopt or sr.policy_name.lower() in self.adopt

    def _adopted_target_set(self, server: ServerRow, sr: ServerResult) -> bool:
        """A shared set has no FQDN of its own, so --adopt also accepts its name. Deliberately not folded into
        _adopted(): naming a domain must not silently adopt every policy in it as well."""
        return self._adopted(server, sr) or server.target_set_key in self.adopt

    def _abort(self, reason: str) -> None:
        self._stop.set()
        with self._lock:
            if self._abort_reason is None:
                self._abort_reason = reason
                if self._result is not None:
                    self._result.aborted.append(reason)
                self._log.error("Aborting run (fail-fast): %s", reason)

    def _blocked_by_abort(self) -> Outcome:
        return Outcome("blocked", f"run stopped before this operation: {self._abort_reason}")

    def _systematic(self, exc: SIAApiError) -> bool:
        return self.fail_fast and exc.client_error and exc.status not in NON_SYSTEMATIC_4XX

    @staticmethod
    def _error_status(exc: SIAApiError) -> str:
        return "uncertain" if exc.uncertain else "failed"

    @staticmethod
    def _exception_outcome(status: str, detail: str, exc: BaseException, *, stage: str,
                           object_name: str, ref: str | None = None,
                           mutation_state: str | None = None) -> Outcome:
        diagnostic = diagnose(exc, stage=stage, object_name=object_name,
                              mutation_state=mutation_state).to_dict()
        return Outcome(status, f"{detail}: {exc}", ref, diagnostic)

    @staticmethod
    def _applied_unverified(detail: str, *, stage: str, object_name: str, ref: str,
                            details: dict[str, Any] | None = None) -> Outcome:
        """A write was accepted, but its read-back did not prove that the requested state converged.

        ``details`` (the read-back's tenant/requested values) goes into the diagnostic: the JSON report always
        carries it and ``--verbose`` prints it under "Technical details"."""
        actions = ["Run plan --drift to reconcile the current tenant state before retrying the write."]
        if details and details.get("differences"):
            actions.append("The detail names each field as tenant -> requested; --verbose or the JSON report shows "
                           "the full values, and `show-policy NAME` prints the raw policy.")
        diagnostic = Diagnostic(
            code="SIA-API-RESPONSE", message=detail, stage=stage, object_name=object_name,
            mutation_state="applied", actions=tuple(actions), details=dict(details or {}),
        ).to_dict()
        return Outcome("unverified", detail, ref, diagnostic)

    def _tick(self, stage: str, total: int) -> None:
        if not self.progress_every:
            return
        with self._lock:
            counter = self._progress.setdefault(stage, [0])
            counter[0] += 1
            done = counter[0]
        if done % self.progress_every == 0 or done == total:
            elapsed = int(time.monotonic() - self._started)
            self._log.info("%s: %d/%d done, %dm%02ds elapsed", stage, done, total, elapsed // 60, elapsed % 60)

    def _execute(self, items: list, worker: Callable[[Any], None], stage: str = "", canary: bool = True) -> None:
        """Bound queued work; stop immediately on a worker error and collect in-flight results."""
        if not items:
            return
        total = len(items)

        def wrapped(item: Any) -> None:
            try:
                worker(item)
            except (Exception, KeyboardInterrupt) as exc:
                with self._lock:
                    if self._fatal_error is None:
                        self._fatal_error = exc
                self._abort("Interrupted by operator" if isinstance(exc, KeyboardInterrupt) else str(exc))
                raise
            if stage:
                self._tick(stage, total)

        rest = items
        if canary:
            wrapped(items[0])
            rest = items[1:]
        if not rest:
            return
        if self.workers <= 1 or self._stop.is_set():
            for item in rest:
                wrapped(item)
            return
        pool = ThreadPoolExecutor(max_workers=min(self.workers, len(rest)), thread_name_prefix="sia")
        pending = set()
        index = 0
        error: BaseException | None = None
        try:
            while index < len(rest) or pending:
                while index < len(rest) and len(pending) < self.workers and not self._stop.is_set():
                    pending.add(pool.submit(wrapped, rest[index]))
                    index += 1
                if not pending:
                    break
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    future.result()
        except (Exception, KeyboardInterrupt) as exc:
            error = exc if isinstance(exc, KeyboardInterrupt) else self._fatal_error or exc
            self._abort("Interrupted by operator" if isinstance(error, KeyboardInterrupt) else str(error))
            for future in pending:
                future.cancel()
        finally:
            # A request already sent cannot safely be undone. Let it finish within
            # its HTTP timeout so its confirmed result is retained in the report.
            pool.shutdown(wait=True, cancel_futures=True)
        if error is not None:
            raise error
        if self._fatal_error is not None:
            raise self._fatal_error
        # A systematic rejection is a normal run outcome. Mark unscheduled work
        # blocked using the existing workers' no-write abort branches.
        for item in rest[index:]:
            wrapped(item)

    def _flag_duplicate_policy_names(self, result: RunResult) -> None:
        by_name: dict[str, list[ServerResult]] = {}
        for _, sr in self._rows:
            by_name.setdefault(sr.policy_name, []).append(sr)
        for name, group in by_name.items():
            if len(group) > 1:
                fqdns = ", ".join(sr.fqdn for sr in group)
                for sr in group:
                    sr.policy = Outcome("failed", f"duplicate policy name {name!r} for {fqdns}; set policy_name or policy_suffix per row")

    def _load_template(self) -> dict[str, Any] | None:
        name = self.defaults.template_policy
        if not name:
            return None
        found = self.uap.find_policy_by_name(name)
        if not found:
            raise ReconcileError(f"template_policy {name!r} not found in UAP; create it in the SIA UI or clear the setting")
        policy_id = pick(found.get("metadata") or {}, "policyId", "policy_id")
        template = self.uap.get_policy(str(policy_id)) if policy_id else found
        problems = validate_template(template)
        if problems:
            raise ReconcileError(f"template_policy {name!r} is not usable as a template: " + "; ".join(problems))
        self._log.info("Cloning approved fields (conditions, connection profiles, timeZone, tags) from template policy %r", name)
        return sanitize_template(template)

    @staticmethod
    def _policies_by_name(policies: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for policy in policies:
            name = (policy.get("metadata") or {}).get("name")
            if name:
                key = html.unescape(str(name)).casefold()
                previous = out.get(key)
                if previous is not None:
                    old_id = pick(previous.get("metadata") or {}, "policyId", "policy_id")
                    new_id = pick(policy.get("metadata") or {}, "policyId", "policy_id")
                    if not old_id or not new_id or str(old_id) != str(new_id):
                        raise ReconcileError(f"ambiguous policy name {name!r}: multiple tenant object IDs; resolve them before applying")
                out[key] = policy
        return out

    def _full_policy(self, policy: dict[str, Any], *, force: bool = False) -> dict[str, Any]:
        if "targets" in policy and not force:
            return policy
        policy_id = pick(policy.get("metadata") or {}, "policyId", "policy_id")
        return self.uap.get_policy(str(policy_id)) if policy_id else policy

    def _owned_policy_for_fqdn(self, fqdn: str, claimed: set[str]) -> dict[str, Any] | None:
        """A managed policy (owner tag) whose EXACTLY rule targets this FQDN and whose name is not one this server's
        rows already use (`claimed` holds casefolded names) -- i.e. our policy under another name. Candidates without targets in the list object are
        fetched in full only when their description mentions the FQDN."""
        if self._owned_by_fqdn is None:
            with self._lock:
                if self._owned_by_fqdn is None:
                    self._owned_by_fqdn = self._build_owned_index()
        matches = [m for m in self._owned_by_fqdn.get(fqdn.lower(), [])
                   if html.unescape(str((m.get("metadata") or {}).get("name") or "")).casefold() not in claimed]
        if len(matches) > 1:
            names = ", ".join(repr((m.get("metadata") or {}).get("name")) for m in matches)
            assert self._result is not None
            self._result.warnings.append(f"{fqdn}: several managed policies target it ({names}); resolve manually")
            return None
        return matches[0] if matches else None

    def _build_owned_index(self) -> dict[str, list[dict[str, Any]]]:
        index: dict[str, list[dict[str, Any]]] = {}
        wanted = {s.fqdn.lower() for s, _ in self._rows}
        for policy in self._policy_list:
            if not is_owned_policy(policy, self.defaults.owner_tag):
                continue
            full = policy
            if "targets" not in policy:
                description = str((policy.get("metadata") or {}).get("description") or "").lower()
                if not any(f in description for f in wanted):
                    continue
                full = self._full_policy(policy)
            for target in exact_fqdns(full):
                index.setdefault(target, []).append(full)
        return index

    def _checkpoint_row(self, server: ServerRow, sr: ServerResult) -> None:
        if self.checkpoint is None or self.dry_run:
            return
        account = self.inputs.strong_accounts.get(server.strong_account or "")
        try:
            self.checkpoint.record(
                row_key(sr.fqdn, sr.policy_name), fingerprint(server, account, sr.policy_name, self._checkpoint_context),
                {"secret": sr.secret.status, "target_set": sr.target_set.status, "policy": sr.policy.status},
                {"secret": sr.secret.ref, "target_set": sr.target_set.ref, "policy": sr.policy.ref})
        except Exception as exc:
            self._abort(f"Checkpoint saving failed: {exc}")
            raise

    def _password_for(self, account: StrongAccountRow) -> str | None:
        password = self._get_password(account)
        if password:
            register_secret(password)
        return password

    # -------------------------------------------------------------- vault
    def _ensure_vault(self, result: RunResult) -> None:
        """Optional: make sure type=vault accounts exist in the Vault (PVWA), onboarding the missing ones."""
        accounts = [a for a in self._active_accounts() if a.type == "vault"]
        if self.pvwa is None:
            if self.only == "vault":
                result.warnings.append("[pvwa] is not configured; the vault stage cannot run")
            return
        # Preview and apply share a client, but each pass must observe changes made during confirmation.
        self.pvwa.reset_lookup_cache()
        to_create: list[tuple[StrongAccountRow, dict[str, Any], str]] = []
        for account in accounts:
            what = f"Vault account {account.account_name!r} in safe {account.safe!r}"
            try:
                found = self.pvwa.find_account(account.safe or "", account.account_name or "")
            except SIAApiError as exc:
                result.vault[account.name] = self._exception_outcome(
                    "failed", "lookup failed", exc, stage="vault lookup", object_name=account.name)
                continue
            if found:
                if not isinstance(found, dict) or not isinstance(found.get("id"), str) or not found["id"].strip():
                    result.vault[account.name] = Outcome("unverified", f"{what} lookup returned no usable account identifier; no dependent changes will be made")
                    continue
                result.vault[account.name] = Outcome("exists", f"{what} (id {found.get('id')})", str(found.get("id") or ""))
                continue
            if not self._writes("vault"):
                result.vault[account.name] = Outcome("skipped", f"missing; onboarding disabled by --only {self.only}")
                continue
            address = account.address or self._address_for(account)
            if not account.username:
                result.vault[account.name] = Outcome("failed", f"{what} is missing and has no username to onboard it with "
                                                               "(set strong_account_username_template or the username column)")
                continue
            password = self._password_for(account)
            if not password:
                if self.dry_run:
                    result.vault[account.name] = Outcome("planned", f"would onboard {what} for {address} (password from the password file, not available now)")
                    continue
                result.vault[account.name] = Outcome(
                    "failed", f"{what} is missing and its current password is not available: add {account.name!r} to the password file")
                continue
            if self.dry_run:
                result.vault[account.name] = Outcome("planned", f"would onboard {what} for {address} (platform {self.pvwa_platform_id})")
                continue
            payload = build_vault_account(account, password, platform_id=self.pvwa_platform_id, address=address,
                                          cpm_managed=self.pvwa_cpm_managed)
            to_create.append((account, payload, what))
        self._execute(to_create, self._onboard_vault_account, stage="vault")

    def _address_for(self, account: StrongAccountRow) -> str:
        if not account.is_local:
            return account.account_domain
        for server, _ in self._rows:
            if server.strong_account == account.name:
                return server.fqdn
        return ""

    def _onboard_vault_account(self, item: tuple[StrongAccountRow, dict[str, Any], str]) -> None:
        account, payload, what = item
        assert self._result is not None
        if self._abort_reason:
            self._result.vault[account.name] = self._blocked_by_abort()
            return
        try:
            self.check_cancelled()
            self._result.vault[account.name] = Outcome("uncertain", "Vault create started; response not yet confirmed")
            created = self.pvwa.add_account(payload)
            if (not isinstance(created, dict) or not isinstance(created.get("id"), str) or not created["id"].strip()
                    or str(created.get("name", "")).casefold() != str(payload.get("name", "")).casefold()
                    or str(created.get("safeName", "")).casefold() != str(payload.get("safeName", "")).casefold()):
                raise SIAApiError("POST", "/PasswordVault/api/Accounts", 201,
                                  "Vault account response is missing its identifier or does not match the requested name/safe; reconcile before retrying",
                                  uncertain=True)
        except WriteCancelled:
            self._result.vault[account.name] = self._blocked_by_abort()
            return
        except SIAApiError as exc:
            self._result.vault[account.name] = self._exception_outcome(
                self._error_status(exc), "onboarding failed", exc,
                stage="vault account create", object_name=account.name)
            if self._systematic(exc):
                self._abort(f"onboarding {what}: {exc}")
            return
        self._result.vault[account.name] = Outcome("created", f"onboarded {what} (id {created.get('id')})", str(created.get("id") or ""))

    # ------------------------------------------------------------ secrets
    def _ensure_secrets(self, result: RunResult) -> None:
        """Fills self._refs {strong account name: (secret_id or None if only planned, secret_type)}."""
        to_create: list[tuple[StrongAccountRow, dict[str, Any], str]] = []
        for account in self._active_accounts():
            vault_outcome = result.vault.get(account.name)
            if vault_outcome is not None and vault_outcome.bad:
                result.secrets[account.name] = Outcome("blocked", f"Vault account unavailable: {vault_outcome.detail}")
                continue
            found = self._secrets.find(account)
            if found:
                sid, stype = secret_id_of(found), secret_type_of(found)
                detail = f"{stype} secret {sid} ({account.sia_name})"
                if account.secret_type and stype and account.secret_type != stype:
                    result.warnings.append(f"strong account {account.name!r}: CSV type={account.type} but SIA has {stype}; using SIA's type")
                if not sid:
                    result.secrets[account.name] = Outcome(
                        "unverified", f"strong account {account.sia_name!r} was returned without a usable secret id; "
                                      "target-set and policy changes are blocked")
                    continue
                if not stype:
                    result.secrets[account.name] = Outcome(
                        "unverified", f"strong account {account.sia_name!r} ({sid}) has no secret type; "
                                      "target-set and policy changes are blocked", sid)
                    continue
                if pick(found, "is_active", "isActive", default=True) is False:
                    result.secrets[account.name] = Outcome(
                        "inactive", f"{detail} is inactive; activate it in SIA before reconciling dependent target sets", sid)
                    continue
                result.secrets[account.name] = Outcome("exists", detail, sid)
                self._refs[account.name] = (sid, stype)
                continue
            if vault_outcome is not None and vault_outcome.bad:
                result.secrets[account.name] = Outcome("blocked", f"Vault account unavailable: {vault_outcome.detail}")
                continue
            if account.type == "existing":
                result.secrets[account.name] = Outcome(
                    "failed", f"no strong account named {account.sia_name!r} in SIA (type=existing): create it in the SIA UI "
                              "or use type=vault/credentials")
                continue
            if not self._writes("secrets"):
                result.secrets[account.name] = Outcome("skipped", f"missing; creation disabled by --only {self.only}")
                continue
            what = (f"{account.secret_type} strong account {account.sia_name!r} "
                    + (f"(safe={account.safe} account={account.account_name})" if account.type == "vault"
                       else f"(user={account.username} domain={account.account_domain})"))
            password = None
            if account.type == "credentials":
                password = self._password_for(account)
                if not password and self.dry_run:
                    result.secrets[account.name] = Outcome("planned", f"would create {what}; password from env var {account.password_env} or the password file (not available now)")
                    self._refs[account.name] = (None, account.secret_type or "")
                    continue
                if not password:
                    result.secrets[account.name] = Outcome(
                        "failed", f"password not available: set env var {account.password_env}, add {account.name!r} to the password file, "
                                  "or run interactively to be prompted")
                    continue
            if self.dry_run:
                result.secrets[account.name] = Outcome("planned", f"would create {what}")
                self._refs[account.name] = (None, account.secret_type or "")
                continue
            to_create.append((account, build_secret_payload(account, password), what))
        self._execute(to_create, self._create_secret, stage="strong accounts")

    def _create_secret(self, item: tuple[StrongAccountRow, dict[str, Any], str]) -> None:
        account, payload, what = item
        assert self._result is not None
        if self._abort_reason:
            self._result.secrets[account.name] = self._blocked_by_abort()
            return
        try:
            self.check_cancelled()
            self._result.secrets[account.name] = Outcome("uncertain", "Strong-account create started; response not yet confirmed")
            created = self.sia.create_secret(payload)
        except WriteCancelled:
            self._result.secrets[account.name] = self._blocked_by_abort()
            return
        except SIAApiError as exc:
            self._result.secrets[account.name] = self._exception_outcome(
                self._error_status(exc), "create failed", exc,
                stage="strong account create", object_name=account.name)
            if self._systematic(exc):
                self._abort(f"creating strong account {account.name!r}: {exc}")
            return
        sid = secret_id_of(created)
        stype = secret_type_of(created) or account.secret_type or ""
        if not sid or not stype:
            self._result.secrets[account.name] = Outcome(
                "unverified", f"create returned without a usable secret id and type for {what}; run plan to reconcile")
            return
        self._result.secrets[account.name] = Outcome("created", f"created {what} -> {sid}", sid)
        with self._lock:
            self._secrets.add(created)
            self._refs[account.name] = (sid, stype)

    # -------------------------------------------------------- target sets
    def _rows_by_target_set(self) -> dict[str, list[tuple[ServerRow, ServerResult]]]:
        """Windows rows grouped by the target set they need. One Domain set can cover a whole AD domain, so a group
        may span several FQDNs; every row in a group shares one strong account (the inputs guarantee it)."""
        out: dict[str, list[tuple[ServerRow, ServerResult]]] = {}
        for server, sr in self._rows:
            if not server.is_ssh:
                out.setdefault(server.target_set_key, []).append((server, sr))
        return out

    def _ensure_target_sets(self, result: RunResult) -> None:
        # Pass 1: the strong account is per row.
        for server, sr in self._rows:
            if server.is_ssh:
                sr.secret = Outcome(NOT_APPLICABLE, "SSH: Linux ZSP uses an SSH certificate; no strong account")
                sr.target_set = Outcome(NOT_APPLICABLE, "SSH: no target set needed")
                continue
            found = result.secrets.get(server.strong_account or "", Outcome("failed", "strong account missing"))
            sr.secret = Outcome(found.status, found.detail, found.ref, found.diagnostic)
        # Pass 2: the target set is per target-set name, and its outcome is copied to every server that uses it.
        queue: dict[str, list[dict[str, Any]]] = {}
        queued: dict[str, list[ServerResult]] = {}
        for rows in self._rows_by_target_set().values():
            server = rows[0][0]
            results = [sr for _, sr in rows]
            name = target_set_name_for(server)
            shared = f" (shared by every server in {name})" if server.shares_target_set else ""
            if results[0].secret.bad or results[0].secret.status == "skipped":
                self._set_all(results, target_set=Outcome("blocked", f"strong account {server.strong_account!r} unavailable"))
                continue
            secret_id, secret_type = self._refs[server.strong_account or ""]
            current = self._target_sets.get(server.target_set_key)
            if current:
                outcome = self._reconcile_existing_target_set(server, results[0], current, secret_id, secret_type, result)
                self._set_all(results, target_set=outcome)
                continue
            if not self._writes("targetsets"):
                self._set_all(results, target_set=Outcome("skipped", f"missing; creation disabled by --only {self.only}"))
                continue
            if self._abort_reason:
                self._set_all(results, target_set=self._blocked_by_abort())
                continue
            if self.dry_run or secret_id is None:
                self._set_all(results, target_set=Outcome(
                    "planned", f"would create {server.target_set_type} set {name} -> {server.strong_account}{shared}", name))
                continue
            queue.setdefault(secret_id, []).append(build_target_set(server, secret_id, secret_type, self.defaults))
            queued[name] = results
        if queue:
            self._bulk_create(queue, queued)

    @staticmethod
    def _set_all(results: list[ServerResult], *, secret: Outcome | None = None, target_set: Outcome | None = None) -> None:
        for sr in results:
            if secret is not None:
                sr.secret = Outcome(secret.status, secret.detail, secret.ref, secret.diagnostic)
            if target_set is not None:
                sr.target_set = Outcome(target_set.status, target_set.detail, target_set.ref, target_set.diagnostic)

    def _reconcile_existing_target_set(self, server: ServerRow, sr: ServerResult, current: dict[str, Any],
                                       secret_id: str | None, secret_type: str, result: RunResult) -> Outcome:
        name = target_set_name_for(server)
        expected_type = server.target_set_type or "Target"
        current_secret = pick(current, "secret_id", "secretId")
        ts_type = pick(current, "type", default=expected_type)
        owned = is_owned_target_set(current, self.defaults.owner_tag)
        if str(ts_type) != expected_type:
            result.warnings.append(f"target set {name!r} exists with type={ts_type} (expected {expected_type})")
        if not secret_id:
            # Dry run with a strong account that is only planned: it does not exist yet, so this set necessarily
            # points at another secret. Report what apply will find instead of a misleading "exists".
            summary = (f"points to secret {current_secret or '?'}; strong account {server.strong_account!r} "
                       "does not exist yet")
            if server.shares_target_set:
                summary += f"; re-pointing it moves every server in {name}"
            if not (self.update and self._writes("targetsets")):
                return Outcome("drift", f"{summary} (use --update to re-point it once the account is created)", name)
            if not (owned or self._adopted_target_set(server, sr)):
                return Outcome("drift", f"{summary}; not managed by this tool -- pass --adopt {name} to take ownership", name)
            return Outcome("planned", f"would re-point target set {name} to {server.strong_account} after creating the account", name)
        desired = build_target_set_update(server, secret_id, secret_type, self.defaults, current)
        current_sig, desired_sig = target_set_signature(current), target_set_signature(desired)
        keys = ("secret_id", "type", "secret_type", "description", "certificate_validation", "provision_format") if self.drift else ("secret_id",)
        labels = {
            "type": "type differs", "secret_type": "secret type differs", "description": "description differs",
            "certificate_validation": "certificate validation differs", "provision_format": "provision format differs",
        }
        differences: list[str] = []
        for key in keys:
            if current_sig[key] == desired_sig[key]:
                continue
            if key == "secret_id":
                differences.append(f"points to secret {current_secret}, expected {secret_id} ({server.strong_account})")
            else:
                differences.append(labels[key])
        if not differences:
            note = "" if owned else " (unmanaged: no owner marker)"
            checked = "all managed fields" if self.drift else "strong account"
            return Outcome("exists", f"{ts_type} -> {server.strong_account} ({checked} checked){note}", name)
        summary = "; ".join(differences)
        if server.shares_target_set:
            summary += f"; re-pointing it moves every server in {name}"
        if not (self.update and self._writes("targetsets")):
            return Outcome("drift", f"{summary} (use --update to re-point)", name)
        if not (owned or self._adopted_target_set(server, sr)):
            return Outcome("drift", f"{summary}; not managed by this tool -- pass --adopt {name} to take ownership", name)
        if self._abort_reason:
            return self._blocked_by_abort()
        if self.dry_run:
            return Outcome("planned", f"would re-point target set {name} to {server.strong_account} ({secret_id})", name)
        try:
            self.check_cancelled()
            for _, pending in self._rows:
                if pending.target_set_key == server.target_set_key:
                    pending.target_set = Outcome("uncertain", "Target-set update started; response not yet confirmed", name)
            self.sia.update_target_set(name, desired)
        except WriteCancelled:
            return self._blocked_by_abort()
        except SIAApiError as exc:
            if self._systematic(exc):
                self._abort(f"updating target set {name}: {exc}")
            return self._exception_outcome(
                self._error_status(exc), "update failed", exc,
                stage="target set update", object_name=name, ref=name)
        accepted = self._applied_unverified(
            f"Target-set update for {name} was accepted; read-back not yet complete",
            stage="target set read-back", object_name=name, ref=name)
        for _, pending in self._rows:
            if pending.target_set_key == server.target_set_key:
                pending.target_set = Outcome(
                    accepted.status, accepted.detail, accepted.ref, accepted.diagnostic)
        try:
            read_back, mismatch = self._poll_target_set(name, desired, secret_id)
        except SIAApiError as exc:
            return self._exception_outcome(
                "unverified", f"target set {name} update was accepted, but read-back failed", exc,
                stage="target set read-back", object_name=name, ref=name, mutation_state="applied")
        if mismatch:
            return self._applied_unverified(
                f"target set {name} update was accepted, but read-back {mismatch}",
                stage="target set read-back", object_name=name, ref=name)
        assert read_back is not None
        return Outcome("updated", f"updated target set {name}: {summary}", name)

    def _poll_target_set(self, name: str, desired: dict[str, Any], secret_id: str) -> tuple[dict[str, Any] | None, str]:
        """Read an updated target set until its exact name and normalized writable fields match the PUT payload."""
        wanted_name = name.casefold()
        wanted_signature = self._verified_target_set_signature(desired)
        last_mismatch = "did not return the requested target set"
        for attempt in range(self.status_polls):
            try:
                rows = self._read_back_target_set(name, secret_id)
            except SIAApiError:
                if attempt >= self.status_polls - 1:
                    raise
                self._sleep(POLICY_STATUS_POLL_SECONDS)
                continue
            exact = [row for row in rows
                     if str(pick(row, "name", default="")).casefold() == wanted_name]
            if len(exact) == 1:
                try:
                    actual_signature = self._verified_target_set_signature(exact[0])
                except (AttributeError, TypeError, ValueError):
                    last_mismatch = "returned a malformed target-set object"
                else:
                    if actual_signature == wanted_signature:
                        return exact[0], ""
                    changed = [key.replace("_", " ") for key in wanted_signature
                               if actual_signature.get(key) != wanted_signature[key]]
                    last_mismatch = "still differs in " + ", ".join(changed)
            elif len(exact) > 1:
                last_mismatch = f"returned {len(exact)} exact-name matches"
            if attempt < self.status_polls - 1:
                self._sleep(POLICY_STATUS_POLL_SECONDS)
        return None, last_mismatch

    def _read_back_target_set(self, name: str, secret_id: str) -> list[dict[str, Any]]:
        """The strong account's target sets, narrowed to `name` while the tenant's name filter can be trusted.
        strong_account_id is load-bearing (a set re-pointed at another account must stay invisible); name= only
        saves pages on an account with many sets, so an empty name-filtered read is confirmed against the account's
        listing rather than reported as an unverified write."""
        if self._filters_trusted():
            rows = self.sia.list_target_sets(name=name, strong_account_id=secret_id)
            if rows:
                return rows
        return self.sia.list_target_sets(strong_account_id=secret_id)

    @staticmethod
    def _verified_target_set_signature(target_set: dict[str, Any]) -> dict[str, Any]:
        """Normalize a target set without coercing malformed certificate-validation values to truthy booleans."""
        for key in ("enable_certificate_validation", "enableCertificateValidation"):
            if key in target_set and not isinstance(target_set[key], bool):
                raise TypeError(f"{key} is not a boolean")
        return target_set_signature(target_set)

    def _bulk_create(self, queue: dict[str, list[dict[str, Any]]], queued: dict[str, list[ServerResult]]) -> None:
        total = sum(len(sets) for sets in queue.values())
        for secret_id, sets in queue.items():
            for start in range(0, len(sets), BULK_CHUNK):
                chunk = sets[start:start + BULK_CHUNK]
                names = [ts["name"] for ts in chunk]
                if self._abort_reason:
                    for name in names:
                        self._set_all(queued[name], target_set=self._blocked_by_abort())
                    continue
                try:
                    self.check_cancelled()
                    for name in names:
                        self._set_all(queued[name], target_set=Outcome("uncertain", "Target-set create started; response not yet confirmed", name))
                    outcomes = self.sia.bulk_create_target_sets(build_bulk_target_sets({secret_id: chunk}))
                except WriteCancelled:
                    for name in names:
                        self._set_all(queued[name], target_set=self._blocked_by_abort())
                    continue
                except SIAApiError as exc:
                    for name in names:
                        outcome = self._exception_outcome(
                            self._error_status(exc), "bulk create failed", exc,
                            stage="target set create", object_name=name, ref=name)
                        self._set_all(queued[name], target_set=outcome)
                    if self._systematic(exc):
                        self._abort(f"bulk-creating target sets for strong account {secret_id}: {exc}")
                    continue
                by_name = {str(pick(o, "target_set_name", "targetSetName", default="")).lower(): o for o in outcomes}
                kinds = {ts["name"]: ts["type"] for ts in chunk}
                for name in names:
                    item = by_name.get(name.lower())
                    account = queued[name][0].strong_account
                    if item is None:
                        outcome = Outcome("unverified", "bulk create returned no result for this target set; "
                                                        "run plan to check whether it was created", name)
                    elif pick(item, "success", default=False) is True:
                        outcome = Outcome("created", f"{kinds[name]} set {name} -> {account}", name)
                    else:
                        reason = pick(item, "error", "message", "reason", default="rejected by SIA (check the strong account and FQDN)")
                        outcome = Outcome("failed", f"bulk create: {reason}", name)
                    self._set_all(queued[name], target_set=outcome)
                    self._tick("target sets", total)

    # ------------------------------------------------------------ policies
    def _ensure_policies(self, result: RunResult) -> None:
        compare: list[tuple[ServerRow, ServerResult, dict[str, Any], dict[str, Any], bool]] = []
        create: list[tuple[ServerRow, ServerResult, dict[str, Any]]] = []
        claimed_by_fqdn: dict[str, set[str]] = {}
        for server, sr in self._rows:
            claimed_by_fqdn.setdefault(server.fqdn, set()).add(sr.policy_name.casefold())
        for server, sr in self._rows:
            if sr.policy.status == "failed":  # duplicate name
                self._checkpoint_row(server, sr)
                continue
            if sr.target_set.bad and self.only != "policies":
                sr.policy = Outcome("blocked", "target set unavailable (policy would grant access to a server SIA cannot provision)")
                self._checkpoint_row(server, sr)
                continue
            if not self._writes("policies"):
                sr.policy = Outcome("skipped", f"disabled by --only {self.only}")
                continue
            try:
                for name in server.principals:
                    if name.casefold() in self._principal_errors:
                        raise self._principal_errors[name.casefold()]
                principals = [self.resolver.resolve(name) for name in server.principals]
                desired = build_policy(server, principals, self.defaults, self._template)
                if self.set_policy_status is not None:
                    desired["metadata"]["status"] = {"status": self.set_policy_status}
            except (ResolveError, SIAApiError, ValueError) as exc:
                sr.policy = self._exception_outcome(
                    self._error_status(exc) if isinstance(exc, SIAApiError) else "failed",
                    "policy could not be prepared", exc, stage="policy planning", object_name=sr.policy_name)
                self._checkpoint_row(server, sr)
                continue
            existing = self._policies.get(sr.policy_name.casefold())
            renamed = False
            if existing is None:
                existing = self._owned_policy_for_fqdn(server.fqdn, claimed_by_fqdn[server.fqdn])
                renamed = existing is not None
            if existing is not None:
                compare.append((server, sr, existing, desired, renamed))
                continue
            if self._abort_reason:
                sr.policy = self._blocked_by_abort()
                continue
            if self.dry_run:
                sr.policy = Outcome("planned", f"would create {server.protocol.upper()} policy for [{', '.join(server.principals)}] -> {server.fqdn}")
                continue
            create.append((server, sr, desired))
        self._execute(compare, self._compare_policy, stage="policies (existing)", canary=False)
        self._execute(create, self._create_policy, stage="policies")

    def _compare_policy(self, item: tuple[ServerRow, ServerResult, dict[str, Any], dict[str, Any], bool]) -> None:
        server, sr, existing, desired, renamed = item
        self._reconcile_existing_policy(sr, server, existing, desired, renamed)
        self._checkpoint_row(server, sr)

    def _create_policy(self, item: tuple[ServerRow, ServerResult, dict[str, Any]]) -> None:
        server, sr, desired = item
        if self._abort_reason:
            sr.policy = self._blocked_by_abort()
            return
        principals = ", ".join(server.principals)
        try:
            self.check_cancelled()
            sr.policy = Outcome("uncertain", "Policy create started; response not yet confirmed")
            policy_id = self.uap.create_policy(desired)
        except WriteCancelled:
            sr.policy = self._blocked_by_abort()
            return
        except SIAApiError as exc:
            if self._is_conflict(exc) and self._reclassify_conflict(server, sr, desired):
                self._checkpoint_row(server, sr)
                return
            sr.policy = self._exception_outcome(
                self._error_status(exc), "create failed", exc,
                stage="policy create", object_name=sr.policy_name)
            if self._systematic(exc):
                self._abort(f"creating policy {sr.policy_name!r}: {exc}")
            self._checkpoint_row(server, sr)
            return
        with self._lock:
            self._policies[sr.policy_name.casefold()] = {**desired, "metadata": {**desired["metadata"], "policyId": policy_id}}
        sr.policy = self._applied_unverified(
            "Policy create accepted; read-back not yet complete",
            stage="policy read-back", object_name=sr.policy_name, ref=policy_id)
        expected_status = self.set_policy_status or self.defaults.policy_status
        try:
            _read_back, status, description, mismatch, differences = self._poll_policy(policy_id, desired, expected_status)
        except SIAApiError as exc:
            sr.policy = self._exception_outcome(
                "unverified", f"policy {policy_id} may have been created, but read-back failed", exc,
                stage="policy read-back", object_name=sr.policy_name, ref=policy_id, mutation_state="applied")
            self._checkpoint_row(server, sr)
            return
        detail = f"{server.protocol.upper()} policy {policy_id} for [{principals}], status={status}"
        if status.lower() == "error":
            sr.policy = Outcome("failed", f"{detail}: {description}", policy_id)
        elif status != expected_status or mismatch:
            suffix = f": {description}" if description else ""
            problems = []
            if status != expected_status:
                problems.append(f"requested status was {expected_status}")
            if mismatch:
                problems.append(f"read-back {mismatch}")
            sr.policy = self._applied_unverified(
                f"{detail}{suffix}; " + "; ".join(problems),
                stage="policy read-back", object_name=sr.policy_name, ref=policy_id,
                details={"policy_id": policy_id, "status": status, "requested_status": expected_status,
                         "differences": differences})
        else:
            sr.policy = Outcome("created", detail, policy_id)
        self._checkpoint_row(server, sr)

    @staticmethod
    def _is_conflict(exc: SIAApiError) -> bool:
        body = exc.body.lower()
        return exc.status == 409 or (exc.status == 400 and any(word in body for word in _CONFLICT_WORDS))

    def _reclassify_conflict(self, server: ServerRow, sr: ServerResult, desired: dict[str, Any]) -> bool:
        """A create that hit "name already exists" (e.g. a policy the tag filter hid): compare instead of failing."""
        try:
            found = self.uap.find_policy_by_name(sr.policy_name)
        except SIAApiError:
            return False
        if not found:
            return False
        with self._lock:
            self._policies[sr.policy_name.casefold()] = found
        self._reconcile_existing_policy(sr, server, found, desired, False)
        return True

    def _reconcile_existing_policy(self, sr: ServerResult, server: ServerRow, existing: dict[str, Any],
                                   desired: dict[str, Any], renamed: bool) -> None:
        policy_id = str(pick(existing.get("metadata") or {}, "policyId", "policy_id", default=""))
        if not policy_id:
            sr.policy = Outcome("unverified", f"existing policy {sr.policy_name!r} has no usable policy id; "
                                               "it cannot be safely read or updated")
            return
        full = existing
        wants_full = self.drift or self.set_policy_status is not None or renamed or existing.get("principals") is None
        required_blocks = ("principals", "targets", "conditions", "behavior") if self.drift else ("targets",)
        missing_principals = existing.get("principals") is None
        if missing_principals or (wants_full and any(existing.get(key) is None for key in required_blocks)):
            try:
                full = self._full_policy(existing, force=True)
            except SIAApiError as exc:
                sr.policy = self._exception_outcome(
                    "failed", f"could not read existing policy {policy_id}", exc,
                    stage="policy lookup", object_name=sr.policy_name, ref=policy_id)
                return
        if full.get("principals") is None:
            sr.policy = Outcome("unverified", f"policy {policy_id} full response is missing principals; "
                                                 "cannot confirm who has access or safely update", policy_id)
            return
        if self.drift and any(full.get(key) is None for key in required_blocks):
            missing = ", ".join(key for key in required_blocks if full.get(key) is None)
            sr.policy = Outcome("unverified", f"policy {policy_id} full response is missing {missing}; cannot confirm settings or safely update", policy_id)
            return
        owned = is_owned_policy(full, self.defaults.owner_tag)
        adopted = self._adopted(server, sr)
        current_sig, desired_sig = policy_signature(full), policy_signature(desired)
        diff: list[str] = []
        checked = ["name"]
        if renamed:
            diff.append(f"named {(full.get('metadata') or {}).get('name')!r} instead of {sr.policy_name!r} (renamed)")
        compare_keys = ("principals", "fqdn_rules")
        if self.drift:
            compare_keys = tuple(key for key in desired_sig if key != "name")
        labels = {
            "description": "description differs", "time_frame": "time frame differs",
            "entitlement": "policy entitlement differs", "tags": "policy tags differ",
            "time_zone": "time zone differs", "principals": "principals differ",
            "principal_details": "principal directory details differ",
            "delegation": "delegation classification differs", "conditions": "access conditions differ",
            "fqdn_rules": "FQDN rules differ", "behavior": "connection behavior differs",
        }
        for key in compare_keys:
            if current_sig.get(key) is None:
                continue
            checked.append("targets" if key == "fqdn_rules" else key.replace("_", " "))
            if current_sig[key] != desired_sig[key]:
                diff.append(labels[key] + _policy_change_values(key, full, desired, current_sig, desired_sig))
        status = policy_status(full)
        if self.set_policy_status is not None and status != self.set_policy_status:
            diff.append(f"status is {status or 'unknown'}, requested {self.set_policy_status}")
        if self.update and adopted and not owned:
            diff.append("adopting (adds owner tag)")
        status_note = f"; status={status or 'unknown'}"
        if not diff:
            if status.lower() == "error":
                sr.policy = Outcome("failed", f"policy {policy_id} reports status=Error", policy_id)
                return
            if status not in ("Active", "Suspended"):
                sr.policy = Outcome("unverified", f"policy {policy_id} matches the requested fields but has "
                                                  f"unfinished or unknown status={status or 'unknown'}", policy_id)
                return
            suspended_requested = self.set_policy_status == "Suspended" or (self.set_policy_status is None and self.suspended_ok)
            ok_status = "exists" if status == "Active" or (status == "Suspended" and suspended_requested) else "inactive"
            note = "" if owned else " (unmanaged: no owner tag; pass --adopt to take ownership)"
            hint = "" if "targets" in checked else "; add --drift to compare targets"
            full_hint = "; targets checked" if self.drift else ""
            sr.policy = Outcome(ok_status, f"policy {policy_id} up to date ({', '.join(checked)} checked{hint})"
                                           f"{full_hint}{note}{status_note}", policy_id)
            return
        summary = "; ".join(diff)
        if not (self.update and policy_id):
            hint = " (use --update to fix)" if owned else f" (unmanaged; use --update --adopt {server.fqdn} to take over)"
            sr.policy = Outcome("drift", f"policy {policy_id}: {summary}{hint}{status_note}", policy_id)
            return
        if not (owned or adopted):
            sr.policy = Outcome("drift", f"policy {policy_id}: {summary}; not managed by this tool (no {self.defaults.owner_tag!r} tag) "
                                         f"-- pass --adopt {server.fqdn} to take ownership", policy_id)
            return
        if self._abort_reason:
            sr.policy = self._blocked_by_abort()
            return
        expected_status = self.set_policy_status or (
            status if status in ("Active", "Suspended") else self.defaults.policy_status)
        if self.dry_run:
            status_change = ""
            if self.set_policy_status is None and status not in ("Active", "Suspended"):
                status_change = f"; status {status or 'unknown'} -> {expected_status}"
            sr.policy = Outcome("planned", f"would update policy {policy_id}: {summary}{status_change}", policy_id)
            return
        # Validating, Warning and Error are platform-owned observations, not valid requested states. A corrective
        # update asks for the configured stable state; Active/Suspended are preserved unless explicitly overridden.
        update_payload = build_policy_update(full, desired, status=expected_status)
        try:
            self.check_cancelled()
            sr.policy = Outcome("uncertain", "Policy update started; response not yet confirmed", policy_id)
            self.uap.update_policy(policy_id, update_payload)
        except WriteCancelled:
            sr.policy = self._blocked_by_abort()
            return
        except SIAApiError as exc:
            sr.policy = self._exception_outcome(
                self._error_status(exc), "update failed", exc,
                stage="policy update", object_name=sr.policy_name, ref=policy_id)
            if self._systematic(exc):
                self._abort(f"updating policy {sr.policy_name!r}: {exc}")
            return
        sr.policy = self._applied_unverified(
            "Policy update accepted; read-back not yet complete",
            stage="policy read-back", object_name=sr.policy_name, ref=policy_id)
        try:
            _read_back, read_status, description, mismatch, differences = self._poll_policy(
                policy_id, update_payload, expected_status)
        except SIAApiError as exc:
            sr.policy = self._exception_outcome(
                "unverified", f"policy {policy_id} update was accepted, but read-back failed", exc,
                stage="policy read-back", object_name=sr.policy_name, ref=policy_id, mutation_state="applied")
            return
        detail = f"policy {policy_id}: {summary}; status={read_status}"
        if read_status.lower() == "error":
            sr.policy = Outcome("failed", f"{detail}: {description}", policy_id)
        elif read_status != expected_status or mismatch:
            suffix = f": {description}" if description else ""
            problems = []
            if read_status != expected_status:
                problems.append(f"requested status was {expected_status}")
            if mismatch:
                problems.append(f"read-back {mismatch}")
            sr.policy = self._applied_unverified(
                f"{detail}{suffix}; " + "; ".join(problems),
                stage="policy read-back", object_name=sr.policy_name, ref=policy_id,
                details={"policy_id": policy_id, "status": read_status, "requested_status": expected_status,
                         "differences": differences})
        elif read_status not in ("Active", "Suspended"):
            suffix = f": {description}" if description else ""
            sr.policy = self._applied_unverified(
                f"{detail}{suffix}", stage="policy read-back", object_name=sr.policy_name, ref=policy_id)
        elif self.set_policy_status is None and read_status == "Suspended" and not self.suspended_ok:
            sr.policy = Outcome("inactive", f"{detail}; fields were updated but the existing suspended state was preserved", policy_id)
        else:
            sr.policy = Outcome("updated", detail, policy_id)

    def _poll_policy(self, policy_id: str, desired: dict[str, Any], expected_status: str) -> PolicyReadBack:
        """Poll until a policy's status and normalized writable fields both match the submitted payload.

        A persistent mismatch names every differing field with its tenant -> requested values, and
        ``differences`` carries the normalized blocks for the diagnostic."""
        policy: dict[str, Any] = {}
        status, description = "unknown", ""
        mismatch = "returned no policy state"
        differences: dict[str, Any] = {}
        desired_signature = policy_signature(desired)
        for attempt in range(self.status_polls):
            try:
                policy = self.uap.get_policy(policy_id)
            except SIAApiError:
                if attempt >= self.status_polls - 1:
                    raise
                self._sleep(POLICY_STATUS_POLL_SECONDS)
                continue
            try:
                metadata = policy.get("metadata")
                if not isinstance(metadata, dict):
                    raise TypeError("metadata is not an object")
                returned_id = pick(metadata, "policyId", "policy_id")
                if str(returned_id or "") != str(policy_id):
                    raise ValueError("policy id does not match the requested object")
                st = metadata.get("status")
                if st is None:
                    st = {}
                if isinstance(st, str):
                    status, description = st.capitalize(), ""
                elif isinstance(st, dict):
                    status = str(st.get("status") or "unknown").capitalize()
                    description = str(st.get("statusDescription") or st.get("status_description") or "")
                else:
                    raise TypeError("status is not text or an object")
                actual_signature = policy_signature(policy)
            except (AttributeError, TypeError, ValueError):
                status, description = "unknown", ""
                mismatch = "returned a malformed policy object"
                differences = {}
            else:
                changed = [key for key in desired_signature if actual_signature.get(key) != desired_signature[key]]
                differences = {}
                for key in changed:
                    tenant, requested = plain(actual_signature.get(key)), plain(desired_signature[key])
                    differences[key] = {"tenant": tenant, "requested": requested,
                                        "changed": [path for path, _, _ in leaf_differences(tenant, requested) if path]}
                mismatch = "still differs in " + ", ".join(
                    key.replace("_", " ") + _policy_change_values(key, policy, desired, actual_signature, desired_signature)
                    for key in changed) if changed else ""
            if status.lower() == "error" or (status == expected_status and not mismatch):
                break
            if attempt < self.status_polls - 1:
                self._sleep(POLICY_STATUS_POLL_SECONDS)
        return PolicyReadBack(policy, status, description, mismatch, differences)
