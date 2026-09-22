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
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Callable, Iterable, NamedTuple

from .checkpoint import Checkpoint, fingerprint, is_done, row_key
from .clients import UAP_VM_FILTER, SIAClient, UAPClient, owned_vm_filter
from .config import Defaults
from .diagnostics import Diagnostic, diagnose, for_accounts_scope
from .http import SIAApiError
from .inputs import Inputs, ServerRow, StrongAccountRow
from .payloads import (
    build_bulk_target_sets, build_policy, build_policy_update, build_secret_payload, build_target_set,
    build_target_set_update, build_vault_account, exact_fqdns, implied_session_overrides, is_owned_policy,
    is_owned_target_set, partition_differences, plain, policy_name_for, policy_signature, policy_status,
    sanitize_template, target_set_name_for, target_set_differences, target_set_signature, validate_template,
)
from .payloads import TARGET_SET_SECRET_KEYS, TARGET_SET_UNKNOWN_DEFAULTS
from .redact import register_secret
from .resolve import PrincipalResolver, ResolveError, SecretIndex, pick, secret_id_of, secret_type_of

STAGES = ("all", "vault", "secrets", "targetsets", "policies")
ACCOUNT_STAGES = ("all", "vault", "secrets")   # what an accounts-only run (--accounts) can write
LOOKUP_MODES = ("auto", "search", "list")
BULK_CHUNK = 50
MAX_WORKERS = 16
POLICY_STATUS_POLL_SECONDS = 2.0
MAX_CHANGE_ENTRIES = 8            # named values per differing policy field in a drift or read-back message
# Names an operator recognises for the leaves of a policy signature block (``<signature key>.<leaf path>``); every
# other leaf is named by its path. Values are compared on the normalized blocks (payloads.policy_signature), never raw.
_LEAF_LABELS = {
    "description": "description", "time_zone": "time zone", "tags": "tags",
    "conditions.maxSessionDuration": "max session hours", "conditions.idleTime": "idle minutes",
    "conditions.accessWindow.daysOfTheWeek": "access days", "conditions.accessWindow.fromHour": "from hour",
    "conditions.accessWindow.toHour": "to hour",
    "conditions.overrideIdleTime": "idle time override", "conditions.overrideMaxSessionDuration": "max session override",
    "conditions.overrideRecording": "recording override",
    "behavior.connectAs.ssh.username": "SSH username",
}
for _profile in ("localEphemeralUser", "domainEphemeralUser"):
    _LEAF_LABELS[f"behavior.connectAs.rdp.{_profile}.assignGroups"] = "local groups"
    _LEAF_LABELS[f"behavior.connectAs.rdp.{_profile}.enableEphemeralUserReconnect"] = "reconnect"
_BLOCK_LABELS = {"conditions": "access conditions", "behavior": "connection behavior", "time_frame": "time frame",
                 "entitlement": "policy entitlement", "tags": "policy tags"}
BAD = ("failed", "blocked", "inactive", "uncertain", "unverified")
NON_SYSTEMATIC_4XX = (404, 409, 429)
NOT_APPLICABLE = "n/a"
_CONFLICT_WORDS = ("already exist", "duplicate", "unique", "conflict")


_ACTIVE_WORDS = {"true": True, "1": True, "yes": True, "active": True, "enabled": True,
                 "false": False, "0": False, "no": False, "inactive": False, "disabled": False}


def _active_flag(value: Any) -> bool | None:
    """A strong account's active flag however the API spells it (bool, 0/1, a word); None when it cannot be read.
    An absent field is not a reason to think the account is disabled."""
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        return _ACTIVE_WORDS.get(value.strip().casefold())
    return None


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
    differences: dict[str, Any]   # {signature key: {"tenant": ..., "requested": ..., "changed": [paths], "unmanaged": [paths]}}
    notes: tuple[str, ...]        # leaves only the tenant carries, one note per block (never a failure)


def _unset(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _short(value: Any) -> str:
    if value is None:
        return "absent"
    text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= 100 else text[:97] + "..."


def _leaf_label(key: str, path: str) -> str | None:
    """An operator's name for a leaf, its path when it has none, and no label at all for a whole-block value."""
    full = f"{key}.{path}" if path else key
    label = _LEAF_LABELS.get(full)
    return label if label is not None else (path or None)


def _policy_change_values(key: str, current: dict, desired: dict,
                          current_sig: dict | None = None, desired_sig: dict | None = None,
                          managed: list[tuple[str, Any, Any]] | None = None) -> str:
    """Compact, named before/after values (tenant -> requested) for the managed differences of one signature key.

    Only leaves the tool writes are listed (see ``partition_differences``): settings an operator recognises by their
    ``_LEAF_LABELS`` name, every other leaf by its path, so a value the tenant changed is never silent. A session
    override flag the tool is silent about shows the value the request implies. Leaves only the tenant carries are
    rendered by ``_tenant_only_values`` instead.
    """
    if key == "principals":
        before, after = _principal_summary(current), _principal_summary(desired)
        return f" ({', '.join(before) or 'none'} -> {', '.join(after) or 'none'})" if before != after else ""
    if managed is None:
        current_sig = policy_signature(current) if current_sig is None else current_sig
        desired_sig = policy_signature(desired) if desired_sig is None else desired_sig
        managed, _ = partition_differences(key, plain(current_sig.get(key)), plain(desired_sig.get(key)))
    implied = implied_session_overrides(desired.get("conditions")) if key == "conditions" else {}
    changed: list[str] = []
    for path, old, new in managed:
        if new is None and path in implied:
            new = implied[path]         # the tool never writes the flag; the tenant derives it from the setting
        label = _leaf_label(key, path)
        changed.append(f"{label}: {_short(old)} -> {_short(new)}" if label else f"{_short(old)} -> {_short(new)}")
    if len(changed) > MAX_CHANGE_ENTRIES:
        changed = changed[:MAX_CHANGE_ENTRIES] + [f"+{len(changed) - MAX_CHANGE_ENTRIES} more"]
    return " (" + "; ".join(changed) + ")" if changed else ""


def _tenant_only_values(key: str, tenant_only: list[tuple[str, Any, Any]]) -> str:
    """One note naming the leaves of a block that only the tenant carries, with their values:
    ``access conditions: tenant also carries accessApproval={"required": true}``."""
    label = _BLOCK_LABELS.get(key, key.replace("_", " "))
    shown = [path if key == "tags" else f"{path}={_short(old)}" for path, old, _ in tenant_only]
    if len(shown) > MAX_CHANGE_ENTRIES:
        shown = shown[:MAX_CHANGE_ENTRIES] + [f"+{len(shown) - MAX_CHANGE_ENTRIES} more"]
    return f"{label}: tenant also carries {', '.join(shown)}"


@dataclass
class Outcome:
    status: str = "pending"   # created | exists | inactive | drift | updated | planned | skipped | failed | blocked | uncertain | unverified | n/a
    detail: str = ""
    ref: str | None = None
    diagnostic: dict[str, Any] | None = None
    notes: tuple[str, ...] = ()   # leaves only the tenant carries; informational, never part of the verdict

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
class AccountResult:
    """One strong account of an accounts-only run (--accounts): its Vault stage and its SIA secret."""
    name: str
    type: str
    sia_name: str
    username: str
    address: str
    vault: Outcome = field(default_factory=Outcome)
    secret: Outcome = field(default_factory=Outcome)

    @property
    def ok(self) -> bool:
        return not (self.vault.bad or self.secret.bad)


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
    accounts: list[AccountResult] = field(default_factory=list)   # one per active strong account, in both modes
    accounts_only: bool = False                                    # --accounts: servers is empty, accounts are the unit

    @property
    def failures(self) -> int:
        """Rows that are not fully OK. A failed strong account always surfaces here through the rows it blocks.
        An accounts-only run has no rows, so its accounts are counted instead."""
        if self.accounts_only:
            return sum(1 for a in self.accounts if not a.ok)
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
                 reconciliation_context: dict[str, Any] | None = None, accounts_only: bool = False,
                 pvwa_configured: bool | None = None):
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
        if accounts_only:
            if only not in ACCOUNT_STAGES:
                raise ValueError(f"an accounts-only run can write only these stages: {ACCOUNT_STAGES}")
            if resume or update or set_policy_status is not None:
                raise ValueError("accounts_only cannot be combined with resume, update or set_policy_status")
        elif getattr(inputs, "accounts_only", False):
            # Rows parsed for --accounts carry no principals; a server run would build policies nobody may use.
            raise ValueError("inputs were parsed for accounts-only onboarding (no principals); pass accounts_only=True")
        self.sia, self.uap, self.resolver, self.inputs, self.defaults = sia, uap, resolver, inputs, defaults
        self.dry_run, self.update, self.only, self.fail_fast = dry_run, update, only, fail_fast
        self.drift = update if drift is None else drift
        self.adopt, self.adopt_all = {a.lower() for a in adopt}, adopt_all
        self.workers, self.status_polls = workers, max(1, status_polls)
        self.lookup, self.lookup_search_max_rows = lookup, lookup_search_max_rows
        self.checkpoint, self.resume = checkpoint, resume
        self.progress_every = max(0, progress_every)
        self.pvwa, self.pvwa_platform_id, self.pvwa_cpm_managed = pvwa, pvwa_platform_id, pvwa_cpm_managed
        # Whether [pvwa] is configured at all (None: not said). With it and no session, the Vault stage was not
        # selected or not run by this command -- a different reason from a missing [pvwa] section.
        self.pvwa_configured = pvwa_configured
        self.set_policy_status = set_policy_status
        self.accounts_only = accounts_only
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
        self._shared_addresses: frozenset[str] | None = None
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
        # An accounts-only run builds no policy, so the template policy (a UAP read) is not needed.
        self._template = None if self.accounts_only else self._load_template()
        self._checkpoint_context = self._build_checkpoint_context()
        self._plan_rows()
        if self.checkpoint is not None:
            self._snapshot_warnings.extend(self.checkpoint.warnings)
        fqdns = list(dict.fromkeys(s.fqdn for s, _ in self._rows))
        # Windows servers may share one target set (a Domain set covers a whole AD domain), so look them up by
        # target-set name rather than by FQDN.
        target_set_names = list(dict.fromkeys(s.target_set_key for s, _ in self._rows if not s.is_ssh))
        # The dict key is lower-cased; the tenant's name filter may not be, so it is sent the CSV's own spelling.
        target_set_spellings = {s.target_set_key: (s.target_set_name or s.fqdn) for s, _ in self._rows if not s.is_ssh}
        accounts = self._active_accounts()
        self._lookup_mode = self._choose_lookup(len(fqdns))
        # Per-stage timings: a slow tenant read is otherwise a single unbroken gap in the log, with nothing to say
        # which of the four reads spent the time.
        timings: list[str] = []
        reads: list[tuple[str, Callable[[], None]]] = [("secrets", lambda: self._snapshot_secrets(accounts))]
        if not self.accounts_only:   # --accounts touches no target set, policy or principal, so it reads none
            reads += [("target sets", lambda: self._snapshot_target_sets(target_set_names, accounts, target_set_spellings)),
                      ("policies", lambda: self._snapshot_policies(fqdns)),
                      ("principals", self._snapshot_principals)]
        for label, read in reads:
            started = time.monotonic()
            pages_before = self._pages_read()
            read()
            pages = self._pages_read() - pages_before
            elapsed = f"{time.monotonic() - started:.1f}s"
            timings.append(f"{label} {elapsed}/{pages} page{'s' if pages != 1 else ''}" if pages else f"{label} {elapsed}")
        if self.accounts_only:
            self._log.info("Tenant snapshot (%s lookup): %d strong accounts read for %d servers [%s]",
                           self._lookup_mode, len(self._secrets), len(fqdns), ", ".join(timings))
        else:
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
        result = RunResult(mode="plan" if self.dry_run else "apply", resumed=len(self._resumed), lookup_mode=self._lookup_mode,
                           accounts_only=self.accounts_only)
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
        # keep CSV order; an accounts-only run reports accounts, not rows
        if not self.accounts_only:
            result.servers = [ordered[(s.fqdn, policy_name_for(s, self.defaults))] for s in self.inputs.servers
                              if (s.fqdn, policy_name_for(s, self.defaults)) in ordered]
        try:
            if self.accounts_only:
                skipped = sum(1 for s, _ in self._rows if s.is_ssh)
                if skipped:
                    result.warnings.append(f"{skipped} ssh row(s) skipped: Linux ZSP uses an SSH certificate, not a strong account")
                self._ensure_vault(result)
                self._ensure_secrets(result)
            else:
                self._flag_duplicate_policy_names(result)
                self._ensure_vault(result)
                self._ensure_secrets(result)
                self._ensure_target_sets(result)
                self._ensure_policies(result)
            result.accounts = self._account_results(result)
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
        result.accounts = self._account_results(result)
        if self.accounts_only:
            # Accounts are the unit here, so the ones the run never reached belong in the totals and diagnostics too.
            for account in result.accounts:
                result.secrets.setdefault(account.name, account.secret)
                if account.vault.status != NOT_APPLICABLE:
                    result.vault.setdefault(account.name, account.vault)
        outcomes = [o for sr in result.servers for o in (sr.secret, sr.target_set, sr.policy)]
        outcomes += list(result.secrets.values()) + list(result.vault.values())
        state = ("unknown" if any(o.status == "uncertain" for o in outcomes) else
                 "applied" if any(o.status in ("created", "updated") or
                                  (o.diagnostic or {}).get("mutation_state") == "applied" for o in outcomes) else
                 "unknown" if any(o.status == "unverified" for o in outcomes) else "not_applied")
        if isinstance(exc, KeyboardInterrupt):
            if self.dry_run:   # plan or verify: nothing was written
                stage, action = "Reading tenant", "Nothing was changed; run the command again when ready."
            elif self.accounts_only:
                stage, action = "Apply", ("Review the partial results, then run `sia plan --accounts` with the same input: "
                                          "accounts created before the interruption report exists, and `sia apply "
                                          "--accounts` creates only the missing ones.")
            else:
                stage, action = "Apply", "Review the partial results and run plan --drift before apply --resume."
            diagnostic = Diagnostic(code="SIA-INTERRUPTED", message="Run interrupted; in-flight results have been collected.",
                                    stage=stage, mutation_state=state, actions=(action,))
        else:
            diagnostic = diagnose(exc, stage="Completing run", mutation_state=state)
            if self.accounts_only:
                diagnostic = for_accounts_scope(diagnostic)
        result.diagnostics.append(diagnostic.to_dict())

    # ------------------------------------------------------------ snapshot
    def _build_checkpoint_context(self) -> dict[str, Any]:
        """Inputs outside one CSV row that can change the objects produced by reconciliation."""
        return {
            "caller": self.reconciliation_context,
            "defaults": asdict(self.defaults),
            "template": self._template,
            "input_mappings": {
                "strong_accounts": {key: asdict(self._fingerprinted(value)) for key, value in self.inputs.strong_accounts.items()},
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

    def _fingerprinted(self, account: StrongAccountRow | None) -> StrongAccountRow | None:
        """The account as a checkpoint fingerprint sees it. An address the inputs inferred (a declared local account
        used by one server) only keys the password file and names the Vault address the run derived anyway, so it
        must not make records written before that inference existed look stale."""
        if account is not None and account.name in getattr(self.inputs, "inferred_addresses", ()):
            return replace(account, address=None)
        return account

    def _plan_rows(self) -> None:
        self._rows, self._resumed = [], {}
        for server in self.inputs.servers:
            name = policy_name_for(server, self.defaults)
            sr = ServerResult(fqdn=server.fqdn, strong_account=server.strong_account or "-", policy_name=name,
                              protocol=server.protocol, line=server.line,
                              target_set_name=("" if server.is_ssh else target_set_name_for(server)))
            if self.resume and self.checkpoint is not None:
                account = self._fingerprinted(self.inputs.strong_accounts.get(server.strong_account or ""))
                record = self.checkpoint.get(
                    row_key(server.fqdn, name), fingerprint(server, account, name, self._checkpoint_context))
                if record and is_done(record):
                    self._resumed[sr.key] = (server, sr, record)
                    continue
            self._rows.append((server, sr))

    def _active_accounts(self) -> list[StrongAccountRow]:
        names = {s.strong_account for s, _ in self._rows if s.strong_account and not s.is_ssh}
        return [a for n, a in self.inputs.strong_accounts.items() if n in names]

    def _account_results(self, result: RunResult) -> list[AccountResult]:
        """One AccountResult per active strong account, in the order the servers list first names them: the unit
        of an accounts-only run, informational in a server run."""
        first_seen: dict[str, int] = {}
        for server, _ in self._rows:
            if server.strong_account and not server.is_ssh:
                first_seen.setdefault(server.strong_account, len(first_seen))
        out: list[AccountResult] = []
        for account in sorted(self._active_accounts(), key=lambda a: first_seen.get(a.name, len(first_seen))):
            secret = result.secrets.get(account.name)
            if secret is None:   # the run stopped before this account was reached
                secret = self._blocked_by_abort() if self._abort_reason else Outcome("unverified", "no result recorded")
            vault = result.vault.get(account.name)
            if vault is None:
                vault = self._vault_not_run(account)
            # A local account several servers share has no one server; naming the first of this wave would mislead.
            address = account.address or ("" if self._shared_local(account) else self._address_for(account))
            out.append(AccountResult(name=account.name, type=account.type, sia_name=account.sia_name,
                                     username=account.username or "", address=address, vault=vault, secret=secret))
        return out

    def _vault_not_run(self, account: StrongAccountRow) -> Outcome:
        """Why a strong account has no Vault result: only the true reason, never '[pvwa] not configured' by default."""
        if account.type != "vault":
            return Outcome(NOT_APPLICABLE, f"Vault stage not applicable (type={account.type})")
        if self.pvwa is None:   # the stage never runs without a session, whatever else stopped the run
            if not self._writes("vault"):
                return Outcome(NOT_APPLICABLE, f"Vault stage not run (--only {self.only})")
            if self.pvwa_configured:
                return Outcome(NOT_APPLICABLE, "Vault not checked by this command (verify --accounts checks it)")
            return Outcome(NOT_APPLICABLE, "Vault stage off ([pvwa] not configured)")
        if self._abort_reason:
            return self._blocked_by_abort()
        return Outcome("unverified", "no Vault result recorded")

    def _shared_local(self, account: StrongAccountRow) -> bool:
        return account.is_local and account.name in getattr(self.inputs, "shared_local_accounts", ())

    def _password_hint(self, account: StrongAccountRow) -> str:
        """Where a missing password can come from. The password file's second key is the account's address, and only
        while no other account carries that address (sia_onboard.make_password_source)."""
        name = repr(account.name)
        if account.address:
            if self._shared_addresses is None:   # once per run: a run may report thousands of missing passwords
                self._shared_addresses = (self.inputs.shared_addresses() if hasattr(self.inputs, "shared_addresses")
                                          else frozenset())
            if account.address.casefold() in self._shared_addresses:
                return (f"add {name} to the password file (its address {account.address!r} is shared with other "
                        "accounts, so it keys no password)")
            return f"add {name} (or {account.address!r}) to the password file"
        if self._shared_local(account):
            return f"add {name} to the password file (it is shared by several servers, so no server FQDN selects it)"
        return f"add {name} to the password file"

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

    def _pages_read(self) -> int:
        return int(getattr(self.sia, "pages_read", 0) or 0) + int(getattr(self.uap, "pages_read", 0) or 0)

    def _filters_trusted(self) -> bool:
        """Whether this tenant's server-side name filters agree with an unfiltered listing."""
        caps = getattr(self.sia, "capabilities", None)
        return True if caps is None else bool(getattr(caps, "name_filter_reliable", True))

    def _distrust_name_filters(self, kind: str, recovered: list[str], listed: dict[str, str] | None = None) -> None:
        """A name filter missed objects the unfiltered listing serves: from here on nothing in this run is treated
        as missing on the strength of a filtered read, and the rest of the run uses list mode (one listing per
        object kind instead of a filtered walk per object). When every miss is a spelling the tenant stores in
        another case, the warning says so instead of blaming the tenant's filter."""
        caps = getattr(self.sia, "capabilities", None)
        if caps is not None:
            caps.name_filter_reliable = False
        self._lookup_mode = "list"
        plural = len(recovered) != 1
        pairs = {name: (listed or {}).get(name) for name in recovered}
        case_only = bool(recovered) and all(
            stored is not None and stored != name and stored.casefold() == name.casefold() for name, stored in pairs.items())
        if case_only:
            shown = ", ".join(f"{name!r} is stored as {pairs[name]!r}" for name in recovered[:3])
            if len(recovered) > 3:
                shown += f" and {len(recovered) - 3} more"
            self._snapshot_warnings.append(
                f"this tenant's name filter is case-sensitive: {kind}{'s' if plural else ''} {shown}; the unfiltered "
                f"listing found {'them' if plural else 'it'}, the rest of this run uses list mode, and nothing is treated "
                "as missing on the strength of a name-filtered read. Match the tenant's spelling in your CSV, or pin "
                "--lookup list (or [http] lookup_search_max_rows = 0).")
            return
        shown = ", ".join(repr(n) for n in recovered[:3])
        if len(recovered) > 3:
            shown += f" and {len(recovered) - 3} more"
        self._snapshot_warnings.append(
            f"this tenant matched nothing when filtering by name for {kind}{'s' if plural else ''} {shown}, but its "
            f"unfiltered listing serves {'them' if plural else 'it'}; the rest of this run uses list mode, and nothing "
            "is treated as missing on the strength of a name-filtered read. Pin --lookup list (or [http] "
            "lookup_search_max_rows = 0) for this tenant.")

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
                spellings = {str(s.get("secret_name") or s.get("secretName") or "").casefold():
                             str(s.get("secret_name") or s.get("secretName") or "") for s in listing}
                stored = {name: spellings.get(name.casefold(), name) for name in recovered}
                # Union, not replacement: the per-name reads are evidence too, and a listing endpoint that already
                # misbehaves (empty pages with live cursors) is not the only source of truth. The index collapses
                # an object seen by both reads through its id.
                for secret in listing:
                    self._secrets.add(secret)
                if recovered:
                    self._distrust_name_filters("strong account", recovered, stored)
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

    def _snapshot_target_sets(self, names: list[str], accounts: list[StrongAccountRow],
                              spellings: dict[str, str] | None = None) -> None:
        self._target_sets = {}
        if not names:
            return
        spellings = spellings or {}
        wanted = set(names)
        caps = getattr(self.sia, "capabilities", None)
        unfiltered = True if caps is None else bool(caps.targetsets_list_unfiltered)
        items: list[dict[str, Any]] = []
        if self._lookup_mode == "search" and unfiltered and self._filters_trusted():
            for chunk in self._parallel(names, lambda n: self.sia.list_target_sets(name=spellings.get(n, n))):
                items.extend(chunk)
            # As for strong accounts, an empty name-filtered read is not proof of absence: confirm every wanted
            # name still missing against one unfiltered listing before it becomes a bulk create, which on a set
            # that exists is either a false failure or a write to an object this run never inspected.
            missing = set(names) - {str(pick(ts, "name", default="")).lower() for ts in items}
            if missing:
                listing = self.sia.list_target_sets()
                stored = {str(pick(ts, "name", default="")).lower(): str(pick(ts, "name")) for ts in listing
                          if str(pick(ts, "name", default="")).lower() in missing}
                # Keep conflicting evidence for names already found, too: discarding it would bypass the
                # identity/signature ambiguity check below.
                items.extend(listing)
                if stored:
                    requested = sorted(spellings.get(key, key) for key in stored)
                    self._distrust_name_filters(
                        "target set", requested, {spellings.get(key, key): value for key, value in stored.items()})
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
            if not name:
                continue
            previous = self._target_sets.get(name)
            if previous is not None:
                old_id = pick(previous, "id", "targetSetId", "target_set_id")
                new_id = pick(ts, "id", "targetSetId", "target_set_id")
                same_object = old_id is not None and new_id is not None and str(old_id) == str(new_id)
                if same_object:
                    ts = ts if len(ts) >= len(previous) else previous     # two projections of one object: keep the fuller
                elif name not in wanted:
                    ts = previous          # an object this run never touches: never a reason to abort the run
                elif (old_id is not None and new_id is not None) or target_set_signature(previous) != target_set_signature(ts):
                    raise ReconcileError(f"ambiguous target set {name!r}: the tenant returned conflicting identities or "
                                         "definitions; resolve them before applying")
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
            found_names = self._policies_by_name(list(seen.values()), {sr.policy_name.casefold() for _, sr in self._rows})
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
            if not self._policy_list and self._rows and filter_query != UAP_VM_FILTER:
                self._confirm_empty_owned_listing(filter_query)
        wanted = {sr.policy_name.casefold() for _, sr in self._rows}
        self._policies = self._policies_by_name(self._policy_list, wanted)
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
                            details: dict[str, Any] | None = None, notes: tuple[str, ...] = ()) -> Outcome:
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
        return Outcome("unverified", detail, ref, diagnostic, notes=tuple(notes))

    @staticmethod
    def _converged(status: str, detail: str, ref: str, notes: tuple[str, ...], *, stage: str, object_name: str,
                   details: dict[str, Any] | None = None) -> Outcome:
        """A write whose read-back converged on every field the tool sent. Leaves only the tenant carries ride along
        as notes with an informational diagnostic (JSON report, ``--verbose``), never as a failure."""
        if not notes:
            return Outcome(status, detail, ref)
        diagnostic = Diagnostic(
            code="SIA-TENANT-FIELDS", severity="info", message="; ".join(notes), stage=stage, object_name=object_name,
            mutation_state="applied", details=dict(details or {}),
            actions=("Nothing to fix: fields the tool never sends are preserved on update and reported as notes.",
                     "To silence a field set [defaults] ignore_readback_keys; to fail on unknown fields set "
                     "[defaults] readback_extra_keys = \"fail\".",
                     "`show-policy NAME` prints the raw policy; --verbose or the JSON report shows the values."),
        ).to_dict()
        return Outcome(status, detail, ref, diagnostic, notes=tuple(notes))

    def _partition(self, key: str, tenant: Any, requested: Any) -> tuple[list, list]:
        """``partition_differences`` under this run's configuration: ``[defaults] ignore_readback_keys`` drops
        tenant-only leaves by ``<signature key>.<path>``; ``readback_extra_keys = "fail"`` makes the rest managed."""
        managed, tenant_only = partition_differences(key, tenant, requested)
        ignored = tuple(self.defaults.ignore_readback_keys)
        tenant_only = [leaf for leaf in tenant_only
                       if not any(f"{key}.{leaf[0]}" == item or f"{key}.{leaf[0]}".startswith(item + ".")
                                  for item in ignored)]
        if self.defaults.readback_extra_keys == "fail":
            return managed + tenant_only, []
        return managed, tenant_only

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
    def _policies_by_name(policies: list[dict[str, Any]], wanted: set[str] | None = None) -> dict[str, dict[str, Any]]:
        """Policies keyed by casefolded name. Two objects under one name are ambiguous only when this run wants that
        name (``wanted``; None = every name); a duplicate elsewhere in the tenant keeps its first object and never
        aborts a run that does not touch it."""
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
                        if wanted is None or key in wanted:
                            raise ReconcileError(f"ambiguous policy name {name!r}: multiple tenant object IDs; resolve them before applying")
                        continue
                out[key] = policy
        return out

    def _confirm_empty_owned_listing(self, filter_query: str) -> None:
        """An empty owned-tag read may be right (nothing created yet) or a filter the tenant evaluates differently
        (tag casing, an unsupported operator). One VM listing settles it before any row is planned as a create:
        owned policies it carries prove the filter wrong, and policies under wanted names are kept either way."""
        wanted = {sr.policy_name.casefold() for _, sr in self._rows}
        listing = self.uap.list_policies(filter_query=UAP_VM_FILTER)
        owned = [p for p in listing if is_owned_policy(p, self.defaults.owner_tag)]
        named = [p for p in listing
                 if html.unescape(str((p.get("metadata") or {}).get("name") or "")).casefold() in wanted]
        if owned:
            self._snapshot_warnings.append(
                f"the owned-policy filter ({filter_query}) returned nothing, but the VM listing carries {len(owned)} "
                f"polic{'y' if len(owned) == 1 else 'ies'} tagged {self.defaults.owner_tag!r}: this tenant does not "
                "evaluate the tag filter as expected, so the listing was used instead. Pin --lookup list if this recurs.")
        seen: dict[str, dict[str, Any]] = {}
        for policy in owned + named:
            pid = str(pick(policy.get("metadata") or {}, "policyId", "policy_id", default="")) or str(id(policy))
            seen.setdefault(pid, policy)
        self._policy_list = list(seen.values())

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
        account = self._fingerprinted(self.inputs.strong_accounts.get(server.strong_account or ""))
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
                if self.pvwa_configured:   # the CLI opens no PVWA session when no selected account needs one
                    result.warnings.append("no selected strong account is type=vault; the vault stage had nothing to do")
                elif self.pvwa_configured is None and not accounts:
                    result.warnings.append("[pvwa] is not configured, or no selected strong account is type=vault; "
                                           "the vault stage did not run")
                else:
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
            if not account.address and self._shared_local(account):
                result.vault[account.name] = Outcome(
                    "failed", f"{what} is missing, and it is a local account shared by several servers, so its Vault "
                              "address is ambiguous: set address in strong_accounts.csv (the server the Vault manages "
                              "it on) before onboarding it")
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
                    "failed", f"{what} is missing and its current password is not available: {self._password_hint(account)}")
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
                if account.secret_type and account.secret_type.casefold() != stype.casefold():
                    # A name match alone is not the account the CSV describes: binding target sets (and so every
                    # session's privileged credential) to another kind of secret is a failure, not a footnote.
                    result.secrets[account.name] = Outcome(
                        "failed", f"{detail} is a {stype}, but {account.name!r} is type={account.type} "
                                  f"({account.secret_type}); rename one of them before reconciling, so target sets never "
                                  "bind to another kind of credential", sid)
                    continue
                raw_active = pick(found, "is_active", "isActive", default=None)
                active = _active_flag(raw_active)
                if active is None:
                    result.secrets[account.name] = Outcome(
                        "unverified", f"{detail} has an active flag this tool cannot read ({raw_active!r}); "
                                      "target-set and policy changes are blocked", sid)
                    continue
                if not active:
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
                        "failed", f"password not available: set env var {account.password_env}, "
                                  f"{self._password_hint(account)}, or run interactively to be prompted")
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
            if self._is_conflict(exc) and self._adopt_existing_secret(account, what, exc):
                return
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

    def _adopt_existing_secret(self, account: StrongAccountRow, what: str, exc: SIAApiError) -> bool:
        """A create that answered "already exists" (a race, or a 429 retried after the write had landed): the
        account is there, so read it and report exists instead of a failure that blocks every dependent row."""
        assert self._result is not None
        try:
            found = self.sia.find_secret(account.sia_name)
        except SIAApiError:
            return False
        if not found:
            return False
        sid, stype = secret_id_of(found), secret_type_of(found) or account.secret_type or ""
        if not sid or not stype:
            return False
        self._result.secrets[account.name] = Outcome(
            "exists", f"{stype} secret {sid} ({account.sia_name}) already existed when creating {what} "
                      f"(the create answered {exc.status})", sid)
        with self._lock:
            self._secrets.add(found)
            self._refs[account.name] = (sid, stype)
        return True

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
        current_secret = pick(current, *TARGET_SET_SECRET_KEYS)
        ts_type = pick(current, "type", default=expected_type)
        owned = is_owned_target_set(current, self.defaults.owner_tag)
        if str(ts_type).strip().casefold() != expected_type.casefold():
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
        for key in target_set_differences(current_sig, desired_sig, keys, unknown_defaults=TARGET_SET_UNKNOWN_DEFAULTS):
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
                    changed = [key.replace("_", " ") for key in
                               target_set_differences(actual_signature, wanted_signature, tuple(wanted_signature))]
                    if not changed:
                        unknown = [key.replace("_", " ") for key in wanted_signature
                                   if actual_signature.get(key) is None and wanted_signature.get(key) is not None]
                        if unknown:
                            warning = (f"target-set listings on this tenant do not carry {', '.join(unknown)}; the values "
                                       "written for them cannot be read back, so they were accepted unverified")
                            with self._lock:   # the run's warnings were copied from the snapshot before any write
                                sink = self._result.warnings if self._result is not None else self._snapshot_warnings
                                if warning not in sink:
                                    sink.append(warning)
                        return exact[0], ""
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
            _read_back, status, description, mismatch, differences, notes = self._poll_policy(
                policy_id, desired, expected_status)
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
                         "differences": differences}, notes=notes)
        else:
            sr.policy = self._converged("created", detail, policy_id, notes, stage="policy read-back",
                                        object_name=sr.policy_name,
                                        details={"policy_id": policy_id, "differences": differences})
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
        if self.drift and full.get("targets") is not None and current_sig["fqdn_rules"] is None:
            sr.policy = Outcome("unverified", f"policy {policy_id} targets carry no FQDN/IP rules block; cannot confirm "
                                              "which servers it grants access to or safely update", policy_id)
            return
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
            "fqdn_rules": "FQDN rules differ", "target_extras": "extra target rules differ",
            "behavior": "connection behavior differs",
        }
        notes: list[str] = []
        for key in compare_keys:
            if current_sig.get(key) is None:
                continue
            if key != "target_extras":      # compared like every block, but "targets" is listed once
                checked.append("targets" if key == "fqdn_rules" else key.replace("_", " "))
            if current_sig[key] != desired_sig[key]:
                managed, tenant_only = self._partition(key, plain(current_sig[key]), plain(desired_sig[key]))
                if managed:
                    diff.append(labels[key] + _policy_change_values(key, full, desired, current_sig, desired_sig, managed))
                if tenant_only:
                    notes.append(_tenant_only_values(key, tenant_only))
        status = policy_status(full)
        if not status and full is existing:
            # a list projection without metadata.status: settle it with one full read, as for a missing block
            try:
                full = self._full_policy(existing, force=True)
            except SIAApiError as exc:
                sr.policy = self._exception_outcome(
                    "failed", f"could not read existing policy {policy_id}", exc,
                    stage="policy lookup", object_name=sr.policy_name, ref=policy_id)
                return
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
            full_hint = "; targets checked" if self.drift and "targets" in checked else ""
            sr.policy = Outcome(ok_status, f"policy {policy_id} up to date ({', '.join(checked)} checked{hint})"
                                           f"{full_hint}{note}{status_note}", policy_id, notes=tuple(notes))
            return
        summary = "; ".join(diff)
        if not (self.update and policy_id):
            hint = " (use --update to fix)" if owned else f" (unmanaged; use --update --adopt {server.fqdn} to take over)"
            sr.policy = Outcome("drift", f"policy {policy_id}: {summary}{hint}{status_note}", policy_id, notes=tuple(notes))
            return
        if not (owned or adopted):
            sr.policy = Outcome("drift", f"policy {policy_id}: {summary}; not managed by this tool (no {self.defaults.owner_tag!r} tag) "
                                         f"-- pass --adopt {server.fqdn} to take ownership", policy_id, notes=tuple(notes))
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
            sr.policy = Outcome("planned", f"would update policy {policy_id}: {summary}{status_change}", policy_id,
                                notes=tuple(notes))
            return
        # Validating, Warning and Error are platform-owned observations, not valid requested states. A corrective
        # update asks for the configured stable state; Active/Suspended are preserved unless explicitly overridden.
        # Leaves only the tenant carries travel with the PUT (a PUT replaces the object) unless the tenant is strict.
        update_payload = build_policy_update(full, desired, status=expected_status,
                                             preserve=self.defaults.readback_extra_keys != "fail")
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
            _read_back, read_status, description, mismatch, differences, read_notes = self._poll_policy(
                policy_id, update_payload, expected_status)
            notes += [note for note in read_notes if note not in notes]
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
                         "differences": differences}, notes=tuple(notes))
        elif read_status not in ("Active", "Suspended"):
            suffix = f": {description}" if description else ""
            sr.policy = self._applied_unverified(
                f"{detail}{suffix}", stage="policy read-back", object_name=sr.policy_name, ref=policy_id, notes=tuple(notes))
        elif self.set_policy_status is None and read_status == "Suspended" and not self.suspended_ok:
            sr.policy = Outcome("inactive", f"{detail}; fields were updated but the existing suspended state was preserved",
                                policy_id, notes=tuple(notes))
        else:
            sr.policy = self._converged("updated", detail, policy_id, tuple(notes), stage="policy read-back",
                                        object_name=sr.policy_name, details={"policy_id": policy_id})

    def _poll_policy(self, policy_id: str, desired: dict[str, Any], expected_status: str) -> PolicyReadBack:
        """Poll until a policy's status and normalized writable fields both match the submitted payload.

        A persistent mismatch names every differing field with its tenant -> requested values, and
        ``differences`` carries the normalized blocks for the diagnostic."""
        policy: dict[str, Any] = {}
        status, description = "unknown", ""
        mismatch = "returned no policy state"
        differences: dict[str, Any] = {}
        notes: list[str] = []
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
                notes = []
            else:
                differences = {}
                changed_keys: list[str] = []
                notes = []
                for key in desired_signature:
                    if actual_signature.get(key) == desired_signature[key]:
                        continue
                    tenant, requested = plain(actual_signature.get(key)), plain(desired_signature[key])
                    managed, tenant_only = self._partition(key, tenant, requested)
                    differences[key] = {"tenant": tenant, "requested": requested,
                                        "changed": [path for path, _, _ in managed if path],
                                        "unmanaged": [path for path, _, _ in tenant_only]}
                    if managed:
                        changed_keys.append(key)
                        differences[key]["values"] = _policy_change_values(
                            key, policy, desired, actual_signature, desired_signature, managed)
                    if tenant_only:
                        notes.append(_tenant_only_values(key, tenant_only))
                mismatch = "still differs in " + ", ".join(
                    key.replace("_", " ") + differences[key]["values"] for key in changed_keys) if changed_keys else ""
                for key in changed_keys:
                    differences[key].pop("values", None)
            if status.lower() == "error" or (status == expected_status and not mismatch):
                break
            if attempt < self.status_polls - 1:
                self._sleep(POLICY_STATUS_POLL_SECONDS)
        return PolicyReadBack(policy, status, description, mismatch, differences, tuple(notes))
