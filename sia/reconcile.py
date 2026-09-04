"""Desired state (CSVs) vs tenant state -> per-row actions.

Units of work
  * one strong account per referenced account row (shared by every server that names it);
  * one target set per distinct target-set name: normally that is one per Windows server (FQDN), but a "Domain" set
    covers every server in one AD domain, so its outcome is copied to all of them;
  * one access policy per servers.csv row (a server may have several, e.g. one per Identity group).

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
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .checkpoint import Checkpoint, fingerprint, is_done, row_key
from .clients import UAP_VM_FILTER, SIAClient, UAPClient, owned_vm_filter
from .config import Defaults
from .http import SIAApiError
from .inputs import Inputs, ServerRow, StrongAccountRow
from .payloads import (
    build_bulk_target_sets, build_policy, build_policy_update, build_secret_payload, build_target_set,
    build_target_set_update, build_vault_account, exact_fqdns, is_owned_policy, is_owned_target_set, policy_name_for,
    policy_signature, policy_status, sanitize_template, target_set_name_for, validate_template,
)
from .redact import register_secret
from .resolve import PrincipalResolver, ResolveError, SecretIndex, pick, secret_id_of, secret_type_of

STAGES = ("all", "vault", "secrets", "targetsets", "policies")
LOOKUP_MODES = ("auto", "search", "list")
BULK_CHUNK = 50
MAX_WORKERS = 16
POLICY_STATUS_POLL_SECONDS = 2.0
BAD = ("failed", "blocked", "inactive")
NON_SYSTEMATIC_4XX = (404, 409, 429)
NOT_APPLICABLE = "n/a"
_CONFLICT_WORDS = ("already exist", "duplicate", "unique", "conflict")


def env_password(account: StrongAccountRow) -> str | None:
    return os.environ.get(account.password_env or "", "") or None


class ReconcileError(Exception):
    """A run-level problem that prevents any progress (e.g. the template policy is missing or unsuitable)."""


@dataclass
class Outcome:
    status: str = "pending"   # created | exists | inactive | drift | updated | planned | skipped | failed | blocked | n/a
    detail: str = ""
    ref: str | None = None

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
                 pvwa: Any = None, pvwa_platform_id: str = "WinServerLocal", pvwa_cpm_managed: bool = True):
        if only not in STAGES:
            raise ValueError(f"only must be one of {STAGES}")
        if lookup not in LOOKUP_MODES:
            raise ValueError(f"lookup must be one of {LOOKUP_MODES}")
        if not 1 <= workers <= MAX_WORKERS:
            raise ValueError(f"workers must be between 1 and {MAX_WORKERS}")
        self.sia, self.uap, self.resolver, self.inputs, self.defaults = sia, uap, resolver, inputs, defaults
        self.dry_run, self.update, self.only, self.fail_fast = dry_run, update, only, fail_fast
        self.drift = update if drift is None else drift
        self.adopt, self.adopt_all = {a.lower() for a in adopt}, adopt_all
        self.workers, self.status_polls = workers, max(1, status_polls)
        self.lookup, self.lookup_search_max_rows = lookup, lookup_search_max_rows
        self.checkpoint, self.resume = checkpoint, resume
        self.progress_every = max(0, progress_every)
        self.pvwa, self.pvwa_platform_id, self.pvwa_cpm_managed = pvwa, pvwa_platform_id, pvwa_cpm_managed
        self._get_password = get_password
        self._log = logger or logging.getLogger("sia.reconcile")
        self._sleep = sleep
        self._lock = threading.Lock()
        self._abort_reason: str | None = None
        self._owned_by_fqdn: dict[str, list[dict[str, Any]]] | None = None
        self._policy_list: list[dict[str, Any]] = []
        self._policies: dict[str, dict[str, Any]] = {}
        self._target_sets: dict[str, dict[str, Any]] = {}
        self._refs: dict[str, tuple[str | None, str]] = {}
        self._secrets: SecretIndex = SecretIndex([])
        self._template: dict[str, Any] | None = None
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
        self._template = self._load_template()
        self._plan_rows()
        fqdns = list(dict.fromkeys(s.fqdn for s, _ in self._rows))
        # Windows servers may share one target set (a Domain set covers a whole AD domain), so look them up by
        # target-set name rather than by FQDN.
        target_set_names = list(dict.fromkeys(s.target_set_key for s, _ in self._rows if not s.is_ssh))
        accounts = self._active_accounts()
        self._lookup_mode = self._choose_lookup(len(fqdns))
        self._snapshot_secrets(accounts)
        self._snapshot_target_sets(target_set_names, accounts)
        self._snapshot_policies(fqdns)
        self._log.info("Tenant snapshot (%s lookup): %d strong accounts, %d target sets, %d policies read for %d rows (%d resumed)",
                       self._lookup_mode, len(self._secrets), len(self._target_sets), len(self._policies), len(self._rows),
                       len(self._resumed))
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
        for key, (server, old, record) in self._resumed.items():
            sr = ServerResult(fqdn=old.fqdn, strong_account=old.strong_account, policy_name=old.policy_name,
                              protocol=old.protocol, line=old.line, target_set_name=old.target_set_name)
            statuses, refs, at = record.get("statuses") or {}, record.get("refs") or {}, record.get("at", "")
            for label in ("secret", "target_set", "policy"):
                status = statuses.get(label, "exists")
                note = f"checkpoint {at}: {status}"
                setattr(sr, label, Outcome(NOT_APPLICABLE if status == NOT_APPLICABLE else "exists", note, refs.get(label)))
            ordered[key] = sr
        for server, sr in self._rows:
            ordered[sr.key] = sr
        # keep CSV order
        result.servers = [ordered[(s.fqdn, policy_name_for(s, self.defaults))] for s in self.inputs.servers
                          if (s.fqdn, policy_name_for(s, self.defaults)) in ordered]
        self._flag_duplicate_policy_names(result)
        self._ensure_vault(result)
        self._ensure_secrets(result)
        self._ensure_target_sets(result)
        self._ensure_policies(result)
        return result

    # ------------------------------------------------------------ snapshot
    def _plan_rows(self) -> None:
        self._rows, self._resumed = [], {}
        for server in self.inputs.servers:
            name = policy_name_for(server, self.defaults)
            sr = ServerResult(fqdn=server.fqdn, strong_account=server.strong_account or "-", policy_name=name,
                              protocol=server.protocol, line=server.line,
                              target_set_name=("" if server.is_ssh else target_set_name_for(server)))
            if self.resume and self.checkpoint is not None:
                account = self.inputs.strong_accounts.get(server.strong_account or "")
                record = self.checkpoint.get(row_key(server.fqdn, name), fingerprint(server, account, name))
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
        with ThreadPoolExecutor(max_workers=min(self.workers, len(items)), thread_name_prefix="sia-read") as pool:
            return list(pool.map(fn, items))

    def _snapshot_secrets(self, accounts: list[StrongAccountRow]) -> None:
        if self._lookup_mode == "search":
            self._secrets = SecretIndex([])
            found = self._parallel(accounts, lambda a: self.sia.find_secret(a.sia_name))
            for secret in found:
                if secret:
                    self._secrets.add(secret)
        else:
            self._secrets = SecretIndex(self.sia.list_secrets())

    def _snapshot_target_sets(self, names: list[str], accounts: list[StrongAccountRow]) -> None:
        self._target_sets = {}
        if not names:
            return
        caps = getattr(self.sia, "capabilities", None)
        unfiltered = True if caps is None else bool(caps.targetsets_list_unfiltered)
        items: list[dict[str, Any]] = []
        if self._lookup_mode == "search" and unfiltered:
            for chunk in self._parallel(names, lambda n: self.sia.list_target_sets(name=n)):
                items.extend(chunk)
        elif unfiltered:
            items = self.sia.list_target_sets()
        else:
            secret_ids = sorted({secret_id_of(s) for s in (self._secrets.find(a) for a in accounts) if s})
            for chunk in self._parallel(secret_ids, lambda sid: self.sia.list_target_sets(strong_account_id=sid)):
                items.extend(chunk)
        for ts in items:
            name = str(pick(ts, "name", default="")).lower()
            if name:
                self._target_sets[name] = ts

    def _snapshot_policies(self, fqdns: list[str]) -> None:
        self._owned_by_fqdn = None
        if self._lookup_mode == "search":
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
            self._policy_list = list(seen.values())
        else:
            filter_query = UAP_VM_FILTER if self.adopt_all else owned_vm_filter(self.defaults.owner_tag)
            self._policy_list = self.uap.list_policies(filter_query=filter_query)
        self._policies = self._policies_by_name(self._policy_list)

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
        with self._lock:
            if self._abort_reason is None:
                self._abort_reason = reason
                assert self._result is not None
                self._result.aborted.append(reason)
                self._log.error("Aborting run (fail-fast): %s", reason)

    def _blocked_by_abort(self) -> Outcome:
        return Outcome("blocked", f"run aborted (fail-fast): {self._abort_reason}")

    def _systematic(self, exc: SIAApiError) -> bool:
        return self.fail_fast and exc.client_error and exc.status not in NON_SYSTEMATIC_4XX

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
        """Run `worker` over items: the first alone (canary), the rest sequentially or on a thread pool."""
        if not items:
            return
        total = len(items)

        def wrapped(item: Any) -> None:
            worker(item)
            if stage:
                self._tick(stage, total)

        rest = items
        if canary:
            wrapped(items[0])
            rest = items[1:]
        if not rest:
            return
        if self.workers <= 1:
            for item in rest:
                wrapped(item)
            return
        with ThreadPoolExecutor(max_workers=min(self.workers, len(rest)), thread_name_prefix="sia") as pool:
            list(pool.map(wrapped, rest))

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
                out[html.unescape(str(name))] = policy
        return out

    def _full_policy(self, policy: dict[str, Any]) -> dict[str, Any]:
        if "targets" in policy:
            return policy
        policy_id = pick(policy.get("metadata") or {}, "policyId", "policy_id")
        return self.uap.get_policy(str(policy_id)) if policy_id else policy

    def _owned_policy_for_fqdn(self, fqdn: str, claimed: set[str]) -> dict[str, Any] | None:
        """A managed policy (owner tag) whose EXACTLY rule targets this FQDN and whose name is not one this server's
        rows already use -- i.e. our policy under another name. Candidates without targets in the list object are
        fetched in full only when their description mentions the FQDN."""
        if self._owned_by_fqdn is None:
            with self._lock:
                if self._owned_by_fqdn is None:
                    self._owned_by_fqdn = self._build_owned_index()
        matches = [m for m in self._owned_by_fqdn.get(fqdn.lower(), [])
                   if html.unescape(str((m.get("metadata") or {}).get("name") or "")) not in claimed]
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
                try:
                    full = self._full_policy(policy)
                except SIAApiError as exc:
                    assert self._result is not None
                    self._result.warnings.append(f"could not read managed policy {pick(policy.get('metadata') or {}, 'policyId')}: {exc}")
                    continue
            for target in exact_fqdns(full):
                index.setdefault(target, []).append(full)
        return index

    def _checkpoint_row(self, server: ServerRow, sr: ServerResult) -> None:
        if self.checkpoint is None or self.dry_run:
            return
        account = self.inputs.strong_accounts.get(server.strong_account or "")
        self.checkpoint.record(
            row_key(sr.fqdn, sr.policy_name), fingerprint(server, account, sr.policy_name),
            {"secret": sr.secret.status, "target_set": sr.target_set.status, "policy": sr.policy.status},
            {"secret": sr.secret.ref, "target_set": sr.target_set.ref, "policy": sr.policy.ref})

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
        to_create: list[tuple[StrongAccountRow, dict[str, Any], str]] = []
        for account in accounts:
            what = f"Vault account {account.account_name!r} in safe {account.safe!r}"
            try:
                found = self.pvwa.find_account(account.safe or "", account.account_name or "")
            except SIAApiError as exc:
                result.vault[account.name] = Outcome("failed", f"lookup failed: {exc}")
                continue
            if found:
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
            created = self.pvwa.add_account(payload)
        except SIAApiError as exc:
            self._result.vault[account.name] = Outcome("failed", f"onboarding failed: {exc}")
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
            found = self._secrets.find(account)
            if found:
                sid, stype = secret_id_of(found), secret_type_of(found)
                detail = f"{stype} secret {sid} ({account.sia_name})"
                if account.secret_type and stype and account.secret_type != stype:
                    result.warnings.append(f"strong account {account.name!r}: CSV type={account.type} but SIA has {stype}; using SIA's type")
                if pick(found, "is_active", "isActive", default=True) is False:
                    result.warnings.append(f"strong account {account.name!r} ({sid}) is inactive in SIA")
                    detail += " (inactive)"
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
            created = self.sia.create_secret(payload)
        except SIAApiError as exc:
            self._result.secrets[account.name] = Outcome("failed", f"create failed: {exc}")
            if self._systematic(exc):
                self._abort(f"creating strong account {account.name!r}: {exc}")
            return
        sid = secret_id_of(created)
        with self._lock:
            self._secrets.add(created)
            self._refs[account.name] = (sid, secret_type_of(created) or account.secret_type or "")
        self._result.secrets[account.name] = Outcome("created", f"created {what} -> {sid}", sid)

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
            sr.secret = Outcome(found.status, found.detail, found.ref)
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
                sr.secret = Outcome(secret.status, secret.detail, secret.ref)
            if target_set is not None:
                sr.target_set = Outcome(target_set.status, target_set.detail, target_set.ref)

    def _reconcile_existing_target_set(self, server: ServerRow, sr: ServerResult, current: dict[str, Any],
                                       secret_id: str | None, secret_type: str, result: RunResult) -> Outcome:
        name = target_set_name_for(server)
        expected_type = server.target_set_type or "Target"
        current_secret = pick(current, "secret_id", "secretId")
        ts_type = pick(current, "type", default=expected_type)
        owned = is_owned_target_set(current, self.defaults.owner_tag)
        if str(ts_type) != expected_type:
            result.warnings.append(f"target set {name!r} exists with type={ts_type} (expected {expected_type})")
        if not secret_id or current_secret == secret_id:
            note = "" if owned else " (unmanaged: no owner marker)"
            return Outcome("exists", f"{ts_type} -> {server.strong_account}{note}", name)
        summary = f"points to secret {current_secret}, expected {secret_id} ({server.strong_account})"
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
            self.sia.update_target_set(name, build_target_set_update(server, secret_id, secret_type, self.defaults, current))
            return Outcome("updated", f"re-pointed to {server.strong_account} ({secret_id})", name)
        except SIAApiError as exc:
            if self._systematic(exc):
                self._abort(f"updating target set {name}: {exc}")
            return Outcome("failed", f"update failed: {exc}", name)

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
                    outcomes = self.sia.bulk_create_target_sets(build_bulk_target_sets({secret_id: chunk}))
                except SIAApiError as exc:
                    for name in names:
                        self._set_all(queued[name], target_set=Outcome("failed", f"bulk create failed: {exc}", name))
                    if self._systematic(exc):
                        self._abort(f"bulk-creating target sets for strong account {secret_id}: {exc}")
                    continue
                by_name = {str(pick(o, "target_set_name", "targetSetName", default="")).lower(): o for o in outcomes}
                kinds = {ts["name"]: ts["type"] for ts in chunk}
                for name in names:
                    item = by_name.get(name.lower())
                    account = queued[name][0].strong_account
                    if item is None:
                        outcome = Outcome("failed", "bulk create returned no result for this target set", name)
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
            claimed_by_fqdn.setdefault(server.fqdn, set()).add(sr.policy_name)
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
                principals = [self.resolver.resolve(g) for g in server.groups]
                desired = build_policy(server, principals, self.defaults, self._template)
            except (ResolveError, SIAApiError, ValueError) as exc:
                sr.policy = Outcome("failed", str(exc))
                self._checkpoint_row(server, sr)
                continue
            existing = self._policies.get(sr.policy_name)
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
                sr.policy = Outcome("planned", f"would create {server.protocol.upper()} policy for [{', '.join(server.groups)}] -> {server.fqdn}")
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
        groups = ", ".join(server.groups)
        try:
            policy_id = self.uap.create_policy(desired)
        except SIAApiError as exc:
            if self._is_conflict(exc) and self._reclassify_conflict(server, sr, desired):
                self._checkpoint_row(server, sr)
                return
            sr.policy = Outcome("failed", f"create failed: {exc}")
            if self._systematic(exc):
                self._abort(f"creating policy {sr.policy_name!r}: {exc}")
            self._checkpoint_row(server, sr)
            return
        with self._lock:
            self._policies[sr.policy_name] = {**desired, "metadata": {**desired["metadata"], "policyId": policy_id}}
        try:
            status, description = self._poll_status(policy_id)
        except SIAApiError as exc:
            sr.policy = Outcome("created", f"policy {policy_id} created; status unknown ({exc})", policy_id)
            self._checkpoint_row(server, sr)
            return
        detail = f"{server.protocol.upper()} policy {policy_id} for [{groups}], status={status}"
        if status.lower() == "error":
            sr.policy = Outcome("failed", f"{detail}: {description}", policy_id)
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
            self._policies[sr.policy_name] = found
        self._reconcile_existing_policy(sr, server, found, desired, False)
        return True

    def _reconcile_existing_policy(self, sr: ServerResult, server: ServerRow, existing: dict[str, Any],
                                   desired: dict[str, Any], renamed: bool) -> None:
        policy_id = str(pick(existing.get("metadata") or {}, "policyId", "policy_id", default=""))
        full = existing
        wants_full = self.drift or renamed or existing.get("principals") is None
        if wants_full and "targets" not in existing:
            try:
                full = self._full_policy(existing)
            except SIAApiError as exc:
                sr.policy = Outcome("failed", f"could not read existing policy {policy_id}: {exc}", policy_id)
                return
        owned = is_owned_policy(full, self.defaults.owner_tag)
        adopted = self._adopted(server, sr)
        current_sig, desired_sig = policy_signature(full), policy_signature(desired)
        diff: list[str] = []
        checked = ["name"]
        if renamed:
            diff.append(f"named {(full.get('metadata') or {}).get('name')!r} instead of {sr.policy_name!r} (renamed)")
        if current_sig["principals"] is not None:
            checked.append("principals")
            if current_sig["principals"] != desired_sig["principals"]:
                diff.append("principals differ")
        if current_sig["fqdn_rules"] is not None:
            checked.append("targets")
            if current_sig["fqdn_rules"] != desired_sig["fqdn_rules"]:
                diff.append("FQDN rules differ")
        status = policy_status(full)
        status_note = "" if status in ("", "Active", "Validating") else f"; status={status}"
        ok_status = "exists" if not status_note else "inactive"
        if not diff:
            if owned or not (self.update and adopted):
                note = "" if owned else " (unmanaged: no owner tag; pass --adopt to take ownership)"
                hint = "" if "targets" in checked else "; add --drift to compare targets"
                sr.policy = Outcome(ok_status, f"policy {policy_id} up to date ({', '.join(checked)} checked{hint}){note}{status_note}", policy_id)
                return
            diff.append("adopting (adds owner tag)")
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
        if self.dry_run:
            sr.policy = Outcome("planned", f"would update policy {policy_id}: {summary}", policy_id)
            return
        try:
            self.uap.update_policy(policy_id, build_policy_update(full, desired))
            sr.policy = Outcome("updated", f"policy {policy_id}: {summary}", policy_id)
        except SIAApiError as exc:
            sr.policy = Outcome("failed", f"update failed: {exc}", policy_id)
            if self._systematic(exc):
                self._abort(f"updating policy {sr.policy_name!r}: {exc}")

    def _poll_status(self, policy_id: str) -> tuple[str, str]:
        status, description = "unknown", ""
        for attempt in range(self.status_polls):
            policy = self.uap.get_policy(policy_id)
            st = ((policy.get("metadata") or {}).get("status") or {})
            status = str(st.get("status") or "unknown")
            description = str(st.get("statusDescription") or st.get("status_description") or "")
            if status.lower() != "validating":
                break
            if attempt < self.status_polls - 1:
                self._sleep(POLICY_STATUS_POLL_SECONDS)
        return status, description
