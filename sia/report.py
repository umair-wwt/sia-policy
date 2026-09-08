"""Human-readable summary on stdout plus machine-readable JSON/CSV reports (no secrets are ever included).

Large runs: the console shows totals plus the noteworthy rows only, the CSV always has every row, and the JSON
carries per-row detail up to `json_max_rows` rows (counts and failures beyond that).
"""
from __future__ import annotations

import csv
import io
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from .diagnostics import Diagnostic, render_diagnostic
from .reconcile import Outcome, RunResult, ServerResult
from .redact import sanitize
from .artifacts import ArtifactWriteError, write_artifacts

_DETAIL_STATUSES = {"failed", "blocked", "drift", "planned", "updated", "created", "skipped", "inactive",
                    "uncertain", "unverified"}
_QUIET_STATUSES = {"exists", "n/a"}
CSV_COLUMNS = ("fqdn", "strong_account", "target_set_name", "policy_name", "secret_status", "secret_detail",
               "target_set_status", "target_set_detail", "policy_status", "policy_detail", "policy_id")
VERIFY_COLUMNS = ("fqdn", "policy_name", "strong_account", "secret", "target_set", "policy", "verdict", "policy_id", "detail")
VERDICT_BY_STATUS = {"exists": "PASS", "created": "PASS", "updated": "PASS", "n/a": "PASS", "planned": "MISSING",
                     "drift": "FAIL", "failed": "FAIL", "blocked": "FAIL", "inactive": "FAIL", "skipped": "SKIP",
                     "uncertain": "FAIL", "unverified": "FAIL"}
_DIAGNOSTIC_STATUSES = frozenset({"failed", "blocked", "inactive", "uncertain", "unverified", "drift"})


@dataclass(frozen=True)
class ReportPaths:
    """The two artifact paths reserved for one operation report."""

    json_path: Path
    csv_path: Path

    def as_tuple(self) -> tuple[Path, Path]:
        return self.json_path, self.csv_path

    def to_dict(self) -> dict[str, str]:
        return {"json": str(self.json_path), "csv": str(self.csv_path)}


class ReportWriteError(OSError):
    """Report persistence failed after the tenant operation had already completed."""

    def __init__(self, path: Path, cause: BaseException, *, paths: ReportPaths,
                 completed_paths: tuple[Path, ...] = ()):
        self.path = Path(path)
        self.paths = paths
        self.intended_paths = paths.as_tuple()
        self.completed_paths = tuple(completed_paths)
        self.cause = cause
        self.interrupted = isinstance(cause, KeyboardInterrupt) or bool(getattr(cause, "interrupted", False))
        message = f"could not write report {self.path}: {sanitize(str(cause))}"
        super().__init__(message)
        self.errno = getattr(cause, "errno", None)
        self.filename = str(self.path)


def _cell(outcome: Outcome) -> str:
    return outcome.status


def _outcome_dict(outcome: Outcome) -> dict[str, object]:
    data = dict(vars(outcome))
    if not data.get("diagnostic"):
        data.pop("diagnostic", None)
    return sanitize(data)


def _diagnostic_from_outcome(stage: str, object_name: str, outcome: Outcome) -> Diagnostic | None:
    if outcome.status not in _DIAGNOSTIC_STATUSES:
        return None
    existing = getattr(outcome, "diagnostic", None)
    if isinstance(existing, Diagnostic):
        return existing
    if isinstance(existing, dict):
        try:
            return Diagnostic(**existing)
        except (TypeError, ValueError):
            pass
    code_by_status = {
        "drift": "SIA-DRIFT",
        "inactive": "SIA-INACTIVE",
        "blocked": "SIA-BLOCKED",
        "uncertain": "SIA-UNCERTAIN",
        "unverified": "SIA-UNVERIFIED",
        "failed": "SIA-ITEM-FAILED",
    }
    inactive_action = (("Check whether the policy's platform status is intentionally Suspended. To activate it, preview "
                        "with `sia plan --update --set-policy-status Active`, then apply the same flags.")
                       if stage == "policies" else
                       "Activate or repair the strong account, then run `sia plan` again.")
    actions_by_status = {
        "drift": ("Review the differences, then use --update for an object this tool manages.",),
        "inactive": (inactive_action,),
        "blocked": ("Correct the prerequisite failure shown earlier, then run `sia plan` again.",),
        "uncertain": ("Do not repeat the mutation; run `sia plan` to reconcile current tenant state.",),
        "unverified": ("Run `sia plan --drift` and confirm the object identifier and requested state.",),
        "failed": ("Correct the reported cause, then run `sia plan` before applying again.",),
    }
    state = {"blocked": "not_applied", "uncertain": "unknown", "unverified": "unknown"}.get(
        outcome.status, "not_applicable")
    if outcome.status == "inactive" and stage == "policies" and "fields were updated" in outcome.detail:
        state = "applied"
    return Diagnostic(
        code=code_by_status[outcome.status],
        message=outcome.detail or f"{stage} {outcome.status}",
        actions=actions_by_status[outcome.status],
        stage=stage,
        object_name=object_name,
        mutation_state=state,
        details={"status": outcome.status, "reference": outcome.ref or ""},
    )


def result_diagnostics(result: RunResult) -> list[Diagnostic]:
    """Return one diagnostic per noteworthy object, without duplicating shared objects."""
    found: list[Diagnostic] = [Diagnostic(**item) for item in result.diagnostics]
    for stage, outcomes in (("vault", result.vault), ("strong accounts", result.secrets)):
        for name, outcome in outcomes.items():
            diagnostic = _diagnostic_from_outcome(stage, name, outcome)
            if diagnostic:
                found.append(diagnostic)
    seen_target_sets: set[str] = set()
    for sr in result.servers:
        if sr.target_set_key not in seen_target_sets:
            seen_target_sets.add(sr.target_set_key)
            diagnostic = _diagnostic_from_outcome("target sets", sr.target_set_name or sr.fqdn, sr.target_set)
            if diagnostic:
                found.append(diagnostic)
        diagnostic = _diagnostic_from_outcome("policies", sr.policy_name, sr.policy)
        if diagnostic:
            found.append(diagnostic)
    return found


def _print_result_diagnostics(result: RunResult, out: TextIO, max_rows: int) -> None:
    diagnostics = result_diagnostics(result)
    if not diagnostics:
        return
    shown = diagnostics[:min(max_rows, 10)]
    print("\nTroubleshooting:", file=out)
    for diagnostic in shown:
        render_diagnostic(diagnostic, out)
    if len(shown) < len(diagnostics):
        print(f"\n  ... {len(diagnostics) - len(shown)} more diagnostic(s) in the JSON report", file=out)


def _noteworthy(sr: ServerResult) -> bool:
    return any(o.status not in _QUIET_STATUSES or "unmanaged" in o.detail for o in (sr.secret, sr.target_set, sr.policy))


def _print_accounts(title: str, outcomes: dict[str, Outcome], out: TextIO, max_rows: int) -> None:
    if not outcomes:
        return
    print(f"\n{title}:", file=out)
    width = max(len(n) for n in outcomes)
    shown = 0
    for name, outcome in outcomes.items():
        if shown >= max_rows and outcome.status in _QUIET_STATUSES:
            continue
        print(f"  {sanitize(name):<{width}}  {outcome.status:<8} {sanitize(outcome.detail)}", file=out)
        shown += 1
    if shown < len(outcomes):
        print(f"  ... {len(outcomes) - shown} more (see the JSON report)", file=out)


def print_summary(result: RunResult, out: TextIO | None = None, *, max_rows: int = 200) -> None:
    out = out or sys.stdout  # resolve at call time so redirected/captured stdout is honoured
    title = "PLAN (dry run — nothing was changed)" if result.mode == "plan" else "APPLY"
    print(f"\n== {title} ==", file=out)
    if result.lookup_mode:
        print(f"Lookup mode: {result.lookup_mode}", file=out)
    if result.resumed:
        print(f"Resumed from checkpoint: {result.resumed} row(s) already complete, not re-checked", file=out)
    _print_accounts("Vault accounts", result.vault, out, max_rows)
    _print_accounts("Strong accounts", result.secrets, out, max_rows)
    if result.servers:
        servers = result.servers
        hidden = 0
        if len(servers) > max_rows:
            shown = [sr for sr in servers if _noteworthy(sr)][:max_rows]
            hidden = len(servers) - len(shown)
            servers = shown
        headers = ("Server", "Strong account", "Policy", "Secret", "Target set", "Policy")
        rows = [(str(sanitize(sr.fqdn)), str(sanitize(sr.strong_account)), str(sanitize(sr.policy_name)),
                 _cell(sr.secret), _cell(sr.target_set), _cell(sr.policy))
                for sr in servers]
        widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
        line = "  ".join(f"{h:<{w}}" for h, w in zip(headers, widths, strict=True))
        print(f"\nServers:\n  {line}\n  {'-' * len(line)}", file=out)
        for r in rows:
            print("  " + "  ".join(f"{c:<{w}}" for c, w in zip(r, widths, strict=True)), file=out)
        if hidden:
            print(f"  ... {hidden} row(s) with nothing to report not shown (see the CSV report)", file=out)
        details = []
        seen_target_sets: set[str] = set()
        for sr in servers:
            items = [("policy", sr.policy)]
            if sr.target_set_key not in seen_target_sets:   # one target set, however many rows and servers use it
                seen_target_sets.add(sr.target_set_key)
                items.insert(0, ("target set", sr.target_set))
            for label, outcome in items:
                noteworthy = outcome.status in _DETAIL_STATUSES or "unmanaged" in outcome.detail
                if noteworthy and outcome.detail:
                    details.append(str(sanitize(
                        f"  {sr.fqdn} [{sr.policy_name}]: {label} {outcome.status} — {outcome.detail}")))
        if details:
            print("\nDetails:", file=out)
            print("\n".join(details[:max_rows]), file=out)
            if len(details) > max_rows:
                print(f"  ... {len(details) - max_rows} more (see the CSV report)", file=out)
    if result.aborted:
        print("\nRun aborted (fail-fast); remaining changes were not attempted:", file=out)
        for reason in result.aborted:
            print(f"  ! {sanitize(reason)}", file=out)
    if result.warnings:
        print("\nWarnings:", file=out)
        for w in result.warnings[:max_rows]:
            print(f"  - {sanitize(w)}", file=out)
        if len(result.warnings) > max_rows:
            print(f"  ... {len(result.warnings) - max_rows} more warnings (see the JSON report)", file=out)
    _print_result_diagnostics(result, out, max_rows)
    totals = _totals(result)
    print(f"\nSummary: {totals}", file=out)
    if result.failures:
        print(f"{result.failures} item(s) need attention.", file=out)


def _counts(result: RunResult) -> dict[str, int]:
    """Objects by status: strong accounts and Vault accounts once each, target sets once per *set* (a Domain set
    shared by a whole AD domain counts once, not once per server), policies per row."""
    counts: dict[str, int] = {}
    seen_target_sets: set[str] = set()
    for sr in result.servers:
        outcomes = [sr.policy]
        if sr.target_set_key not in seen_target_sets:
            seen_target_sets.add(sr.target_set_key)
            outcomes.append(sr.target_set)
        for outcome in outcomes:
            counts[outcome.status] = counts.get(outcome.status, 0) + 1
    for outcome in list(result.secrets.values()) + list(result.vault.values()):
        counts[outcome.status] = counts.get(outcome.status, 0) + 1
    return counts


def _totals(result: RunResult) -> str:
    return ", ".join(f"{k}={v}" for k, v in sorted(_counts(result).items())) or "nothing to do"


def _server_dict(sr: ServerResult) -> dict:
    return sanitize({"fqdn": sr.fqdn, "strong_account": sr.strong_account, "policy_name": sr.policy_name,
                     "protocol": sr.protocol, "target_set_name": sr.target_set_name or sr.fqdn,
                     "secret": _outcome_dict(sr.secret), "target_set": _outcome_dict(sr.target_set),
                     "policy": _outcome_dict(sr.policy)})


def result_dict(result: RunResult, *, json_max_rows: int = 10_000) -> dict:
    """The whole run as plain data: written to reports/<mode>-<stamp>.json, and printed by --json."""
    data: dict = {
        "mode": result.mode,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "lookup_mode": result.lookup_mode,
        "complete": not result.incomplete,
        "interrupted": result.interrupted,
        "resumed": result.resumed,
        "rows": len(result.servers),
        "failures": result.failures,
        "counts": _counts(result),
        "aborted": result.aborted,
        "warnings": result.warnings,
        "vault_accounts": {name: _outcome_dict(o) for name, o in result.vault.items()},
        "strong_accounts": {name: _outcome_dict(o) for name, o in result.secrets.items()},
        "diagnostics": [diagnostic.to_dict() for diagnostic in result_diagnostics(result)],
    }
    if len(result.servers) <= json_max_rows:
        data["servers"] = [_server_dict(sr) for sr in result.servers]
    else:
        data["servers"] = f"{len(result.servers)} rows: see the CSV report"
        data["servers_needing_attention"] = [_server_dict(sr) for sr in result.servers if not sr.ok][:json_max_rows]
    return sanitize(data)


def report_paths(report_dir: str | Path, mode: str, *, at: datetime | None = None) -> ReportPaths:
    """Choose a non-colliding JSON/CSV pair without creating either file."""
    directory = Path(report_dir)
    stamp = (at or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    stem = f"{mode}-{stamp}"
    sequence = 0
    while True:
        suffix = f"-{sequence:02d}" if sequence else ""
        base = directory / f"{stem}{suffix}"
        paths = ReportPaths(base.with_suffix(".json"), base.with_suffix(".csv"))
        if not paths.json_path.exists() and not paths.csv_path.exists():
            return paths
        sequence += 1


def write_reports(result: RunResult, report_dir: str | Path, *, json_max_rows: int = 10_000) -> tuple[Path, Path]:
    paths = report_paths(report_dir, result.mode)
    try:
        paths.json_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ReportWriteError(paths.json_path.parent, exc, paths=paths) from exc

    # Build both payloads before opening a destination.  This keeps formatting
    # failures from leaving a file that looks like a complete report.
    try:
        json_text = json.dumps(result_dict(result, json_max_rows=json_max_rows), indent=2)
        csv_buffer = io.StringIO(newline="")
        writer = csv.writer(csv_buffer)
        writer.writerow(CSV_COLUMNS)
        for sr in result.servers:
            writer.writerow(sanitize([sr.fqdn, sr.strong_account, sr.target_set_name or sr.fqdn, sr.policy_name,
                                      sr.secret.status, sr.secret.detail, sr.target_set.status, sr.target_set.detail,
                                      sr.policy.status, sr.policy.detail, sr.policy.ref or ""]))
        csv_text = csv_buffer.getvalue()
    except (TypeError, ValueError, csv.Error, KeyboardInterrupt) as exc:
        raise ReportWriteError(paths.json_path, exc, paths=paths) from exc

    for _ in range(100):
        try:
            write_artifacts([(paths.json_path, json_text.encode("utf-8")), (paths.csv_path, csv_text.encode("utf-8"))],
                            exclusive=paths.as_tuple())
        except ArtifactWriteError as exc:
            if isinstance(exc.cause, FileExistsError) and not exc.completed_paths:
                paths = report_paths(report_dir, result.mode)
                continue
            raise ReportWriteError(exc.path, exc.cause, paths=paths, completed_paths=exc.completed_paths) from exc
        return paths.as_tuple()
    raise ReportWriteError(paths.json_path, FileExistsError("Could not reserve a unique report name; try again"), paths=paths)


def exit_code(result: RunResult) -> int:
    return 130 if result.interrupted else 1 if result.failures or result.incomplete or result.aborted else 0


# ------------------------------------------------------------------ verify

def verdict_for(sr: ServerResult) -> tuple[str, str]:
    """(verdict, detail) for one row: FAIL beats MISSING beats SKIP beats PASS."""
    worst, detail = "PASS", ""
    order = {"PASS": 0, "SKIP": 1, "MISSING": 2, "FAIL": 3}
    for label, outcome in (("strong account", sr.secret), ("target set", sr.target_set), ("policy", sr.policy)):
        verdict = VERDICT_BY_STATUS.get(outcome.status, "FAIL")
        if order[verdict] > order[worst]:
            worst, detail = verdict, f"{label} {outcome.status}: {outcome.detail}"
    return worst, detail


def verify_rows(result: RunResult) -> list[list[str]]:
    rows = []
    for sr in result.servers:
        verdict, detail = verdict_for(sr)
        rows.append(sanitize([sr.fqdn, sr.policy_name, sr.strong_account, sr.secret.status, sr.target_set.status,
                              sr.policy.status, verdict, sr.policy.ref or "", detail]))
    return rows


def print_verify(result: RunResult, out: TextIO | None = None, *, max_rows: int = 200) -> int:
    """Print the PASS/FAIL table; returns the number of rows that are not PASS."""
    out = out or sys.stdout
    rows = verify_rows(result)
    counts: dict[str, int] = {}
    for row in rows:
        counts[row[6]] = counts.get(row[6], 0) + 1
    print("\n== VERIFY ==", file=out)
    if result.lookup_mode:
        print(f"Lookup mode: {result.lookup_mode}", file=out)
    problems = [row for row in rows if row[6] != "PASS"]
    shown = problems if len(rows) > max_rows else rows
    if shown:
        headers = ("Server", "Policy", "Strong account", "Secret", "Target set", "Policy", "Verdict")
        widths = [max(len(h), *(len(r[i]) for r in shown)) for i, h in enumerate(headers)]
        line = "  ".join(f"{h:<{w}}" for h, w in zip(headers, widths, strict=True))
        print(f"  {line}\n  {'-' * len(line)}", file=out)
        for row in shown[:max_rows]:
            print("  " + "  ".join(f"{c:<{w}}" for c, w in zip(row[:7], widths, strict=True)), file=out)
        if len(shown) > max_rows:
            print(f"  ... {len(shown) - max_rows} more (see the CSV)", file=out)
    if problems:
        print("\nDetails:", file=out)
        for row in problems[:max_rows]:
            print(f"  {row[0]} [{row[1]}]: {row[6]} — {row[8]}", file=out)
    if result.warnings:
        print("\nWarnings:", file=out)
        for w in result.warnings[:max_rows]:
            print(f"  - {sanitize(w)}", file=out)
    _print_result_diagnostics(result, out, max_rows)
    print("\nVerify: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) + f" (rows={len(rows)})", file=out)
    return len(problems)


def write_verify_csv(result: RunResult, path: str | Path) -> Path:
    path = Path(path)
    paths = ReportPaths(path.with_suffix(".json"), path)
    try:
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer)
        writer.writerow(VERIFY_COLUMNS)
        writer.writerows(verify_rows(result))
        write_artifacts([(path, buffer.getvalue().encode("utf-8"))])
    except (OSError, csv.Error) as exc:
        raise ReportWriteError(path, exc, paths=paths) from exc
    return path
