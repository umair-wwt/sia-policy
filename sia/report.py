"""Human-readable summary on stdout plus machine-readable JSON/CSV reports (no secrets are ever included).

Large runs: the console shows totals plus the noteworthy rows only, the CSV always has every row, and the JSON
carries per-row detail up to `json_max_rows` rows (counts and failures beyond that).
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from .reconcile import Outcome, RunResult, ServerResult

_DETAIL_STATUSES = {"failed", "blocked", "drift", "planned", "updated", "created", "skipped", "inactive"}
_QUIET_STATUSES = {"exists", "n/a"}
CSV_COLUMNS = ("fqdn", "strong_account", "target_set_name", "policy_name", "secret_status", "secret_detail",
               "target_set_status", "target_set_detail", "policy_status", "policy_detail", "policy_id")
VERIFY_COLUMNS = ("fqdn", "policy_name", "strong_account", "secret", "target_set", "policy", "verdict", "policy_id", "detail")
VERDICT_BY_STATUS = {"exists": "PASS", "created": "PASS", "updated": "PASS", "n/a": "PASS", "planned": "MISSING",
                     "drift": "FAIL", "failed": "FAIL", "blocked": "FAIL", "inactive": "FAIL", "skipped": "SKIP"}


def _cell(outcome: Outcome) -> str:
    return outcome.status


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
        print(f"  {name:<{width}}  {outcome.status:<8} {outcome.detail}", file=out)
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
        rows = [(sr.fqdn, sr.strong_account, sr.policy_name, _cell(sr.secret), _cell(sr.target_set), _cell(sr.policy))
                for sr in servers]
        widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
        line = "  ".join(f"{h:<{w}}" for h, w in zip(headers, widths))
        print(f"\nServers:\n  {line}\n  {'-' * len(line)}", file=out)
        for r in rows:
            print("  " + "  ".join(f"{c:<{w}}" for c, w in zip(r, widths)), file=out)
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
                    details.append(f"  {sr.fqdn} [{sr.policy_name}]: {label} {outcome.status} — {outcome.detail}")
        if details:
            print("\nDetails:", file=out)
            print("\n".join(details[:max_rows]), file=out)
            if len(details) > max_rows:
                print(f"  ... {len(details) - max_rows} more (see the CSV report)", file=out)
    if result.aborted:
        print("\nRun aborted (fail-fast); remaining changes were not attempted:", file=out)
        for reason in result.aborted:
            print(f"  ! {reason}", file=out)
    if result.warnings:
        print("\nWarnings:", file=out)
        for w in result.warnings[:max_rows]:
            print(f"  - {w}", file=out)
        if len(result.warnings) > max_rows:
            print(f"  ... {len(result.warnings) - max_rows} more warnings (see the JSON report)", file=out)
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
    return {"fqdn": sr.fqdn, "strong_account": sr.strong_account, "policy_name": sr.policy_name, "protocol": sr.protocol,
            "target_set_name": sr.target_set_name or sr.fqdn,
            "secret": vars(sr.secret), "target_set": vars(sr.target_set), "policy": vars(sr.policy)}


def result_dict(result: RunResult, *, json_max_rows: int = 10_000) -> dict:
    """The whole run as plain data: written to reports/<mode>-<stamp>.json, and printed by --json."""
    data: dict = {
        "mode": result.mode,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "lookup_mode": result.lookup_mode,
        "resumed": result.resumed,
        "rows": len(result.servers),
        "failures": result.failures,
        "counts": _counts(result),
        "aborted": result.aborted,
        "warnings": result.warnings,
        "vault_accounts": {name: vars(o) for name, o in result.vault.items()},
        "strong_accounts": {name: vars(o) for name, o in result.secrets.items()},
    }
    if len(result.servers) <= json_max_rows:
        data["servers"] = [_server_dict(sr) for sr in result.servers]
    else:
        data["servers"] = f"{len(result.servers)} rows: see the CSV report"
        data["servers_needing_attention"] = [_server_dict(sr) for sr in result.servers if not sr.ok][:json_max_rows]
    return data


def write_reports(result: RunResult, report_dir: str | Path, *, json_max_rows: int = 10_000) -> tuple[Path, Path]:
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = report_dir / f"{result.mode}-{stamp}"
    data = result_dict(result, json_max_rows=json_max_rows)
    json_path = base.with_suffix(".json")
    with json_path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    csv_path = base.with_suffix(".csv")
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_COLUMNS)
        for sr in result.servers:
            writer.writerow([sr.fqdn, sr.strong_account, sr.target_set_name or sr.fqdn, sr.policy_name,
                             sr.secret.status, sr.secret.detail, sr.target_set.status, sr.target_set.detail,
                             sr.policy.status, sr.policy.detail, sr.policy.ref or ""])
    return json_path, csv_path


def exit_code(result: RunResult) -> int:
    return 1 if result.failures else 0


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
        rows.append([sr.fqdn, sr.policy_name, sr.strong_account, sr.secret.status, sr.target_set.status, sr.policy.status,
                     verdict, sr.policy.ref or "", detail])
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
        line = "  ".join(f"{h:<{w}}" for h, w in zip(headers, widths))
        print(f"  {line}\n  {'-' * len(line)}", file=out)
        for row in shown[:max_rows]:
            print("  " + "  ".join(f"{c:<{w}}" for c, w in zip(row[:7], widths)), file=out)
        if len(shown) > max_rows:
            print(f"  ... {len(shown) - max_rows} more (see the CSV)", file=out)
    if problems:
        print("\nDetails:", file=out)
        for row in problems[:max_rows]:
            print(f"  {row[0]} [{row[1]}]: {row[6]} — {row[8]}", file=out)
    if result.warnings:
        print("\nWarnings:", file=out)
        for w in result.warnings[:max_rows]:
            print(f"  - {w}", file=out)
    print("\nVerify: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) + f" (rows={len(rows)})", file=out)
    return len(problems)


def write_verify_csv(result: RunResult, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(VERIFY_COLUMNS)
        writer.writerows(verify_rows(result))
    return path
