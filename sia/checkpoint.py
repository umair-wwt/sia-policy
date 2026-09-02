"""Checkpoint file for long runs: one JSON line per server row, so an interrupted `apply` can `--resume`.

The file lives next to the input CSVs (<input dir>/.sia-checkpoint.jsonl by default). A row is skipped on resume
only when its fingerprint (the inputs that shape its objects) still matches and every object reached a final,
good state. It contains no secrets: names, statuses and object ids only.
"""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .inputs import ServerRow, StrongAccountRow

DEFAULT_NAME = ".sia-checkpoint.jsonl"
DONE_STATUSES = frozenset({"created", "exists", "updated", "n/a"})


def row_key(fqdn: str, policy_name: str) -> str:
    return f"{fqdn}|{policy_name}"


def fingerprint(server: ServerRow, account: StrongAccountRow | None, policy_name: str) -> str:
    """Hash of everything in the CSVs that determines the row's objects (line numbers excluded)."""
    data: dict[str, Any] = {k: v for k, v in asdict(server).items() if k != "line"}
    data["policy_name_effective"] = policy_name
    if account is not None:
        data["account"] = {k: v for k, v in asdict(account).items() if k not in ("line", "password_env")}
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def is_done(record: dict[str, Any]) -> bool:
    statuses = record.get("statuses") or {}
    return bool(statuses) and all(status in DONE_STATUSES for status in statuses.values())


class Checkpoint:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._records: dict[str, dict[str, Any]] = {}
        self._loaded = False

    def load(self) -> dict[str, dict[str, Any]]:
        """Read the file (later lines override earlier ones); malformed lines are ignored."""
        with self._lock:
            self._records = {}
            if self.path.is_file():
                for line in self.path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(record, dict) and record.get("key"):
                        self._records[str(record["key"])] = record
            self._loaded = True
            return dict(self._records)

    def get(self, key: str, fp: str) -> dict[str, Any] | None:
        if not self._loaded:
            self.load()
        record = self._records.get(key)
        if record and record.get("fingerprint") == fp:
            return record
        return None

    def record(self, key: str, fp: str, statuses: dict[str, str], refs: dict[str, str | None]) -> None:
        entry = {"key": key, "fingerprint": fp, "statuses": statuses, "refs": {k: v for k, v in refs.items() if v},
                 "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        line = json.dumps(entry, sort_keys=True)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
            self._records[key] = entry

    def __len__(self) -> int:
        if not self._loaded:
            self.load()
        return len(self._records)

    def done_count(self) -> int:
        if not self._loaded:
            self.load()
        return sum(1 for record in self._records.values() if is_done(record))
