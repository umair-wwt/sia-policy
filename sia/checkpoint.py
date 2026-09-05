"""Checkpoint file for long runs: one JSON line per server row, so an interrupted `apply` can `--resume`.

The file lives next to the input CSVs (<input dir>/.sia-checkpoint.jsonl by default). A row is skipped on resume
only when its fingerprint (the inputs that shape its objects) still matches and every object reached a final,
good state. It contains no secrets: names, statuses and object ids only.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .inputs import ServerRow, StrongAccountRow

DEFAULT_NAME = ".sia-checkpoint.jsonl"
CHECKPOINT_VERSION = 2
STAGE_NAMES = frozenset({"secret", "target_set", "policy"})
DONE_STATUSES = frozenset({"created", "exists", "updated", "n/a"})


class CheckpointWriteError(OSError):
    """A checkpoint could not be persisted after the named row reached the supplied states."""

    def __init__(self, path: Path, key: str, statuses: dict[str, str], refs: dict[str, str | None], cause: OSError):
        self.path = Path(path)
        self.row_key = key
        self.statuses = dict(statuses)
        self.refs = {name: value for name, value in refs.items() if value}
        self.cause = cause
        self.mutation_state = "applied" if any(status in {"created", "updated"} for status in statuses.values()) else "unknown"
        super().__init__(f"could not save checkpoint for {key} at {self.path}: {cause}")
        self.errno = getattr(cause, "errno", None)
        self.filename = str(self.path)


def row_key(fqdn: str, policy_name: str) -> str:
    return f"{fqdn}|{policy_name}"


def _without_lines(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _without_lines(item) for key, item in value.items() if key != "line"}
    if isinstance(value, (list, tuple)):
        return [_without_lines(item) for item in value]
    return value


def fingerprint(server: ServerRow, account: StrongAccountRow | None, policy_name: str,
                context: dict[str, Any] | None = None) -> str:
    """Hash of every local value that determines a row's objects (source line numbers excluded)."""
    data: dict[str, Any] = {k: v for k, v in asdict(server).items() if k != "line"}
    data["policy_name_effective"] = policy_name
    if account is not None:
        data["account"] = {k: v for k, v in asdict(account).items() if k != "line"}
    if context:
        data["reconciliation_context"] = _without_lines(context)
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def is_done(record: dict[str, Any]) -> bool:
    statuses = record.get("statuses") or {}
    return (record.get("version") == CHECKPOINT_VERSION and isinstance(statuses, dict)
            and set(statuses) == STAGE_NAMES and all(status in DONE_STATUSES for status in statuses.values()))


class Checkpoint:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._records: dict[str, dict[str, Any]] = {}
        self._loaded = False
        self._warnings: list[str] = []
        self._warning_keys: set[str] = set()

    @property
    def warnings(self) -> tuple[str, ...]:
        if not self._loaded:
            self.load()
        return tuple(self._warnings)

    def _warn(self, key: str, message: str) -> None:
        if key not in self._warning_keys:
            self._warning_keys.add(key)
            self._warnings.append(message)

    @staticmethod
    def _record_problem(record: dict[str, Any]) -> str | None:
        if record.get("version") != CHECKPOINT_VERSION:
            return f"unsupported checkpoint version {record.get('version')!r}; expected {CHECKPOINT_VERSION}"
        fp = record.get("fingerprint")
        if not isinstance(fp, str) or len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp.lower()):
            return "missing or invalid fingerprint"
        statuses = record.get("statuses")
        if not isinstance(statuses, dict) or set(statuses) != STAGE_NAMES:
            return "statuses must contain exactly secret, target_set, and policy"
        if not all(isinstance(value, str) for value in statuses.values()):
            return "every status must be text"
        refs = record.get("refs")
        if not isinstance(refs, dict):
            return "refs must be an object"
        for stage, status in statuses.items():
            if status in DONE_STATUSES - {"n/a"} and not refs.get(stage):
                return f"completed stage {stage} has no object reference"
        if not isinstance(record.get("at"), str) or not record.get("at"):
            return "missing completion timestamp"
        return None

    def load(self) -> dict[str, dict[str, Any]]:
        """Read the file (later lines override earlier ones); malformed lines are ignored."""
        with self._lock:
            self._records = {}
            self._warnings = []
            self._warning_keys = set()
            if self.path.is_file():
                for line_number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        self._warn(f"line:{line_number}",
                                   f"checkpoint {self.path}: line {line_number} is not valid JSON; reconciling it again")
                        continue
                    if isinstance(record, dict) and record.get("key"):
                        self._records[str(record["key"])] = record
                    else:
                        self._warn(f"line:{line_number}",
                                   f"checkpoint {self.path}: line {line_number} has no row key; ignoring it")
            self._loaded = True
            return dict(self._records)

    def get(self, key: str, fp: str) -> dict[str, Any] | None:
        if not self._loaded:
            self.load()
        record = self._records.get(key)
        if record:
            problem = self._record_problem(record)
            if problem:
                self._warn(f"invalid:{key}", f"checkpoint row {key}: {problem}; reconciling it again")
                return None
            if record.get("fingerprint") != fp:
                self._warn(f"stale:{key}",
                           f"checkpoint row {key}: settings, template, tenant, or input changed; reconciling it again")
                return None
            return record
        return None

    def record(self, key: str, fp: str, statuses: dict[str, str], refs: dict[str, str | None]) -> None:
        entry = {"version": CHECKPOINT_VERSION, "key": key, "fingerprint": fp, "statuses": statuses,
                 "refs": {k: v for k, v in refs.items() if v},
                 "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        line = json.dumps(entry, sort_keys=True)
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                self._records[key] = entry
        except OSError as exc:
            raise CheckpointWriteError(self.path, key, statuses, refs, exc) from exc

    def check_writable(self) -> tuple[bool, str]:
        """Probe checkpoint-directory writability without modifying an existing checkpoint."""
        probe_path: str | None = None
        try:
            if self.path.exists() and not self.path.is_file():
                return False, f"checkpoint path is not a regular file: {self.path}"
            if self.path.is_file() and not os.access(self.path, os.W_OK):
                return False, f"existing checkpoint file is not writable: {self.path}"
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, probe_path = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".probe", dir=self.path.parent)
            os.close(fd)
            Path(probe_path).unlink()
            return True, f"checkpoint directory is writable: {self.path.parent}"
        except OSError as exc:
            if probe_path:
                try:
                    Path(probe_path).unlink(missing_ok=True)
                except OSError:
                    pass
            return False, f"cannot write checkpoint beside {self.path}: {exc}"

    def __len__(self) -> int:
        if not self._loaded:
            self.load()
        return len(self._records)

    def done_count(self) -> int:
        if not self._loaded:
            self.load()
        return sum(1 for record in self._records.values() if self._record_problem(record) is None and is_done(record))
