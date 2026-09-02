"""Resolve names from the CSVs into tenant identifiers: Identity groups -> UAP principals, strong accounts -> secret ids."""
from __future__ import annotations

import logging
from typing import Any, Callable

from .clients import IdentityClient
from .inputs import StrongAccountRow
from .payloads import build_principal


class ResolveError(Exception):
    """A name could not be resolved unambiguously."""


def pick(d: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Read the first present key (tolerates snake_case / camelCase variants in API responses)."""
    for key in keys:
        if key in d and d[key] is not None:
            return d[key]
    return default


class PrincipalResolver:
    """Looks up Identity groups by name and builds UAP principals. Results are cached per run."""

    def __init__(self, identity: IdentityClient, pinned_directory: Callable[[str], str | None] = lambda _: None,
                 logger: logging.Logger | None = None):
        self._identity = identity
        self._pinned = pinned_directory
        self._log = logger or logging.getLogger("sia.resolve")
        self._directories: list[dict[str, Any]] | None = None
        self._cache: dict[str, dict[str, Any]] = {}

    @property
    def directories(self) -> list[dict[str, Any]]:
        if self._directories is None:
            self._directories = self._identity.list_directories()
            self._log.debug("Identity directories: %s",
                            [(pick(d, "Service"), pick(d, "DisplayName"), pick(d, "directoryServiceUuid")) for d in self._directories])
        return self._directories

    def _directory_uuids(self) -> list[str]:
        uuids = [pick(d, "directoryServiceUuid", "DirectoryServiceUuid") for d in self.directories]
        return [u for u in uuids if u]

    def _directory_labels(self, uuid: str | None) -> set[str]:
        labels: set[str] = set()
        for d in self.directories:
            if pick(d, "directoryServiceUuid", "DirectoryServiceUuid") == uuid:
                for key in ("DisplayName", "Service", "Name", "DisplayNameShort"):
                    value = pick(d, key)
                    if value:
                        labels.add(str(value).lower())
        return labels

    def _matches_pin(self, row: dict[str, Any], pinned: str) -> bool:
        wanted = pinned.strip().lower()
        localized = str(pick(row, "ServiceInstanceLocalized", default="")).lower()
        if localized == wanted:
            return True
        return wanted in self._directory_labels(pick(row, "DirectoryServiceUuid"))

    def resolve(self, group_name: str) -> dict[str, Any]:
        if group_name in self._cache:
            return self._cache[group_name]
        rows = self._identity.query_groups(group_name, self._directory_uuids())
        wanted = group_name.lower()
        exact = [r for r in rows if wanted in (str(pick(r, "SystemName", default="")).lower(),
                                                str(pick(r, "DisplayName", default="")).lower())]
        pinned = self._pinned(group_name)
        if pinned:
            exact = [r for r in exact if self._matches_pin(r, pinned)]
        if not exact:
            near = sorted({f"{pick(r, 'SystemName') or pick(r, 'DisplayName')} ({pick(r, 'ServiceInstanceLocalized')})" for r in rows})
            hint = f"; similar names: {', '.join(near[:8])}" if near else ""
            where = f" in directory {pinned!r}" if pinned else ""
            raise ResolveError(f"group {group_name!r} not found in Identity{where}{hint}")
        if len(exact) > 1:
            candidates = ", ".join(sorted(f"{pick(r, 'SystemName')} ({pick(r, 'ServiceInstanceLocalized')})" for r in exact))
            raise ResolveError(
                f"group {group_name!r} is ambiguous ({len(exact)} matches: {candidates}); pin the directory in groups.csv")
        row = exact[0]
        missing = [k for k in ("InternalName", "DirectoryServiceUuid", "ServiceInstanceLocalized") if not pick(row, k)]
        if missing:
            raise ResolveError(f"group {group_name!r}: Identity row lacks {', '.join(missing)}; cannot build a principal")
        principal = build_principal(row)
        self._cache[group_name] = principal
        return principal


class SecretIndex:
    """In-memory index of SIA VM secrets (strong accounts) keyed by name, case-insensitively."""

    def __init__(self, secrets: list[dict[str, Any]]):
        self._by_name: dict[str, dict[str, Any]] = {}
        for secret in secrets:
            self.add(secret)

    def add(self, secret: dict[str, Any]) -> None:
        name = pick(secret, "secret_name", "secretName")
        if name:
            self._by_name[str(name).lower()] = secret

    def find(self, account: StrongAccountRow) -> dict[str, Any] | None:
        """Deterministic: vault accounts by the platform's <account_name>_<safe> name, others by their CSV name."""
        return self._by_name.get(account.sia_name.lower())

    def __len__(self) -> int:
        return len(self._by_name)


def secret_id_of(secret: dict[str, Any]) -> str:
    return str(pick(secret, "secret_id", "secretId"))


def secret_type_of(secret: dict[str, Any]) -> str:
    return str(pick(secret, "secret_type", "secretType", default=""))
