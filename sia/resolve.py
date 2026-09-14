"""Resolve names from the CSVs into tenant identifiers: Identity roles or groups -> UAP principals, strong accounts -> secret ids."""
from __future__ import annotations

import logging
from typing import Any, Callable

from .clients import IdentityClient
from .config import PRINCIPAL_TYPES
from .inputs import StrongAccountRow
from .payloads import build_group_principal, build_role_principal


class ResolveError(Exception):
    """A name could not be resolved unambiguously."""


def pick(d: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Read the first present key (tolerates snake_case / camelCase variants in API responses)."""
    for key in keys:
        if key in d and d[key] is not None:
            return d[key]
    return default


class PrincipalResolver:
    """Looks up Identity roles (principal_type = role, the default) or groups by name and builds UAP principals.

    Results are cached per run. Roles are tenant-scoped objects of the CyberArk Cloud Directory (CDS), so they are
    queried in that directory alone and need no pin; a group name can exist in several directories, which is what
    `pinned_directory` (groups.csv) disambiguates.
    """

    def __init__(self, identity: IdentityClient, pinned_directory: Callable[[str], str | None] = lambda _: None,
                 logger: logging.Logger | None = None, *, principal_type: str = "role"):
        if principal_type not in PRINCIPAL_TYPES:
            raise ValueError(f"principal_type must be one of {', '.join(PRINCIPAL_TYPES)}")
        self._identity = identity
        self._type = principal_type
        self._pinned = pinned_directory
        self._log = logger or logging.getLogger("sia.resolve")
        self._directories: list[dict[str, Any]] | None = None
        self._cache: dict[str, dict[str, Any]] = {}

    @property
    def principal_type(self) -> str:
        return self._type

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
            actual = pick(d, "directoryServiceUuid", "DirectoryServiceUuid")
            if str(actual or "").casefold() == str(uuid or "").casefold():
                for key in ("DisplayName", "Service", "Name", "DisplayNameShort"):
                    value = pick(d, key)
                    if value:
                        labels.add(str(value).casefold())
        return labels

    def _matches_pin(self, row: dict[str, Any], pinned: str) -> bool:
        wanted = pinned.strip().casefold()
        localized = str(pick(row, "ServiceInstanceLocalized", default="")).casefold()
        if localized == wanted:
            return True
        return wanted in self._directory_labels(pick(row, "DirectoryServiceUuid"))

    def _cds_directories(self) -> list[dict[str, Any]]:
        """Rows whose Service is CDS -- the CyberArk Cloud Directory, where every Identity role lives."""
        return [d for d in self.directories if str(pick(d, "Service", "service", default="")).casefold() == "cds"]

    def _cds_directory(self) -> dict[str, Any] | None:
        cds = self._cds_directories()
        return cds[0] if cds else None

    def _cds_uuids(self) -> list[str]:
        rows = self._cds_directories() or self.directories   # nothing labelled CDS: query every directory
        return [u for u in (pick(d, "directoryServiceUuid", "DirectoryServiceUuid") for d in rows) if u]

    def resolve(self, name: str) -> dict[str, Any]:
        """The UAP principal for a role or group name, looked up once per run (case-insensitively)."""
        cache_key = name.casefold()
        if cache_key in self._cache:
            return self._cache[cache_key]
        principal = self._resolve_role(name) if self._type == "role" else self._resolve_group(name)
        self._cache[cache_key] = principal
        return principal

    def _resolve_role(self, role_name: str) -> dict[str, Any]:
        rows = self._identity.query_roles(role_name, self._cds_uuids())
        wanted = role_name.casefold()
        # Identity can repeat the same object in search results: collapse those observations by id, so that a real
        # duplicate name (two roles, two ids) remains an explicit ambiguity.
        unique: dict[str, dict[str, Any]] = {}
        for row in rows:
            if str(pick(row, "Name", default="")).casefold() == wanted:
                unique.setdefault(str(pick(row, "_ID", default="")).casefold(), row)
        exact = list(unique.values())
        if not exact:
            near = sorted({str(pick(r, "Name")) for r in rows if pick(r, "Name")})
            hint = f"; similar names: {', '.join(near[:8])}" if near else ""
            raise ResolveError(f"role {role_name!r} not found in Identity{hint}")
        if len(exact) > 1:
            # Never say "not found" here: reconcile._snapshot_principals treats that phrase as a per-row miss and
            # anything else as a reason to stop before the first write.
            ids = ", ".join(sorted(str(pick(r, "_ID") or "<no id>") for r in exact))
            raise ResolveError(f"role {role_name!r} is ambiguous ({len(exact)} matches: {ids})")
        row = exact[0]
        if not pick(row, "_ID"):
            raise ResolveError(f"role {role_name!r}: Identity row lacks _ID; cannot build a principal")
        return build_role_principal(row, self._cds_directory())

    def _resolve_group(self, group_name: str) -> dict[str, Any]:
        rows = self._identity.query_groups(group_name, self._directory_uuids())
        wanted = group_name.casefold()
        exact = [r for r in rows if wanted in (str(pick(r, "SystemName", default="")).casefold(),
                                                str(pick(r, "DisplayName", default="")).casefold())]
        pinned = self._pinned(group_name)
        if pinned:
            exact = [r for r in exact if self._matches_pin(r, pinned)]
        # Identity can repeat the same object in search results.  Collapse
        # those observations, while retaining distinct ids/directories so a
        # real name collision remains an explicit ambiguity.
        unique: dict[tuple[str, str], dict[str, Any]] = {}
        for row in exact:
            identity = (
                str(pick(row, "InternalName", default="")).casefold(),
                str(pick(row, "DirectoryServiceUuid", default="")).casefold(),
            )
            unique.setdefault(identity, row)
        exact = list(unique.values())
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
        return build_group_principal(row)


class SecretIndex:
    """In-memory index of SIA VM secrets (strong accounts) keyed by name, case-insensitively."""

    def __init__(self, secrets: list[dict[str, Any]]):
        self._by_name: dict[str, list[dict[str, Any]]] = {}
        for secret in secrets:
            self.add(secret)

    def add(self, secret: dict[str, Any]) -> None:
        name = pick(secret, "secret_name", "secretName")
        if name:
            key = str(name).casefold()
            candidates = self._by_name.setdefault(key, [])
            new_id = secret_id_of(secret)
            if any((new_id and secret_id_of(existing) == new_id) or (not new_id and existing == secret)
                   for existing in candidates):
                return
            candidates.append(secret)

    def has(self, sia_name: str) -> bool:
        """Presence test by SIA name. Unlike `find` it never raises, so it is safe on an ambiguous name."""
        return bool(self._by_name.get(sia_name.casefold()))

    def find(self, account: StrongAccountRow) -> dict[str, Any] | None:
        """Deterministic: vault accounts by the platform's <account_name>_<safe> name, others by their CSV name."""
        candidates = self._by_name.get(account.sia_name.casefold(), [])
        if len(candidates) > 1:
            ids = sorted(secret_id_of(secret) or "<missing>" for secret in candidates)
            raise ResolveError(
                f"strong account {account.sia_name!r} is ambiguous across object ids: {', '.join(ids)}")
        return candidates[0] if candidates else None

    def __len__(self) -> int:
        return len(self._by_name)


def secret_id_of(secret: dict[str, Any]) -> str:
    value = pick(secret, "secret_id", "secretId", default="")
    return str(value) if value is not None else ""


def secret_type_of(secret: dict[str, Any]) -> str:
    return str(pick(secret, "secret_type", "secretType", default=""))
