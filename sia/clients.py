"""Thin API clients. Each method maps 1:1 to an endpoint; no business logic here.

Wire formats follow the documented APIs and CyberArk's official SDKs (ark-sdk-python / idsec-sdk-golang):
  SIA   https://<sub>.dpa.cyberark.cloud/api/{settings,secrets[/public/v1|v2],[discovery/]targetsets}
  UAP   https://<sub>.uap.cyberark.cloud/api/policies
  Identity  https://<tenant>.id.cyberark.cloud/{Core/GetDirectoryServices,UserMgmt/DirectoryServiceQuery}

Two SIA path families exist for strong accounts and target sets (the SDK's legacy paths and the documented public
ones). `SIAClient.probe()` finds out, with read-only calls, which family the tenant serves; `[http] secrets_api`
and `targetsets_api` pin the answer once known.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from .http import HttpClient, SIAApiError, json_or_error

SECRET_TYPES = ("ProvisionerUser", "PCloudAccount")
UAP_VM_FILTER = "(targetCategory eq 'VM')"
LEGACY_SECRETS = "/api/secrets"
PUBLIC_SECRETS_V1 = "/api/secrets/public/v1"
PUBLIC_SECRETS_V2 = "/api/secrets/public/v2"
LEGACY_TARGETSETS = "/api/targetsets"
DISCOVERY_TARGETSETS = "/api/discovery/targetsets"
SECRETS_PAGE = 500
_NEEDS_ACCOUNT = "strongaccountid"


def _seg(value: str) -> str:
    return quote(value, safe="")


def owned_vm_filter(owner_tag: str) -> str:
    """UAP list filter for the VM policies this tool manages (policyTags eq <owner tag>)."""
    return f"({UAP_VM_FILTER} and (policyTags eq '{owner_tag}'))"


@dataclass
class SIACapabilities:
    secrets_api: str = "legacy"            # public | legacy
    targetsets_api: str = "legacy"         # legacy | discovery
    targetsets_list_unfiltered: bool = True   # GET .../targetsets without strongAccountId is accepted
    probed: bool = False

    def describe(self) -> str:
        listing = "unfiltered listing OK" if self.targetsets_list_unfiltered else "listing needs strongAccountId"
        return f"secrets={self.secrets_api} targetsets={self.targetsets_api} ({listing})"


class SIAClient:
    """Secure Infrastructure Access service ("dpa")."""

    def __init__(self, http: HttpClient, base_url: str, *, secrets_api: str = "auto", targetsets_api: str = "auto",
                 capabilities: SIACapabilities | None = None, logger: logging.Logger | None = None):
        self._http = http
        self._base = base_url.rstrip("/")
        self._secrets_pref = secrets_api
        self._targetsets_pref = targetsets_api
        self._caps: SIACapabilities | None = capabilities
        self._log = logger or logging.getLogger("sia.clients")

    # ---------------------------------------------------------------- probe
    @property
    def capabilities(self) -> SIACapabilities:
        if self._caps is None:
            self.probe()
        assert self._caps is not None
        return self._caps

    def probe(self) -> SIACapabilities:
        """Find the API families with read-only GETs (one page each). A pinned family ([http] secrets_api /
        targetsets_api) is taken as is, without a request; whether unfiltered target-set listing is accepted is
        then learned from the first listing call."""
        caps = SIACapabilities(probed=True)
        if self._secrets_pref in ("public", "legacy"):
            caps.secrets_api = self._secrets_pref
        else:
            try:
                self._http.get(f"{self._base}{PUBLIC_SECRETS_V1}", params={"secret_type": ",".join(SECRET_TYPES), "count": "1"})
                caps.secrets_api = "public"
            except SIAApiError as exc:
                if not exc.not_found:
                    raise
                caps.secrets_api = "legacy"
        if self._targetsets_pref in ("legacy", "discovery"):
            caps.targetsets_api = self._targetsets_pref
        else:
            for family in ("legacy", "discovery"):
                path = LEGACY_TARGETSETS if family == "legacy" else DISCOVERY_TARGETSETS
                try:
                    self._http.get(f"{self._base}{path}")
                    caps.targetsets_api, caps.targetsets_list_unfiltered = family, True
                    break
                except SIAApiError as exc:
                    if self._needs_account(exc):
                        caps.targetsets_api, caps.targetsets_list_unfiltered = family, False
                        break
                    if exc.not_found and family == "legacy":
                        continue
                    raise
        self._caps = caps
        self._log.info("SIA API families: %s", caps.describe())
        return caps

    @staticmethod
    def _needs_account(exc: SIAApiError) -> bool:
        return exc.status in (400, 422) and _NEEDS_ACCOUNT in exc.body.lower().replace("_", "")

    def _secrets_family(self) -> str:
        return self.capabilities.secrets_api

    def _targetsets_path(self) -> str:
        return LEGACY_TARGETSETS if self.capabilities.targetsets_api == "legacy" else DISCOVERY_TARGETSETS

    # ------------------------------------------------------------- settings
    def get_settings(self) -> dict[str, Any]:
        return json_or_error(self._http.get(f"{self._base}/api/settings"))

    # -------------------------------------------------------------- secrets
    @staticmethod
    def _secret_items(body: Any) -> list[dict[str, Any]]:
        if isinstance(body, dict):
            body = body.get("secrets") or body.get("results") or body.get("items") or []
        return list(body)

    def list_secrets(self, *, name: str | None = None) -> list[dict[str, Any]]:
        """All strong accounts of the VM types (optionally only those whose name matches `name`)."""
        if self._secrets_family() == "legacy":
            body = json_or_error(self._http.get(f"{self._base}{LEGACY_SECRETS}", params={"secret_type": ",".join(SECRET_TYPES)}))
            items = self._secret_items(body)
            if name:
                items = [s for s in items if str(s.get("secret_name") or s.get("secretName") or "").lower() == name.lower()]
            return items
        params: dict[str, Any] = {"secret_type": ",".join(SECRET_TYPES)}
        if name:
            params["secret_name"] = name
        items = self._list_secrets_v2(params)
        if items is None:
            items = self._list_secrets_v1(params)
        if name:
            items = [s for s in items if str(s.get("secret_name") or s.get("secretName") or "").lower() == name.lower()]
        return items

    def _list_secrets_v2(self, params: dict[str, Any]) -> list[dict[str, Any]] | None:
        """Paginated listing; None when the tenant does not serve v2 (caller falls back to v1)."""
        items: list[dict[str, Any]] = []
        start_key: str | None = None
        seen: set[str] = set()
        while True:
            page_params = dict(params)
            if start_key:
                page_params["b64StartKey"] = start_key
            try:
                body = json_or_error(self._http.get(f"{self._base}{PUBLIC_SECRETS_V2}", params=page_params))
            except SIAApiError as exc:
                if exc.client_error and not items:
                    return None
                raise
            items.extend(self._secret_items(body))
            start_key = body.get("b64_last_evaluated_key") if isinstance(body, dict) else None
            if not start_key or start_key in seen:
                return items
            seen.add(start_key)

    def _list_secrets_v1(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        offset = 0
        while True:
            page = self._secret_items(json_or_error(self._http.get(
                f"{self._base}{PUBLIC_SECRETS_V1}", params={**params, "count": str(SECRETS_PAGE), "offset": str(offset)})))
            items.extend(page)
            if len(page) < SECRETS_PAGE:
                return items
            offset += SECRETS_PAGE

    def find_secret(self, name: str) -> dict[str, Any] | None:
        """One strong account by its SIA name (server-side filter on the public API; client-side on legacy)."""
        matches = self.list_secrets(name=name)
        return matches[0] if matches else None

    def create_secret(self, payload: dict[str, Any]) -> dict[str, Any]:
        path = PUBLIC_SECRETS_V1 if self._secrets_family() == "public" else LEGACY_SECRETS
        try:
            resp = self._http.post(f"{self._base}{path}", json=payload, expected=(200, 201))
        except SIAApiError as exc:
            if path == PUBLIC_SECRETS_V1 and exc.not_found:   # route missing: nothing was created, use the legacy path
                self.capabilities.secrets_api = "legacy"
                resp = self._http.post(f"{self._base}{LEGACY_SECRETS}", json=payload, expected=(200, 201))
            else:
                raise
        return json_or_error(resp)

    # ---------------------------------------------------------- target sets
    def list_target_sets(self, *, strong_account_id: str | None = None, name: str | None = None) -> list[dict[str, Any]]:
        caps = self.capabilities
        if not strong_account_id and not caps.targetsets_list_unfiltered:
            raise ValueError("this tenant lists target sets per strong account only (strongAccountId is required)")
        items: list[dict[str, Any]] = []
        start_key: str | None = None
        seen_keys: set[str] = set()
        base_params: dict[str, Any] = {}
        if strong_account_id:
            base_params["strongAccountId"] = strong_account_id
        if name:
            base_params["name"] = name
        while True:
            params = dict(base_params)
            if start_key:
                params["b64StartKey"] = start_key
            try:
                body = json_or_error(self._http.get(f"{self._base}{self._targetsets_path()}", params=params or None))
            except SIAApiError as exc:
                if not strong_account_id and self._needs_account(exc):
                    caps.targetsets_list_unfiltered = False
                    raise ValueError("this tenant lists target sets per strong account only (strongAccountId is required)") from exc
                raise
            if isinstance(body, list):  # older API shape: bare list
                items.extend(body)
                break
            items.extend(body.get("target_sets") or body.get("targetSets") or [])
            start_key = body.get("b64_last_evaluated_key") or None
            if not start_key or start_key in seen_keys:
                break
            seen_keys.add(start_key)
        if name:
            items = [t for t in items if str(t.get("name") or "").lower() == name.lower()]
        return items

    def bulk_create_target_sets(self, target_sets_mapping: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """POST .../targetsets/bulk -> HTTP 207 with per-item {strong_account_id, target_set_name, success}."""
        resp = self._http.post(
            f"{self._base}{self._targetsets_path()}/bulk",
            json={"target_sets_mapping": target_sets_mapping},
            expected=(200, 201, 207),
        )
        body = json_or_error(resp)
        return list(body.get("results") or []) if isinstance(body, dict) else list(body)

    def update_target_set(self, name: str, payload: dict[str, Any]) -> dict[str, Any]:
        """PUT .../targetsets/{name}; a target set is identified by its name."""
        resp = self._http.put(f"{self._base}{self._targetsets_path()}/{_seg(name)}", json=payload)
        return json_or_error(resp)


class UAPClient:
    """Access Control Policies (Unified Access Policies) service."""

    PAGE_SIZE = 50

    def __init__(self, http: HttpClient, base_url: str):
        self._http = http
        self._base = base_url.rstrip("/")

    def list_policies(self, *, text: str | None = None, filter_query: str | None = UAP_VM_FILTER,
                      max_pages: int = 10_000) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        next_token: str | None = None
        for _ in range(max_pages):
            params: dict[str, Any] = {"limit": self.PAGE_SIZE}
            if filter_query:
                params["filter"] = filter_query
            if text:
                params["q"] = text
            if next_token:
                params["nextToken"] = next_token
            body = json_or_error(self._http.get(f"{self._base}/api/policies", params=params))
            results.extend(body.get("results") or [])
            new_token = body.get("nextToken") or None
            if not new_token or new_token == next_token:
                break
            next_token = new_token
        return results

    def find_policies_for_fqdn(self, fqdn: str) -> list[dict[str, Any]]:
        """Free-text search (name + description) for one server's policies; usually one page."""
        return self.list_policies(text=fqdn, filter_query=UAP_VM_FILTER)

    def get_policy(self, policy_id: str) -> dict[str, Any]:
        return json_or_error(self._http.get(f"{self._base}/api/policies/{_seg(policy_id)}"))

    def find_policy_by_name(self, name: str) -> dict[str, Any] | None:
        """Text search then exact name match (the API's q= is a substring search)."""
        candidates = self.list_policies(text=name, filter_query=None)
        for policy in candidates:
            if (policy.get("metadata") or {}).get("name") == name:
                return policy
        return None

    def create_policy(self, payload: dict[str, Any]) -> str:
        body = json_or_error(self._http.post(f"{self._base}/api/policies", json=payload, expected=(200, 201)))
        policy_id = body.get("policyId") or body.get("policy_id")
        if not policy_id:
            raise SIAApiError("POST", f"{self._base}/api/policies", 200, f"no policyId in response: {json.dumps(body)[:300]}")
        return str(policy_id)

    def update_policy(self, policy_id: str, payload: dict[str, Any]) -> None:
        self._http.put(f"{self._base}/api/policies/{_seg(policy_id)}", json=payload, expected=(200, 204))


class IdentityClient:
    """CyberArk Identity directory lookups used to build policy principals."""

    def __init__(self, http: HttpClient, identity_url: str):
        self._http = http
        self._base = identity_url.rstrip("/")

    def _identity_result(self, method: str, path: str, **kw) -> Any:
        url = f"{self._base}/{path}"
        resp = self._http.request(method, url, **kw)
        body = json_or_error(resp)
        if not isinstance(body, dict) or body.get("success") is not True:
            message = body.get("Message") if isinstance(body, dict) else None
            raise SIAApiError(method, url, resp.status_code, message or json.dumps(body)[:300])
        return body.get("Result")

    def list_directories(self) -> list[dict[str, Any]]:
        """Rows have Service (CDS | AdProxy | FDS), directoryServiceUuid, DisplayName, ..."""
        result = self._identity_result("GET", "Core/GetDirectoryServices", json={})
        return [item.get("Row", item) for item in (result or {}).get("Results", [])]

    def query_groups(self, search: str, directory_uuids: list[str]) -> list[dict[str, Any]]:
        """Rows have InternalName (id), SystemName, DisplayName, DirectoryServiceUuid, ServiceInstanceLocalized, ServiceType."""
        group_filter = {"_or": [{"DisplayName": {"_like": search}}, {"SystemName": {"_like": search}}]}
        payload = {
            "directoryServices": directory_uuids,
            "group": json.dumps(group_filter),
            "Args": {"PageNumber": 1, "PageSize": 200, "Limit": 200, "SortBy": "",
                     "Caching": -1, "Direction": "", "Ascending": True},
        }
        result = self._identity_result("POST", "UserMgmt/DirectoryServiceQuery", json=payload)
        groups = ((result or {}).get("Group") or {}).get("Results") or []
        return [item.get("Row", item) for item in groups]
