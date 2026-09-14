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
MAX_LIST_PAGES = 10_000
_NEEDS_ACCOUNT = "strongaccountid"


def _seg(value: str) -> str:
    return quote(value, safe="")


def owned_vm_filter(owner_tag: str) -> str:
    """UAP list filter for the VM policies this tool manages (policyTags eq <owner tag>)."""
    return f"({UAP_VM_FILTER} and (policyTags eq '{owner_tag}'))"


class PerAccountTargetSetListingRequired(ValueError):
    """The tenant requires strongAccountId on target-set list requests."""


def _response_method(resp: Any) -> str:
    return str(getattr(getattr(resp, "request", None), "method", "GET") or "GET").upper()


def _malformed(resp: Any, message: str) -> SIAApiError:
    return SIAApiError(_response_method(resp), str(getattr(resp, "url", "?")),
                       int(getattr(resp, "status_code", 0) or 0), message,
                       cause="malformed_response", mutation_state="not_applicable")


def _list_field(resp: Any, body: Any, keys: tuple[str, ...], label: str,
                validate_item: Any, *, allow_bare: bool = True) -> list[dict[str, Any]]:
    """Return a validated list from a bare-list or documented envelope response."""
    if isinstance(body, list):
        if not allow_bare:
            raise _malformed(resp, f"{label} response must be an object containing {', '.join(keys)}")
        raw = body
    elif isinstance(body, dict):
        present = [key for key in keys if key in body]
        if not present:
            raise _malformed(resp, f"{label} response must contain one of: {', '.join(keys)}")
        raw = body[present[0]]
    else:
        raise _malformed(resp, f"{label} response must be an object or list")
    if not isinstance(raw, list):
        raise _malformed(resp, f"{label} response list is not an array")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise _malformed(resp, f"{label} item {index} is not an object")
        problem = validate_item(item)
        if problem:
            raise _malformed(resp, f"{label} item {index} {problem}")
        result.append(item)
    return result


def _continuation(resp: Any, body: Any, keys: tuple[str, ...], label: str) -> str | None:
    if not isinstance(body, dict):
        return None
    present = [key for key in keys if key in body]
    if not present:
        return None
    value = body[present[0]]
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not value.strip():
        raise _malformed(resp, f"{label} continuation token must be a non-empty string or null")
    return value


def _page_signature(items: list[dict[str, Any]]) -> str:
    return json.dumps(items, sort_keys=True, separators=(",", ":"), default=str)


def _repeated_page(page: list[dict[str, Any]], signature: str, seen_pages: set[str]) -> bool:
    """Whether a page that arrived with a continuation token duplicates one already collected.

    An empty page is never duplication. These endpoints hand out DynamoDB-style
    ``b64LastEvaluatedKey`` cursors (and UAP ``nextToken``), and a scan filtered server-side applies
    its filter *after* the page limit, so a page can legitimately hold zero matching items while the
    cursor still advances -- the caller has to keep paging until the token is absent. Treating an
    empty page as a stall stopped discovery on tenants whose first page filtered to nothing.

    Progress is still guaranteed: a cycled token is the real infinite-loop guard, a repeated
    non-empty page is real duplication, and ``max_pages`` bounds the walk either way. Empty
    signatures are deliberately not recorded, because every empty page shares one.
    """
    return bool(page) and signature in seen_pages


def _pagination_error(method: str, url: str, detail: str) -> SIAApiError:
    return SIAApiError(method, url, 200, detail, cause="incomplete_pagination",
                       mutation_state="not_applicable")


def _nonempty(item: dict[str, Any], *keys: str) -> bool:
    return any(isinstance(item.get(key), str) and bool(item[key].strip()) for key in keys)


def _secret_problem(item: dict[str, Any]) -> str | None:
    if not _nonempty(item, "secret_id", "secretId"):
        return "needs a non-empty secret id"
    if not _nonempty(item, "secret_name", "secretName"):
        return "needs a non-empty secret name"
    return None


def _target_set_problem(item: dict[str, Any]) -> str | None:
    return None if _nonempty(item, "name") else "needs a non-empty name"


def _policy_problem(item: dict[str, Any]) -> str | None:
    metadata = item.get("metadata")
    if not isinstance(metadata, dict):
        return "needs a metadata object"
    if not _nonempty(metadata, "name"):
        return "needs metadata.name"
    if not _nonempty(metadata, "policyId", "policy_id"):
        return "needs a policy id"
    return None


def _dedupe_by(items: list[dict[str, Any]], identity: Any) -> list[dict[str, Any]]:
    """Collapse repeated observations of the same stable object, retaining order."""
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        key = str(identity(item) or "")
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        result.append(item)
    return result


def _one_exact(items: list[dict[str, Any]], wanted: str, *, name_of: Any, id_of: Any,
               resource: str, url: str) -> dict[str, Any] | None:
    matches = [item for item in items if str(name_of(item) or "").casefold() == wanted.casefold()]
    matches = _dedupe_by(matches, id_of)
    if len(matches) > 1:
        ids = sorted(str(id_of(item) or "<missing>") for item in matches)
        raise SIAApiError("GET", url, 200,
                          f"{resource} name {wanted!r} is ambiguous across object ids: {', '.join(ids)}",
                          cause="ambiguous_response")
    return matches[0] if matches else None


@dataclass
class SIACapabilities:
    secrets_api: str = "legacy"            # public | legacy
    targetsets_api: str = "legacy"         # legacy | discovery
    targetsets_list_unfiltered: bool = True   # GET .../targetsets without strongAccountId is accepted
    # Server-side name filters (secret_name, target-set name, policy q=) return what an unfiltered listing shows.
    # Flipped to False when a filtered read comes back empty for a name the listing serves: on such a tenant no
    # "does not exist" decision may rest on a filtered read.
    name_filter_reliable: bool = True
    probed: bool = False

    def describe(self) -> str:
        listing = "unfiltered listing OK" if self.targetsets_list_unfiltered else "listing needs strongAccountId"
        if not self.name_filter_reliable:
            listing += ", name filter unreliable"
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
                response = self._http.get(
                    f"{self._base}{PUBLIC_SECRETS_V1}",
                    params={"secret_type": ",".join(SECRET_TYPES), "count": "1"},
                )
                self._secret_items(response, json_or_error(response))
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
                    response = self._http.get(f"{self._base}{path}")
                    self._target_set_items(response, json_or_error(response))
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
        response = self._http.get(f"{self._base}/api/settings")
        body = json_or_error(response)
        if not isinstance(body, dict):
            raise _malformed(response, "settings response must be an object")
        return body

    # -------------------------------------------------------------- secrets
    @staticmethod
    def _secret_items(response: Any, body: Any) -> list[dict[str, Any]]:
        return _list_field(response, body, ("secrets", "results", "items"), "strong-account list", _secret_problem)

    @staticmethod
    def _target_set_items(response: Any, body: Any) -> list[dict[str, Any]]:
        return _list_field(response, body, ("target_sets", "targetSets"), "target-set list", _target_set_problem)

    def list_secrets(self, *, name: str | None = None, max_pages: int = MAX_LIST_PAGES) -> list[dict[str, Any]]:
        """All strong accounts of the VM types (optionally only those whose name matches `name`)."""
        if self._secrets_family() == "legacy":
            response = self._http.get(f"{self._base}{LEGACY_SECRETS}",
                                      params={"secret_type": ",".join(SECRET_TYPES)})
            items = self._secret_items(response, json_or_error(response))
            if name:
                items = [s for s in items if str(s.get("secret_name") or s.get("secretName") or "").casefold() == name.casefold()]
            return _dedupe_by(items, lambda s: s.get("secret_id") or s.get("secretId"))
        params: dict[str, Any] = {"secret_type": ",".join(SECRET_TYPES)}
        if name:
            params["secret_name"] = name
        items = self._list_secrets_v2(params, max_pages=max_pages)
        if items is None:
            items = self._list_secrets_v1(params, max_pages=max_pages)
        if name:
            items = [s for s in items if str(s.get("secret_name") or s.get("secretName") or "").casefold() == name.casefold()]
        return _dedupe_by(items, lambda s: s.get("secret_id") or s.get("secretId"))

    def _list_secrets_v2(self, params: dict[str, Any], *, max_pages: int) -> list[dict[str, Any]] | None:
        """Paginated listing; None when the tenant does not serve v2 (caller falls back to v1)."""
        if max_pages < 1:
            raise ValueError("max_pages must be at least 1")
        items: list[dict[str, Any]] = []
        start_key: str | None = None
        seen_tokens: set[str] = set()
        seen_pages: set[str] = set()
        url = f"{self._base}{PUBLIC_SECRETS_V2}"
        for _ in range(max_pages):
            page_params = dict(params)
            if start_key:
                page_params["b64StartKey"] = start_key
            try:
                response = self._http.get(url, params=page_params)
                body = json_or_error(response)
            except SIAApiError as exc:
                if exc.not_found and not items:
                    return None
                raise
            page = self._secret_items(response, body)
            new_key = _continuation(response, body,
                                    ("b64_last_evaluated_key", "b64LastEvaluatedKey"), "strong-account list")
            if not new_key:
                items.extend(page)
                return _dedupe_by(items, lambda s: s.get("secret_id") or s.get("secretId"))
            signature = _page_signature(page)
            if _repeated_page(page, signature, seen_pages):
                raise _pagination_error("GET", url, "strong-account pagination made no progress")
            if new_key in seen_tokens:
                raise _pagination_error("GET", url, "strong-account pagination token repeated or cycled")
            items.extend(page)
            if page:
                seen_pages.add(signature)
            seen_tokens.add(new_key)
            start_key = new_key
        raise _pagination_error("GET", url, f"strong-account pagination exceeded the {max_pages}-page safety limit")

    def _list_secrets_v1(self, params: dict[str, Any], *, max_pages: int) -> list[dict[str, Any]]:
        if max_pages < 1:
            raise ValueError("max_pages must be at least 1")
        items: list[dict[str, Any]] = []
        offset = 0
        seen_pages: set[str] = set()
        url = f"{self._base}{PUBLIC_SECRETS_V1}"
        for _ in range(max_pages):
            response = self._http.get(url, params={**params, "count": str(SECRETS_PAGE), "offset": str(offset)})
            page = self._secret_items(response, json_or_error(response))
            signature = _page_signature(page)
            if len(page) == SECRETS_PAGE and signature in seen_pages:
                raise _pagination_error("GET", url, "strong-account offset pagination repeated a page")
            items.extend(page)
            if len(page) < SECRETS_PAGE:
                return _dedupe_by(items, lambda s: s.get("secret_id") or s.get("secretId"))
            seen_pages.add(signature)
            offset += SECRETS_PAGE
        raise _pagination_error("GET", url, f"strong-account pagination exceeded the {max_pages}-page safety limit")

    def find_secret(self, name: str) -> dict[str, Any] | None:
        """One strong account by its SIA name (server-side filter on the public API; client-side on legacy)."""
        matches = self.list_secrets(name=name)
        family = PUBLIC_SECRETS_V2 if self._secrets_family() == "public" else LEGACY_SECRETS
        return _one_exact(matches, name,
                          name_of=lambda s: s.get("secret_name") or s.get("secretName"),
                          id_of=lambda s: s.get("secret_id") or s.get("secretId"),
                          resource="strong account", url=f"{self._base}{family}")

    def create_secret(self, payload: dict[str, Any]) -> dict[str, Any]:
        path = PUBLIC_SECRETS_V1 if self._secrets_family() == "public" else LEGACY_SECRETS
        resp = self._http.post(f"{self._base}{path}", json=payload, expected=(200, 201))
        body = json_or_error(resp)
        secret_id = (body.get("secret_id") or body.get("secretId")) if isinstance(body, dict) else None
        if not isinstance(secret_id, str) or not secret_id.strip():
            raise SIAApiError("POST", resp.url, resp.status_code,
                              f"create response has no secret id: {json.dumps(body)[:300]}",
                              uncertain=True, cause="malformed_response")
        return body

    # ---------------------------------------------------------- target sets
    def list_target_sets(self, *, strong_account_id: str | None = None, name: str | None = None,
                         max_pages: int = MAX_LIST_PAGES) -> list[dict[str, Any]]:
        caps = self.capabilities
        if not strong_account_id and not caps.targetsets_list_unfiltered:
            raise PerAccountTargetSetListingRequired(
                "this tenant lists target sets per strong account only (strongAccountId is required)")
        if max_pages < 1:
            raise ValueError("max_pages must be at least 1")
        items: list[dict[str, Any]] = []
        start_key: str | None = None
        seen_tokens: set[str] = set()
        seen_pages: set[str] = set()
        base_params: dict[str, Any] = {}
        if strong_account_id:
            base_params["strongAccountId"] = strong_account_id
        if name:
            base_params["name"] = name
        url = f"{self._base}{self._targetsets_path()}"
        for _ in range(max_pages):
            params = dict(base_params)
            if start_key:
                params["b64StartKey"] = start_key
            try:
                response = self._http.get(url, params=params or None)
                body = json_or_error(response)
            except SIAApiError as exc:
                if not strong_account_id and self._needs_account(exc):
                    caps.targetsets_list_unfiltered = False
                    raise PerAccountTargetSetListingRequired(
                        "this tenant lists target sets per strong account only (strongAccountId is required)") from exc
                raise
            page = self._target_set_items(response, body)
            new_key = _continuation(response, body,
                                    ("b64_last_evaluated_key", "b64LastEvaluatedKey"), "target-set list")
            if not new_key:
                items.extend(page)
                break
            signature = _page_signature(page)
            if _repeated_page(page, signature, seen_pages):
                raise _pagination_error("GET", url, "target-set pagination made no progress")
            if new_key in seen_tokens:
                raise _pagination_error("GET", url, "target-set pagination token repeated or cycled")
            items.extend(page)
            if page:
                seen_pages.add(signature)
            seen_tokens.add(new_key)
            start_key = new_key
        else:
            raise _pagination_error("GET", url, f"target-set pagination exceeded the {max_pages}-page safety limit")
        items = _dedupe_by(items, lambda t: t.get("id") or t.get("target_set_id") or t.get("targetSetId")
                           or f"{t.get('name')}\0{t.get('secret_id') or t.get('secretId') or t.get('strong_account_id') or ''}")
        if name:
            items = [t for t in items if str(t.get("name") or "").casefold() == name.casefold()]
            ids = {str(t.get("id") or t.get("target_set_id") or t.get("targetSetId")
                       or t.get("secret_id") or t.get("secretId") or "") for t in items}
            if len(items) > 1 and len(ids) > 1:
                raise SIAApiError("GET", url, 200,
                                  f"target-set name {name!r} is ambiguous across object ids: {', '.join(sorted(ids))}",
                                  cause="ambiguous_response")
        return items

    def bulk_create_target_sets(self, target_sets_mapping: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """POST .../targetsets/bulk -> HTTP 207 with per-item {strong_account_id, target_set_name, success}."""
        resp = self._http.post(
            f"{self._base}{self._targetsets_path()}/bulk",
            json={"target_sets_mapping": target_sets_mapping},
            expected=(200, 201, 207),
        )
        body = json_or_error(resp)
        raw_results = body.get("results") if isinstance(body, dict) else body if isinstance(body, list) else None
        if raw_results is None or not isinstance(raw_results, list) or any(not isinstance(item, dict) for item in raw_results):
            raise SIAApiError("POST", resp.url, resp.status_code,
                              f"bulk create response has an invalid results shape: {json.dumps(body)[:300]}",
                              uncertain=True, cause="malformed_response")
        results = list(raw_results)
        requested_names = [str(target.get("name") or "").casefold()
                           for mapping in target_sets_mapping for target in (mapping.get("target_sets") or [])]
        result_names = [str(item.get("target_set_name") or item.get("targetSetName") or "").casefold()
                        for item in results]
        requested = len(requested_names)
        valid_items = all(isinstance(item.get("success"), bool)
                          and isinstance(item.get("target_set_name") or item.get("targetSetName"), str)
                          and bool((item.get("target_set_name") or item.get("targetSetName")).strip())
                          for item in results)
        if requested != len(results) or not valid_items or sorted(result_names) != sorted(requested_names):
            raise SIAApiError("POST", resp.url, resp.status_code,
                              f"bulk create response items do not match the {requested} requested target set(s)",
                              uncertain=True, cause="malformed_response")
        return results

    def update_target_set(self, name: str, payload: dict[str, Any]) -> dict[str, Any]:
        """PUT .../targetsets/{name}; a target set is identified by its name."""
        resp = self._http.put(f"{self._base}{self._targetsets_path()}/{_seg(name)}", json=payload)
        body = json_or_error(resp)
        identifier = (body.get("name") or body.get("id")) if isinstance(body, dict) else None
        if not isinstance(identifier, str) or not identifier.strip():
            raise SIAApiError("PUT", resp.url, resp.status_code,
                              f"update response does not identify target set {name!r}: {json.dumps(body)[:300]}",
                              uncertain=True, cause="malformed_response")
        return body


class UAPClient:
    """Access Control Policies (Unified Access Policies) service."""

    PAGE_SIZE = 50

    def __init__(self, http: HttpClient, base_url: str, page_size: int | None = None):
        self._http = http
        self._base = base_url.rstrip("/")
        # UAP applies `filter` after the page limit, so a filtered walk drains the cursor across every policy in the
        # tenant: on a large tenant the page size, not the number of matches, decides how many round trips that costs.
        self._page_size = int(page_size) if page_size else self.PAGE_SIZE

    def list_policies(self, *, text: str | None = None, filter_query: str | None = UAP_VM_FILTER,
                      max_pages: int = MAX_LIST_PAGES) -> list[dict[str, Any]]:
        if max_pages < 1:
            raise ValueError("max_pages must be at least 1")
        results: list[dict[str, Any]] = []
        next_token: str | None = None
        seen_tokens: set[str] = set()
        seen_pages: set[str] = set()
        url = f"{self._base}/api/policies"
        for _ in range(max_pages):
            params: dict[str, Any] = {"limit": self._page_size}
            if filter_query:
                params["filter"] = filter_query
            if text:
                params["q"] = text
            if next_token:
                params["nextToken"] = next_token
            response = self._http.get(url, params=params)
            body = json_or_error(response)
            page = _list_field(response, body, ("results",), "policy list", _policy_problem,
                               allow_bare=False)
            new_token = _continuation(response, body, ("nextToken", "next_token"), "policy list")
            if not new_token:
                results.extend(page)
                return _dedupe_by(results, lambda p: (p.get("metadata") or {}).get("policyId")
                                  or (p.get("metadata") or {}).get("policy_id"))
            signature = _page_signature(page)
            if _repeated_page(page, signature, seen_pages):
                raise _pagination_error("GET", url, "policy pagination made no progress")
            if new_token in seen_tokens:
                raise _pagination_error("GET", url, "policy pagination token repeated or cycled")
            results.extend(page)
            if page:
                seen_pages.add(signature)
            seen_tokens.add(new_token)
            next_token = new_token
        raise _pagination_error("GET", url, f"policy pagination exceeded the {max_pages}-page safety limit")

    def find_policies_for_fqdn(self, fqdn: str) -> list[dict[str, Any]]:
        """Free-text search (name + description) for one server's policies; usually one page."""
        return self.list_policies(text=fqdn, filter_query=UAP_VM_FILTER)

    def get_policy(self, policy_id: str) -> dict[str, Any]:
        url = f"{self._base}/api/policies/{_seg(policy_id)}"
        response = self._http.get(url)
        body = json_or_error(response)
        if not isinstance(body, dict) or _policy_problem(body):
            raise _malformed(response, f"policy response {_policy_problem(body) if isinstance(body, dict) else 'must be an object'}")
        returned_id = (body.get("metadata") or {}).get("policyId") or (body.get("metadata") or {}).get("policy_id")
        if str(returned_id) != str(policy_id):
            raise _malformed(response, f"policy response id does not match requested id {policy_id!r}")
        return body

    def find_policy_by_name(self, name: str) -> dict[str, Any] | None:
        """Text search then exact name match (the API's q= is a substring search)."""
        candidates = self.list_policies(text=name, filter_query=None)
        return _one_exact(candidates, name,
                          name_of=lambda p: (p.get("metadata") or {}).get("name"),
                          id_of=lambda p: (p.get("metadata") or {}).get("policyId")
                          or (p.get("metadata") or {}).get("policy_id"),
                          resource="policy", url=f"{self._base}/api/policies")

    def create_policy(self, payload: dict[str, Any]) -> str:
        resp = self._http.post(f"{self._base}/api/policies", json=payload, expected=(200, 201))
        body = json_or_error(resp)
        policy_id = (body.get("policyId") or body.get("policy_id")) if isinstance(body, dict) else None
        if not isinstance(policy_id, str) or not policy_id.strip():
            raise SIAApiError("POST", resp.url, resp.status_code,
                              f"no policyId in response: {json.dumps(body)[:300]}",
                              uncertain=True, cause="malformed_response")
        return str(policy_id)

    def update_policy(self, policy_id: str, payload: dict[str, Any]) -> None:
        self._http.put(f"{self._base}/api/policies/{_seg(policy_id)}", json=payload, expected=(200, 204))


class IdentityClient:
    """CyberArk Identity directory lookups used to build policy principals (Identity roles or groups)."""

    def __init__(self, http: HttpClient, identity_url: str):
        self._http = http
        self._base = identity_url.rstrip("/")

    def _identity_result(self, method: str, path: str, **kw) -> tuple[Any, dict[str, Any]]:
        url = f"{self._base}/{path}"
        resp = self._http.request(method, url, mutation=False, **kw)
        body = json_or_error(resp, mutation=False)
        if not isinstance(body, dict):
            raise _malformed(resp, "Identity response must be an object")
        if body.get("success") is not True:
            if body.get("success") is False:
                message = body.get("Message")
                raise SIAApiError(method, url, resp.status_code,
                                  str(message) if isinstance(message, str) and message else "Identity request failed",
                                  mutation_state="not_applicable")
            raise _malformed(resp, "Identity response must contain success=true")
        result = body.get("Result")
        if not isinstance(result, dict):
            raise _malformed(resp, "Identity response must contain a Result object")
        return resp, result

    @staticmethod
    def _rows(response: Any, container: Any, label: str, validate_row: Any) -> list[dict[str, Any]]:
        raw_items = _list_field(response, container, ("Results",), label, lambda _: None)
        rows: list[dict[str, Any]] = []
        for index, item in enumerate(raw_items):
            row = item.get("Row", item)
            if not isinstance(row, dict):
                raise _malformed(response, f"{label} item {index} Row is not an object")
            problem = validate_row(row)
            if problem:
                raise _malformed(response, f"{label} item {index} {problem}")
            rows.append(row)
        return rows

    def list_directories(self) -> list[dict[str, Any]]:
        """Rows have Service (CDS | AdProxy | FDS), directoryServiceUuid, DisplayName, ..."""
        response, result = self._identity_result("GET", "Core/GetDirectoryServices", json={})
        return self._rows(
            response,
            result,
            "Identity directory list",
            lambda row: None if _nonempty(row, "directoryServiceUuid", "DirectoryServiceUuid")
            else "needs a directory service UUID",
        )

    def query_groups(self, search: str, directory_uuids: list[str], *,
                     max_pages: int = MAX_LIST_PAGES) -> list[dict[str, Any]]:
        """Rows have InternalName (id), SystemName, DisplayName, DirectoryServiceUuid, ServiceInstanceLocalized, ServiceType."""
        group_filter = {"_or": [{"DisplayName": {"_like": search}}, {"SystemName": {"_like": search}}]}
        return self._directory_query(
            directory_uuids, filter_key="group", filter_value=group_filter, containers=("Group",),
            label="Identity group",
            validate_row=lambda row: None if _nonempty(row, "SystemName", "DisplayName") else "needs a group name",
            identity_of=lambda row: (f"{row.get('InternalName')}\0"
                                     f"{row.get('DirectoryServiceUuid') or row.get('directoryServiceUuid') or ''}")
            if row.get("InternalName") else "",
            max_pages=max_pages,
        )

    def query_roles(self, search: str, directory_uuids: list[str], *,
                    max_pages: int = MAX_LIST_PAGES) -> list[dict[str, Any]]:
        """Rows have _ID (the role id), Name, Description, IsHidden, AdministrativeRights.

        Roles are tenant-scoped objects of the CyberArk Cloud Directory; the filter is the one CyberArk's SDK sends
        for its role search (case-insensitive substring on Name). The response container is documented as ``Roles``
        and read by the SDK as ``roles``, so both spellings are accepted.
        """
        role_filter = {"Name": {"_like": {"value": search, "ignoreCase": True}}}
        return self._directory_query(
            directory_uuids, filter_key="roles", filter_value=role_filter, containers=("roles", "Roles"),
            label="Identity role",
            validate_row=lambda row: None if _nonempty(row, "Name") else "needs a role name",
            identity_of=lambda row: str(row.get("_ID") or ""),
            max_pages=max_pages,
        )

    def _directory_query(self, directory_uuids: list[str], *, filter_key: str, filter_value: dict[str, Any],
                         containers: tuple[str, ...], label: str, validate_row: Any, identity_of: Any,
                         max_pages: int) -> list[dict[str, Any]]:
        """One DirectoryServiceQuery walk (page-number based, 200 rows a page) for the object type `filter_key` selects."""
        if max_pages < 1:
            raise ValueError("max_pages must be at least 1")
        rows: list[dict[str, Any]] = []
        seen_pages: set[str] = set()
        page_size = 200
        url = f"{self._base}/UserMgmt/DirectoryServiceQuery"
        for page_number in range(1, max_pages + 1):
            payload = {
                "directoryServices": directory_uuids,
                filter_key: json.dumps(filter_value),
                "Args": {"PageNumber": page_number, "PageSize": page_size, "Limit": page_size, "SortBy": "",
                         "Caching": -1, "Direction": "", "Ascending": True},
            }
            response, result = self._identity_result("POST", "UserMgmt/DirectoryServiceQuery", json=payload)
            container = next((result[key] for key in containers if isinstance(result.get(key), dict)), None)
            if container is None:
                raise _malformed(response, f"{label} query Result must contain a {containers[0]} object")
            page = self._rows(response, container, f"{label} list", validate_row)
            signature = _page_signature(page)
            if len(page) == page_size and signature in seen_pages:
                raise _pagination_error("POST", url, f"{label} pagination repeated a page")
            rows.extend(page)
            if len(page) < page_size:
                return _dedupe_by(rows, identity_of)
            seen_pages.add(signature)
        raise _pagination_error("POST", url, f"{label} pagination exceeded the {max_pages}-page safety limit")
