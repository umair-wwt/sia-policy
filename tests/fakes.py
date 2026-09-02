"""Offline fakes: an in-memory tenant standing in for SIAClient/UAPClient/IdentityClient/PVWAClient, and a fake requests.Session."""
from __future__ import annotations

import json
import re
from typing import Any

from sia.clients import SIACapabilities
from sia.http import SIAApiError

CDS_UUID = "09B9A9B0-6CE8-465F-AB03-65766D33B05E"
AD_UUID = "5F8C4E2A-0000-4000-8000-000000000AD1"
_TAG_FILTER = re.compile(r"policyTags eq '([^']+)'")


def group_row(name: str, uuid: str = CDS_UUID, localized: str = "CyberArk Cloud Directory", internal: str | None = None,
              service_type: str = "CDS") -> dict[str, Any]:
    return {"InternalName": internal or f"id-{name}-{uuid[:4]}", "SystemName": name, "DisplayName": name.replace("-", " "),
            "DirectoryServiceUuid": uuid, "ServiceInstanceLocalized": localized, "ServiceType": service_type}


class FakeIdentity:
    def __init__(self, groups: list[dict[str, Any]] | None = None):
        self.directories = [
            {"Service": "CDS", "directoryServiceUuid": CDS_UUID, "DisplayName": "CyberArk Cloud Directory"},
            {"Service": "AdProxy", "directoryServiceUuid": AD_UUID, "DisplayName": "corp.example.com"},
        ]
        self.groups = groups if groups is not None else [group_row("SIA-Web-Admins"), group_row("SIA-Platform-Ops"), group_row("SIA-DMZ-Admins"), group_row("SIA-Linux-Admins")]
        self.queries: list[str] = []

    def list_directories(self):
        return list(self.directories)

    def query_groups(self, search: str, directory_uuids: list[str]):
        self.queries.append(search)
        needle = search.lower()
        return [g for g in self.groups if needle in g["SystemName"].lower() or needle in g["DisplayName"].lower()]


class FakeSIA:
    def __init__(self, secrets: list[dict[str, Any]] | None = None, target_sets: list[dict[str, Any]] | None = None):
        self.secrets = list(secrets or [])
        self.target_sets = list(target_sets or [])
        self.settings = {"self_hosted_pam": {"tenant_type": "SELF_HOSTED", "pvwa_base_url": "https://pvwa.corp.example.com",
                                             "connector_pool_id": "pool-1", "service_user_secret_id": "svc-1"}}
        self.capabilities = SIACapabilities(secrets_api="public", targetsets_api="legacy", targetsets_list_unfiltered=True, probed=True)
        self.calls: list[tuple[str, Any]] = []
        self.fail_bulk_for: set[str] = set()
        self.raise_on_create_secret: SIAApiError | None = None
        self.raise_on_settings: SIAApiError | None = None
        self.raise_on_bulk: SIAApiError | None = None
        self.raise_on_update_target_set: SIAApiError | None = None
        self._counter = 0

    def probe(self):
        self.calls.append(("probe", None))
        return self.capabilities

    def get_settings(self):
        if self.raise_on_settings:
            raise self.raise_on_settings
        return dict(self.settings)

    def list_secrets(self, *, name=None):
        self.calls.append(("list_secrets", name))
        items = [dict(s) for s in self.secrets]
        if name:
            items = [s for s in items if s["secret_name"].lower() == name.lower()]
        return items

    def find_secret(self, name):
        self.calls.append(("find_secret", name))
        for s in self.secrets:
            if s["secret_name"].lower() == name.lower():
                return dict(s)
        return None

    def create_secret(self, payload):
        self.calls.append(("create_secret", payload))
        if self.raise_on_create_secret:
            raise self.raise_on_create_secret
        self._counter += 1
        created = {"secret_id": f"sec-{self._counter}", "secret_type": payload["secret_type"], "secret_name": payload["secret_name"],
                   "secret_details": payload["secret_details"], "is_active": payload["is_active"]}
        self.secrets.append(created)
        return dict(created)

    def list_target_sets(self, *, strong_account_id=None, name=None):
        self.calls.append(("list_target_sets", (strong_account_id, name)))
        if not strong_account_id and not self.capabilities.targetsets_list_unfiltered:
            raise ValueError("this tenant lists target sets per strong account only (strongAccountId is required)")
        items = [dict(t) for t in self.target_sets]
        if strong_account_id:
            items = [t for t in items if t.get("secret_id") == strong_account_id]
        if name:
            items = [t for t in items if t["name"].lower() == name.lower()]
        return items

    def bulk_create_target_sets(self, mapping):
        self.calls.append(("bulk_create_target_sets", mapping))
        if self.raise_on_bulk:
            raise self.raise_on_bulk
        results = []
        for item in mapping:
            for ts in item["target_sets"]:
                ok = ts["name"] not in self.fail_bulk_for
                if ok:
                    self.target_sets.append({"id": ts["name"], **ts})
                results.append({"strong_account_id": item["strong_account_id"], "target_set_name": ts["name"], "success": ok})
        return results

    def update_target_set(self, name, payload):
        self.calls.append(("update_target_set", (name, payload)))
        if self.raise_on_update_target_set:
            raise self.raise_on_update_target_set
        for ts in self.target_sets:
            if ts["name"] == name:
                ts.update(payload)
                return dict(ts)
        raise SIAApiError("PUT", f"/api/targetsets/{name}", 404, "not found")


class FakeUAP:
    def __init__(self, policies: list[dict[str, Any]] | None = None):
        self.policies = list(policies or [])
        self.calls: list[tuple[str, Any]] = []
        self.create_status = "Active"
        self.statuses_sequence: list[str] | None = None
        self.raise_on_create_policy: SIAApiError | None = None
        self.raise_on_update_policy: SIAApiError | None = None
        self.partial_list = False            # True: list results carry no "targets" (like the real list endpoint)
        self.conflict_on_create: set[str] = set()   # policy names whose creation answers 409
        self._counter = 0

    def list_policies(self, *, text=None, filter_query=None, max_pages=1000):
        self.calls.append(("list_policies", (text, filter_query)))
        items = [json.loads(json.dumps(p)) for p in self.policies]
        if text:
            needle = text.lower()
            items = [p for p in items if needle in p["metadata"]["name"].lower() or needle in str(p["metadata"].get("description") or "").lower()]
        tag = _TAG_FILTER.search(filter_query or "")
        if tag:
            items = [p for p in items if tag.group(1) in (p["metadata"].get("policyTags") or [])]
        if self.partial_list:
            for p in items:
                p.pop("targets", None)
        return items

    def find_policies_for_fqdn(self, fqdn):
        return self.list_policies(text=fqdn, filter_query="(targetCategory eq 'VM')")

    def get_policy(self, policy_id):
        self.calls.append(("get_policy", policy_id))
        for p in self.policies:
            if p["metadata"].get("policyId") == policy_id:
                copy = json.loads(json.dumps(p))
                if self.statuses_sequence:
                    copy["metadata"]["status"] = {"status": self.statuses_sequence.pop(0), "statusDescription": "connector unreachable"}
                return copy
        raise SIAApiError("GET", f"/api/policies/{policy_id}", 404, "not found")

    def find_policy_by_name(self, name):
        self.calls.append(("find_policy_by_name", name))
        for p in self.policies:
            if p["metadata"]["name"] == name:
                copy = json.loads(json.dumps(p))
                if self.partial_list:
                    copy.pop("targets", None)
                return copy
        return None

    def create_policy(self, payload):
        self.calls.append(("create_policy", payload))
        if self.raise_on_create_policy:
            raise self.raise_on_create_policy
        name = payload["metadata"]["name"]
        if name in self.conflict_on_create or any(p["metadata"]["name"] == name for p in self.policies):
            raise SIAApiError("POST", "/api/policies", 409, f"policy name '{name}' already exists")
        self._counter += 1
        pid = f"pol-{self._counter}"
        stored = json.loads(json.dumps(payload))
        stored["metadata"]["policyId"] = pid
        stored["metadata"]["status"] = {"status": self.create_status}
        self.policies.append(stored)
        return pid

    def update_policy(self, policy_id, payload):
        self.calls.append(("update_policy", (policy_id, payload)))
        if self.raise_on_update_policy:
            raise self.raise_on_update_policy
        for i, p in enumerate(self.policies):
            if p["metadata"].get("policyId") == policy_id:
                stored = json.loads(json.dumps(payload))
                stored["metadata"].setdefault("status", p["metadata"].get("status") or {"status": "Active"})
                self.policies[i] = stored
                return
        raise SIAApiError("PUT", f"/api/policies/{policy_id}", 404, "not found")


class FakePVWA:
    def __init__(self, accounts: list[dict[str, Any]] | None = None):
        self.accounts = list(accounts or [])
        self.calls: list[tuple[str, Any]] = []
        self.raise_on_add: SIAApiError | None = None
        self.logged_off = False
        self._counter = 0

    def find_account(self, safe, name):
        self.calls.append(("find_account", (safe, name)))
        for a in self.accounts:
            if a["name"].lower() == name.lower() and a["safeName"].lower() == safe.lower():
                return dict(a)
        return None

    def add_account(self, payload):
        self.calls.append(("add_account", {k: v for k, v in payload.items() if k != "secret"}))
        if self.raise_on_add:
            raise self.raise_on_add
        self._counter += 1
        created = {"id": f"{self._counter}_1", "name": payload["name"], "safeName": payload["safeName"],
                   "address": payload["address"], "userName": payload["userName"], "platformId": payload["platformId"]}
        self.accounts.append(created)
        return dict(created)

    def logoff(self):
        self.logged_off = True


class FakeResponse:
    def __init__(self, status: int, body: Any = None, headers: dict[str, str] | None = None, url: str = "https://x", method: str = "GET"):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self.url = url
        self.text = body if isinstance(body, str) else json.dumps(body if body is not None else {})
        self.request = type("Req", (), {"method": method})()

    def json(self):
        if isinstance(self._body, str):
            return json.loads(self._body)
        return self._body


class FakeSession:
    """Scripted requests.Session: `responses` is a list of FakeResponse (or callables taking (method, url, kwargs))."""

    def __init__(self, responses: list):
        self.responses = list(responses)
        self.requests: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method, url, **kw):
        self.requests.append((method, url, kw))
        if not self.responses:
            raise AssertionError(f"unexpected request {method} {url}")
        nxt = self.responses.pop(0)
        resp = nxt(method, url, kw) if callable(nxt) else nxt
        resp.url = url
        resp.request.method = method
        return resp

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)
