"""PAM Self-Hosted (PVWA) REST API: the optional `vault` stage onboards local administrator accounts that are not
in the Vault yet, so SIA's vault reference (<account_name>_<safe>) can point at them.

  POST /PasswordVault/API/auth/{CyberArk|LDAP}/Logon   -> session token (sent verbatim in Authorization)
  GET  /PasswordVault/API/Accounts?search=<name>&filter=safeName eq <safe>
       (an empty search is confirmed against the safe itself, read once per reconciliation pass:
        ?filter=safeName eq <safe>)
  POST /PasswordVault/API/Accounts                      -> the created account (id, name, safeName, ...)
  POST /PasswordVault/API/auth/Logoff
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

import requests

from .auth import AuthError
from .http import HttpClient, SIAApiError, json_or_error
from .redact import register_secret

AUTH_PATHS = {"cyberark": "CyberArk", "ldap": "LDAP"}
MAX_ACCOUNT_PAGES = 10_000


class PVWAClient:
    def __init__(self, base_url: str, *, auth_type: str = "cyberark", timeout: int = 60, max_retries: int = 2,
                 session: requests.Session | None = None, logger: logging.Logger | None = None, verify: str | bool = True,
                 sleep: Callable[[float], None] = time.sleep,
                 cancel_check: Callable[[], None] | None = None):
        if auth_type not in AUTH_PATHS:
            raise ValueError(f"auth_type must be one of {', '.join(AUTH_PATHS)}")
        self._base = base_url.rstrip("/")
        self._auth_type = auth_type
        self._token: str | None = None
        self._log = logger or logging.getLogger("sia.pvwa")
        self.cancel_check = cancel_check
        # Safes read in full by find_account, keyed by casefolded safe, then account name, then id.
        self._safes: dict[str, dict[str, dict[str, dict[str, Any]]]] = {}
        self._safes_lock = threading.Lock()
        # The session token cannot be refreshed, so a 401 must surface at once: retrying a rejected logon would
        # count a second failed attempt against the Vault user's lockout threshold.
        self._http = HttpClient(lambda force=False: self._token or "-", timeout=timeout, max_retries=max_retries,
                                session=session, logger=self._log, sleep=sleep, verify=verify, refresh_on_401=False)

    @property
    def base_url(self) -> str:
        return self._base

    def reset_lookup_cache(self) -> None:
        """Start a fresh safe snapshot, especially between preview and apply or after an uncertain write."""
        with self._safes_lock:
            self._safes.clear()

    def _headers(self) -> dict[str, str]:
        if not self._token:
            raise SIAApiError("GET", self._base, 0, "PVWA: not logged on (call logon first)")
        return {"Authorization": self._token}   # PVWA tokens are sent verbatim, not as Bearer

    def logon(self, username: str, password: str) -> None:
        self._token = None
        self.reset_lookup_cache()
        url = f"{self._base}/PasswordVault/API/auth/{AUTH_PATHS[self._auth_type]}/Logon"
        register_secret(password)
        try:
            response = self._http.post(url, json={"username": username, "password": password, "concurrentSession": True},
                                       headers={"Authorization": "-"}, expected=(200,))
            body = json_or_error(response)
        except SIAApiError as exc:
            label = f"HTTP {exc.status}" if exc.status else "no response"
            raise AuthError(f"PVWA logon failed ({label}): *** response suppressed because authentication responses "
                            "may contain credentials", status=exc.status, operation="PVWA logon", cause=exc) from exc
        token = body if isinstance(body, str) else (body.get("token") if isinstance(body, dict) else None)
        if not isinstance(token, str) or not token.strip():
            raise SIAApiError("POST", url, 200, "PVWA logon returned no token")
        register_secret(token)
        self._token = token
        self._log.info("PVWA logon OK for %s", username)

    def logoff(self) -> None:
        try:
            if self._token:
                self._http.post(f"{self._base}/PasswordVault/API/auth/Logoff", headers=self._headers(), expected=(200, 204))
        except SIAApiError as exc:   # best effort; the session expires on its own
            self._log.debug("PVWA logoff failed: %s", exc)
        finally:
            self._token = None
            self.reset_lookup_cache()

    def find_account(self, safe: str, name: str, *, max_pages: int = MAX_ACCOUNT_PAGES) -> dict[str, Any] | None:
        """The account named `name` in `safe`, or None."""
        if max_pages < 1:
            raise ValueError("max_pages must be at least 1")
        matches = self._exact(self._walk_accounts({"search": name, "filter": self._safe_filter(safe)}, max_pages),
                              safe, name)
        if not matches:
            # `search` is a server-side substring match over a set this walk re-checks exactly, so it only narrows
            # what the exact comparison would pick out anyway. On a tenant whose search misses a name the safe does
            # hold, believing the empty result onboards a SECOND privileged account into that safe -- so check the
            # safe itself before concluding the account is absent. The vault stage exists to onboard accounts that
            # are missing, so nearly every lookup ends up here: the safe is read once per reconciliation pass and
            # indexed. The reconciler resets this snapshot before each pass, including the apply after a preview.
            matches = dict(self._safe_index(safe, max_pages).get(name.casefold(), {}))
            if matches:
                self._log.warning("account %r was not returned by search=%r but safe %r holds it; this Vault's "
                                  "account search is unreliable", name, name, safe)
        if len(matches) > 1:
            raise SIAApiError("GET", f"{self._base}/PasswordVault/API/Accounts", 200,
                              f"PVWA account {name!r} in safe {safe!r} is ambiguous across ids: "
                              f"{', '.join(sorted(matches))}", cause="ambiguous_response")
        return next(iter(matches.values()), None)

    @staticmethod
    def _safe_filter(safe: str) -> str:
        return f"safeName eq {safe}"

    @staticmethod
    def _exact(accounts: list[dict[str, Any]], safe: str, name: str) -> dict[str, dict[str, Any]]:
        """The accounts whose name and safe both match exactly (case-insensitively), keyed by id."""
        matches: dict[str, dict[str, Any]] = {}
        for account in accounts:
            if account["name"].casefold() == name.casefold() and account["safeName"].casefold() == safe.casefold():
                matches.setdefault(account["id"], account)
        return matches

    def _safe_index(self, safe: str, max_pages: int) -> dict[str, dict[str, dict[str, Any]]]:
        """Every account in `safe`, keyed by casefolded name and then id. Reused until reset_lookup_cache;
        add_account records this client's confirmed creations while an uncertain write invalidates the snapshot."""
        key = safe.casefold()
        with self._safes_lock:
            index = self._safes.get(key)
            if index is None:
                index = {}
                for account in self._walk_accounts({"filter": self._safe_filter(safe)}, max_pages):
                    if account["safeName"].casefold() == key:
                        index.setdefault(account["name"].casefold(), {}).setdefault(account["id"], account)
                self._safes[key] = index
            return index

    def _remember(self, account: dict[str, Any]) -> None:
        """Record an account this client just onboarded in its safe's index, if that safe has been read."""
        safe_name, name, account_id = account.get("safeName"), account.get("name"), account.get("id")
        if not all(isinstance(value, str) and value.strip() for value in (safe_name, name, account_id)):
            return
        with self._safes_lock:
            index = self._safes.get(safe_name.casefold())
            if index is not None:
                index.setdefault(name.casefold(), {}).setdefault(account_id, account)

    def _walk_accounts(self, params: dict[str, str], max_pages: int) -> list[dict[str, Any]]:
        """Walk /Accounts with `params`, returning every account, each with a non-empty id, name and safeName."""
        initial_url = f"{self._base}/PasswordVault/API/Accounts"
        url = initial_url
        request_params: dict[str, str] | None = dict(params)
        seen_urls: set[str] = set()
        seen_pages: set[str] = set()
        accounts: list[dict[str, Any]] = []
        for _ in range(max_pages):
            response = self._http.get(url, params=request_params, headers=self._headers())
            request_params = None
            body = json_or_error(response)
            if not isinstance(body, dict) or not isinstance(body.get("value"), list):
                raise SIAApiError("GET", response.url, response.status_code,
                                  "PVWA account lookup response must contain a value list", cause="malformed_response")
            page = body["value"]
            for index, account in enumerate(page):
                if not isinstance(account, dict):
                    raise SIAApiError("GET", response.url, response.status_code,
                                      f"PVWA account lookup item {index} is not an object", cause="malformed_response")
                if not all(isinstance(value, str) and value.strip()
                           for value in (account.get("id"), account.get("name"), account.get("safeName"))):
                    raise SIAApiError("GET", response.url, response.status_code,
                                      f"PVWA account lookup item {index} needs non-empty id, name, and safeName",
                                      cause="malformed_response")
                accounts.append(account)
            next_link = body.get("nextLink")
            if next_link in (None, ""):
                return accounts
            if not isinstance(next_link, str) or not next_link.strip():
                raise SIAApiError("GET", response.url, response.status_code,
                                  "PVWA account nextLink must be a non-empty string or null",
                                  cause="malformed_response")
            # PVWA returns application-relative links such as "api/Accounts?offset=50", rooted at PasswordVault.
            # Query-only continuations refer to the current Accounts endpoint; absolute and root-relative links
            # retain their standard URL meaning and must still pass the origin check below.
            link_base = response.url if next_link.startswith("?") else f"{self._base}/PasswordVault/"
            next_url = urljoin(link_base, next_link)
            base_parts, next_parts = urlsplit(self._base), urlsplit(next_url)
            if (next_parts.scheme, next_parts.netloc) != (base_parts.scheme, base_parts.netloc):
                raise SIAApiError("GET", response.url, response.status_code,
                                  "PVWA account nextLink points outside the configured PVWA origin",
                                  cause="malformed_response")
            signature = repr(page)
            if not page or signature in seen_pages:
                raise SIAApiError("GET", initial_url, 200, "PVWA account pagination made no progress",
                                  cause="incomplete_pagination")
            if next_url in seen_urls:
                raise SIAApiError("GET", initial_url, 200, "PVWA account pagination link repeated or cycled",
                                  cause="incomplete_pagination")
            seen_pages.add(signature)
            seen_urls.add(next_url)
            url = next_url
        raise SIAApiError("GET", initial_url, 200,
                          f"PVWA account pagination exceeded the {max_pages}-page safety limit",
                          cause="incomplete_pagination")

    def add_account(self, payload: dict[str, Any]) -> dict[str, Any]:
        headers = self._headers()
        try:
            resp = self._http.post(f"{self._base}/PasswordVault/API/Accounts", json=payload, headers=headers,
                                   expected=(200, 201), cancel_check=self.cancel_check)
            body = json_or_error(resp)
            valid = isinstance(body, dict) and all(isinstance(body.get(field), str) and body[field].strip()
                                                  for field in ("id", "name", "safeName"))
            for field in ("name", "safeName"):
                expected = str(payload.get(field) or "")
                if valid and expected:
                    valid = body[field].casefold() == expected.casefold()
            if not valid:
                raise SIAApiError("POST", resp.url, resp.status_code,
                                  "PVWA account create response has no usable matching account id/name/safeName",
                                  uncertain=True, cause="malformed_response")
        except SIAApiError as exc:
            if exc.uncertain or exc.cause == "malformed_response":
                self.reset_lookup_cache()
            raise
        self._remember(body)
        return body
