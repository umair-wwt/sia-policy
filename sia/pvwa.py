"""PAM Self-Hosted (PVWA) REST API: the optional `vault` stage onboards local administrator accounts that are not
in the Vault yet, so SIA's vault reference (<account_name>_<safe>) can point at them.

  POST /PasswordVault/API/auth/{CyberArk|LDAP}/Logon   -> session token (sent verbatim in Authorization)
  GET  /PasswordVault/API/Accounts?search=<name>&filter=safeName eq <safe>
  POST /PasswordVault/API/Accounts                      -> the created account (id, name, safeName, ...)
  POST /PasswordVault/API/auth/Logoff
"""
from __future__ import annotations

import logging
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
        # The session token cannot be refreshed, so a 401 must surface at once: retrying a rejected logon would
        # count a second failed attempt against the Vault user's lockout threshold.
        self._http = HttpClient(lambda force=False: self._token or "-", timeout=timeout, max_retries=max_retries,
                                session=session, logger=self._log, sleep=sleep, verify=verify, refresh_on_401=False)

    @property
    def base_url(self) -> str:
        return self._base

    def _headers(self) -> dict[str, str]:
        if not self._token:
            raise SIAApiError("GET", self._base, 0, "PVWA: not logged on (call logon first)")
        return {"Authorization": self._token}   # PVWA tokens are sent verbatim, not as Bearer

    def logon(self, username: str, password: str) -> None:
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
        if not self._token:
            return
        try:
            self._http.post(f"{self._base}/PasswordVault/API/auth/Logoff", headers=self._headers(), expected=(200, 204))
        except SIAApiError as exc:   # best effort; the session expires on its own
            self._log.debug("PVWA logoff failed: %s", exc)
        self._token = None

    def find_account(self, safe: str, name: str, *, max_pages: int = MAX_ACCOUNT_PAGES) -> dict[str, Any] | None:
        """The account named `name` in `safe`, or None."""
        if max_pages < 1:
            raise ValueError("max_pages must be at least 1")
        initial_url = f"{self._base}/PasswordVault/API/Accounts"
        url = initial_url
        params: dict[str, str] | None = {"search": name, "filter": f"safeName eq {safe}"}
        seen_urls: set[str] = set()
        seen_pages: set[str] = set()
        matches: dict[str, dict[str, Any]] = {}
        for _ in range(max_pages):
            response = self._http.get(url, params=params, headers=self._headers())
            params = None
            body = json_or_error(response)
            if not isinstance(body, dict) or not isinstance(body.get("value"), list):
                raise SIAApiError("GET", response.url, response.status_code,
                                  "PVWA account lookup response must contain a value list", cause="malformed_response")
            page = body["value"]
            for index, account in enumerate(page):
                if not isinstance(account, dict):
                    raise SIAApiError("GET", response.url, response.status_code,
                                      f"PVWA account lookup item {index} is not an object", cause="malformed_response")
                account_id = account.get("id")
                account_name = account.get("name")
                safe_name = account.get("safeName")
                if not all(isinstance(value, str) and value.strip() for value in (account_id, account_name, safe_name)):
                    raise SIAApiError("GET", response.url, response.status_code,
                                      f"PVWA account lookup item {index} needs non-empty id, name, and safeName",
                                      cause="malformed_response")
                if account_name.casefold() == name.casefold() and safe_name.casefold() == safe.casefold():
                    matches.setdefault(account_id, account)
            next_link = body.get("nextLink")
            if next_link in (None, ""):
                if len(matches) > 1:
                    raise SIAApiError("GET", initial_url, 200,
                                      f"PVWA account {name!r} in safe {safe!r} is ambiguous across ids: "
                                      f"{', '.join(sorted(matches))}", cause="ambiguous_response")
                return next(iter(matches.values()), None)
            if not isinstance(next_link, str) or not next_link.strip():
                raise SIAApiError("GET", response.url, response.status_code,
                                  "PVWA account nextLink must be a non-empty string or null",
                                  cause="malformed_response")
            next_url = urljoin(response.url, next_link)
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
        resp = self._http.post(f"{self._base}/PasswordVault/API/Accounts", json=payload, headers=headers,
                               expected=(200, 201), cancel_check=self.cancel_check)
        body = json_or_error(resp)
        valid = isinstance(body, dict) and isinstance(body.get("id"), str) and bool(body["id"].strip())
        expected_name = str(payload.get("name") or "")
        if valid and expected_name:
            valid = isinstance(body.get("name"), str) and body["name"].lower() == expected_name.lower()
        expected_safe = str(payload.get("safeName") or "")
        if valid and expected_safe and "safeName" in body:
            valid = isinstance(body["safeName"], str) and body["safeName"].lower() == expected_safe.lower()
        if not valid:
            raise SIAApiError("POST", resp.url, resp.status_code,
                              "PVWA account create response has no usable matching account id/name",
                              uncertain=True, cause="malformed_response")
        return body
