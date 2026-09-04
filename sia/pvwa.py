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

import requests

from .http import HttpClient, SIAApiError, json_or_error
from .redact import register_secret

AUTH_PATHS = {"cyberark": "CyberArk", "ldap": "LDAP"}


class PVWAClient:
    def __init__(self, base_url: str, *, auth_type: str = "cyberark", timeout: int = 60, max_retries: int = 2,
                 session: requests.Session | None = None, logger: logging.Logger | None = None, verify: str | bool = True,
                 sleep: Callable[[float], None] = time.sleep):
        if auth_type not in AUTH_PATHS:
            raise ValueError(f"auth_type must be one of {', '.join(AUTH_PATHS)}")
        self._base = base_url.rstrip("/")
        self._auth_type = auth_type
        self._token: str | None = None
        self._log = logger or logging.getLogger("sia.pvwa")
        self._http = HttpClient(lambda force=False: self._token or "-", timeout=timeout, max_retries=max_retries,
                                session=session, logger=self._log, sleep=sleep, verify=verify)

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
        body = json_or_error(self._http.post(url, json={"username": username, "password": password, "concurrentSession": True},
                                             headers={"Authorization": "-"}, expected=(200,)))
        token = body if isinstance(body, str) else (body.get("token") if isinstance(body, dict) else None)
        if not token:
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

    def find_account(self, safe: str, name: str) -> dict[str, Any] | None:
        """The account named `name` in `safe`, or None."""
        body = json_or_error(self._http.get(f"{self._base}/PasswordVault/API/Accounts",
                                            params={"search": name, "filter": f"safeName eq {safe}"}, headers=self._headers()))
        for account in (body.get("value") or []) if isinstance(body, dict) else []:
            if str(account.get("name") or "").lower() == name.lower() and str(account.get("safeName") or "").lower() == safe.lower():
                return account
        return None

    def add_account(self, payload: dict[str, Any]) -> dict[str, Any]:
        resp = self._http.post(f"{self._base}/PasswordVault/API/Accounts", json=payload, headers=self._headers(),
                               expected=(200, 201))
        return json_or_error(resp)
