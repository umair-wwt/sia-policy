"""Identity Security Platform authentication for a service user.

Two adapters, both cached until shortly before expiry and both redacting secrets from any error text:

* PlatformTokenProvider     POST {identity_url}/oauth2/platformtoken (client credentials). Documented for the shared
                            services APIs (SIA, UAP). Used for the SIA/UAP calls.
* ServiceUserOIDCTokenProvider  The flow CyberArk's SDKs use for Identity itself:
                            POST {identity_url}/Oauth2/Token/<app> (Basic auth, client_credentials, scope=api)
                            GET  {identity_url}/OAuth2/Authorize/<app> -> 302 whose Location fragment carries id_token.
The Identity directory calls use whichever adapter `[auth] identity_auth` selects; `preflight` proves it works.
"""
from __future__ import annotations

import base64
import json
import logging
import math
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import requests
from requests.auth import HTTPBasicAuth

from .redact import redact, register_secret

PLATFORM_TOKEN_PATH = "/oauth2/platformtoken"
DEFAULT_OIDC_APPLICATION = "__idaptive_cybr_user_oidc"
OIDC_REDIRECT_URI = "https://cyberark.cloud/redirect"
_REFRESH_MARGIN_SECONDS = 60
_DEFAULT_LIFETIME_SECONDS = 15 * 60
_HEADERS = {"Accept": "application/json", "X-IDAP-NATIVE-CLIENT": "true"}


class AuthError(Exception):
    """Authentication failed without exposing a response that may echo credentials."""

    def __init__(self, message: str, *, status: int = 0, operation: str = "authentication",
                 cause: BaseException | None = None):
        self.status = int(status or 0)
        self.operation = operation
        self.cause = cause
        super().__init__(redact(message))


def jwt_claims(token: str) -> dict[str, Any]:
    """Decode a JWT payload without verification (used only for expiry and tenant sanity checks)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
        return decoded if isinstance(decoded, dict) else {}
    except (IndexError, ValueError, UnicodeDecodeError):
        return {}


class _CachingTokenProvider:
    name = "base"

    def __init__(self, identity_url: str, client_id: str, client_secret: str, *, timeout: int = 60,
                 session: requests.Session | None = None, logger: logging.Logger | None = None, clock=time.time,
                 verify: str | bool = True):
        if not client_id or not client_secret:
            raise AuthError("SIA_CLIENT_ID and SIA_CLIENT_SECRET must be set", operation="credential loading")
        register_secret(client_secret)
        self._identity_url = identity_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._timeout = timeout
        self._session = session or requests.Session()
        if verify is not True:      # a corporate CA bundle, or (lab only) verification turned off
            self._session.verify = verify
        self._log = logger or logging.getLogger("sia.auth")
        self._clock = clock
        self._token: str | None = None
        self._expires_at: float = 0.0
        self._lock = threading.Lock()  # concurrent workers share one provider

    def _stale(self) -> bool:
        return not self._token or self._clock() >= self._expires_at - _REFRESH_MARGIN_SECONDS

    def __call__(self, force: bool = False) -> str:
        if force or self._stale():
            with self._lock:
                if force or self._stale():
                    token, expires_at = self._fetch()
                    register_secret(token)
                    self._token, self._expires_at = token, expires_at
                    self._log.info("%s token acquired for %s (valid for ~%d min)", self.name, self._client_id,
                                   max(0, int((expires_at - self._clock()) / 60)))
                    force = False
        assert self._token is not None
        return self._token

    @property
    def claims(self) -> dict[str, Any]:
        return jwt_claims(self())

    def _expiry(self, token: str, lifetime: Any) -> float:
        exp_claim = jwt_claims(token).get("exp")
        if isinstance(lifetime, (int, float)) and not isinstance(lifetime, bool) and math.isfinite(lifetime) and lifetime > 0:
            return self._clock() + float(lifetime)
        if isinstance(exp_claim, (int, float)) and not isinstance(exp_claim, bool) and math.isfinite(exp_claim):
            return float(exp_claim)
        return self._clock() + _DEFAULT_LIFETIME_SECONDS

    @staticmethod
    def _token_payload(body: Any, *, status: int, operation: str) -> tuple[str, Any]:
        if not isinstance(body, dict):
            raise AuthError(f"{operation} must be a JSON object", status=status, operation=operation)
        token = body.get("access_token")
        if not isinstance(token, str) or not token.strip():
            raise AuthError(f"{operation} has no usable access_token", status=status, operation=operation)
        lifetime = body.get("expires_in")
        if lifetime is not None and not (
            isinstance(lifetime, (int, float)) and not isinstance(lifetime, bool)
            and math.isfinite(lifetime) and lifetime > 0
        ):
            raise AuthError(f"{operation} has an invalid expires_in value", status=status, operation=operation)
        return token, lifetime

    def _fetch(self) -> tuple[str, float]:  # pragma: no cover - abstract
        raise NotImplementedError


class PlatformTokenProvider(_CachingTokenProvider):
    """OAuth2 client-credentials platform token. The service user must be flagged "Is OAuth confidential client"."""

    name = "platform_token"

    def _fetch(self) -> tuple[str, float]:
        url = self._identity_url + PLATFORM_TOKEN_PATH
        self._log.info("Requesting platform token from %s", url)
        try:
            resp = self._session.post(url, data={"grant_type": "client_credentials", "client_id": self._client_id,
                                                 "client_secret": self._client_secret},
                                      headers=dict(_HEADERS), timeout=self._timeout)
        except requests.RequestException as exc:
            raise AuthError(f"could not reach {url}: {exc.__class__.__name__}: {exc}",
                            operation="platform token request", cause=exc) from exc
        if resp.status_code != 200:
            raise AuthError(f"platform token request failed (HTTP {resp.status_code}): *** response suppressed because "
                            "authentication responses may contain credentials. Check identity_url, the service user's "
                            "'Is OAuth confidential client' flag, and its password/role.", status=resp.status_code,
                            operation="platform token request")
        try:
            payload = resp.json()
        except ValueError as exc:
            raise AuthError("platform token response is not JSON", status=resp.status_code,
                            operation="platform token response", cause=exc) from exc
        token, lifetime = self._token_payload(payload, status=resp.status_code, operation="platform token response")
        return token, self._expiry(token, lifetime)


class ServiceUserOIDCTokenProvider(_CachingTokenProvider):
    """The service-user flow used by CyberArk's SDKs; yields an id_token accepted by Identity's own APIs."""

    name = "service_user_oidc"

    def __init__(self, identity_url: str, client_id: str, client_secret: str, *, application: str = DEFAULT_OIDC_APPLICATION, **kw):
        super().__init__(identity_url, client_id, client_secret, **kw)
        self._app = application

    def _fetch(self) -> tuple[str, float]:
        token_url = f"{self._identity_url}/Oauth2/Token/{self._app}"
        self._log.info("Requesting service-user access token from %s", token_url)
        try:
            resp = self._session.post(token_url, auth=HTTPBasicAuth(self._client_id, self._client_secret),
                                      data={"grant_type": "client_credentials", "scope": "api"},
                                      headers=dict(_HEADERS), timeout=self._timeout)
        except requests.RequestException as exc:
            raise AuthError(f"could not reach {token_url}: {exc.__class__.__name__}: {exc}",
                            operation="service-user token request", cause=exc) from exc
        if resp.status_code != 200:
            raise AuthError(f"service-user token request failed (HTTP {resp.status_code}): *** response suppressed because "
                            "authentication responses may contain credentials", status=resp.status_code,
                            operation="service-user token request")
        try:
            payload = resp.json()
        except ValueError as exc:
            raise AuthError("service-user token response is not JSON", status=resp.status_code,
                            operation="service-user token response", cause=exc) from exc
        access_token, _ = self._token_payload(payload, status=resp.status_code,
                                              operation="service-user token response")
        register_secret(access_token)

        authorize_url = f"{self._identity_url}/OAuth2/Authorize/{self._app}"
        params = {"client_id": self._app, "response_type": "id_token", "scope": "openid profile api",
                  "redirect_uri": OIDC_REDIRECT_URI}
        try:
            resp = self._session.get(authorize_url, headers={"Authorization": f"Bearer {access_token}", **_HEADERS},
                                     params=params, allow_redirects=False, timeout=self._timeout)
        except requests.RequestException as exc:
            raise AuthError(f"could not reach {authorize_url}: {exc.__class__.__name__}: {exc}",
                            operation="service-user authorization", cause=exc) from exc
        location = resp.headers.get("Location", "")
        if resp.status_code != 302 or not isinstance(location, str) or not location:
            raise AuthError(f"service-user authorization failed (HTTP {resp.status_code}): *** response suppressed because "
                            "authentication responses may contain credentials", status=resp.status_code,
                            operation="service-user authorization")
        parts = urlsplit(location)
        id_token = (parse_qs(parts.fragment).get("id_token") or parse_qs(parts.query).get("id_token") or [None])[0]
        if not isinstance(id_token, str) or not id_token.strip():
            raise AuthError("service-user authorization redirect carries no id_token", status=resp.status_code,
                            operation="service-user authorization")
        return id_token, self._expiry(id_token, None)


def make_identity_token_provider(method: str, platform_provider: PlatformTokenProvider, *, identity_url: str,
                                 client_id: str, client_secret: str, application: str = DEFAULT_OIDC_APPLICATION,
                                 timeout: int = 60, session: requests.Session | None = None,
                                 verify: str | bool = True):
    """Select the adapter used for Identity directory calls ([auth] identity_auth)."""
    if method == "platform_token":
        return platform_provider
    if method == "service_user_oidc":
        return ServiceUserOIDCTokenProvider(identity_url, client_id, client_secret, application=application,
                                            timeout=timeout, session=session, verify=verify)
    raise AuthError(f"unknown identity_auth method {method!r}", operation="identity authentication selection")
