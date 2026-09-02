"""Thin HTTP layer: one session, bearer auth, structured errors, and a retry policy that cannot duplicate objects.

Retry policy
  * 401           -> refresh the token once and retry (any method).
  * 429           -> retry with backoff (any method: the request was rejected, not processed). With a RateLimiter,
                     every worker pauses for the same interval.
  * 5xx / network -> retry only for idempotent methods (GET/HEAD/OPTIONS/PUT/DELETE). A POST that failed this way
                     is reported as *uncertain*: it may have been applied. The caller re-runs `plan`, which finds the
                     object by name if it was created, instead of blindly re-posting.
Bodies are never logged; error text is passed through the redactor.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Iterable

import requests

from .redact import redact

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
RETRY_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})
_MAX_ERROR_SNIPPET = 600
UNCERTAIN_HINT = " -- the request may or may not have been applied; run `plan` to reconcile before retrying"


class SIAApiError(Exception):
    """An API call failed. `status` is 0 for network errors. `uncertain` means a non-idempotent request may have landed."""

    def __init__(self, method: str, url: str, status: int, body: str, *, uncertain: bool = False):
        self.method, self.url, self.status, self.uncertain = method, url, status, uncertain
        self.body = redact(body or "")
        snippet = " ".join(self.body.split())[:_MAX_ERROR_SNIPPET]
        label = f"HTTP {status}" if status else "no response"
        super().__init__(redact(f"{method} {url} -> {label}: {snippet or '<empty body>'}{UNCERTAIN_HINT if uncertain else ''}"))

    @property
    def client_error(self) -> bool:
        return 400 <= self.status < 500

    @property
    def not_found(self) -> bool:
        return self.status in (404, 405, 501)


class RateLimiter:
    """Token bucket shared by all workers (requests per second). `penalize()` pauses everyone after a 429."""

    def __init__(self, rate_per_second: float, *, burst: int | None = None,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep):
        self._rate = float(rate_per_second)
        self._capacity = float(burst if burst else max(1, int(self._rate)))
        self._tokens = self._capacity
        self._clock, self._sleep = clock, sleep
        self._updated = clock()
        self._resume_at = 0.0
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._rate > 0

    def acquire(self) -> None:
        if not self.enabled:
            return
        while True:
            with self._lock:
                now = self._clock()
                wait = self._resume_at - now
                if wait <= 0:
                    self._tokens = min(self._capacity, self._tokens + (now - self._updated) * self._rate)
                    self._updated = now
                    if self._tokens >= 1.0:
                        self._tokens -= 1.0
                        return
                    wait = (1.0 - self._tokens) / self._rate
            self._sleep(wait)

    def penalize(self, seconds: float) -> None:
        """After a 429: nobody sends anything for `seconds` (the longest penalty wins)."""
        with self._lock:
            self._resume_at = max(self._resume_at, self._clock() + max(0.0, seconds))


class HttpClient:
    """Wraps requests.Session. `token_provider(force=False)` returns a bearer token (refreshed on 401)."""

    def __init__(
        self,
        token_provider: Callable[..., str],
        *,
        timeout: int = 60,
        max_retries: int = 4,
        session: requests.Session | None = None,
        logger: logging.Logger | None = None,
        sleep: Callable[[float], None] = time.sleep,
        limiter: RateLimiter | None = None,
    ):
        self._token_provider = token_provider
        self._timeout = timeout
        self._max_retries = max_retries
        self._session = session or requests.Session()
        self._log = logger or logging.getLogger("sia.http")
        self._sleep = sleep
        self._limiter = limiter

    def request(
        self,
        method: str,
        url: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        data: Any = None,
        headers: dict[str, str] | None = None,
        expected: Iterable[int] = (200,),
    ) -> requests.Response:
        expected = set(expected)
        method = method.upper()
        retry_safe = method in RETRY_SAFE_METHODS
        attempt = 0
        refreshed = False
        while True:
            hdrs = {
                "Accept": "application/json",
                "Authorization": f"Bearer {self._token_provider()}",
                "X-IDAP-NATIVE-CLIENT": "true",
            }
            if headers:
                hdrs.update(headers)
            if self._limiter is not None:
                self._limiter.acquire()
            try:
                resp = self._session.request(method, url, json=json, params=params, data=data, headers=hdrs,
                                             timeout=self._timeout)
            except requests.RequestException as exc:
                if retry_safe and attempt < self._max_retries:
                    delay = self._backoff(attempt)
                    self._log.warning("%s %s -> %s, retrying in %.1fs (attempt %d/%d)", method, url,
                                      exc.__class__.__name__, delay, attempt + 1, self._max_retries)
                    self._sleep(delay)
                    attempt += 1
                    continue
                raise SIAApiError(method, url, 0, f"network error: {exc.__class__.__name__}: {exc}",
                                  uncertain=not retry_safe) from exc
            self._log.debug("%s %s -> %s", method, resp.url, resp.status_code)
            if resp.status_code in expected:
                return resp
            if resp.status_code == 401 and not refreshed:
                refreshed = True
                self._log.info("401 received, refreshing token and retrying once")
                self._token_provider(force=True)
                continue
            retryable = resp.status_code == 429 or (retry_safe and resp.status_code in RETRY_STATUSES)
            if retryable and attempt < self._max_retries:
                delay = self._retry_delay(resp, attempt)
                if resp.status_code == 429 and self._limiter is not None:
                    self._limiter.penalize(delay)
                self._log.warning("%s %s -> %s, retrying in %.1fs (attempt %d/%d)", method, url, resp.status_code,
                                  delay, attempt + 1, self._max_retries)
                self._sleep(delay)
                attempt += 1
                continue
            raise SIAApiError(method, url, resp.status_code, resp.text or "",
                              uncertain=(not retry_safe and resp.status_code >= 500))

    @staticmethod
    def _backoff(attempt: int) -> float:
        return min(0.5 * (2 ** attempt), 16.0)

    @classmethod
    def _retry_delay(cls, resp: requests.Response, attempt: int) -> float:
        retry_after = resp.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            return min(float(retry_after), 60.0)
        return cls._backoff(attempt)

    def get(self, url: str, **kw) -> requests.Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> requests.Response:
        return self.request("POST", url, **kw)

    def put(self, url: str, **kw) -> requests.Response:
        return self.request("PUT", url, **kw)

    def delete(self, url: str, **kw) -> requests.Response:
        return self.request("DELETE", url, **kw)


def json_or_error(resp: requests.Response) -> Any:
    """Parse JSON, converting decode failures into SIAApiError so callers see the endpoint that misbehaved."""
    try:
        return resp.json()
    except ValueError as exc:
        raise SIAApiError(resp.request.method or "?", resp.url, resp.status_code,
                          f"response is not JSON: {exc}") from exc
