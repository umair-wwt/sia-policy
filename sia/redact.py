"""Keep secrets out of error messages, logs and reports.

Every secret the process learns (client secret, tokens, strong-account passwords) is registered here; `redact()`
replaces occurrences in any text, and `RedactingFilter` applies that to every log record. Secrets are bucketed by
length so redaction costs the same with ten registered passwords or seventy thousand.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from typing import Any

_BY_LENGTH: dict[int, set[str]] = {}
MASK = "***"

# These patterns are a second line of defence for structured error text from a
# remote service.  Registered values remain the primary mechanism: unlike
# field-name matching, registration also catches a secret copied into prose.
_SENSITIVE_KEY = re.compile(
    r"^(?:password|passwd|secret|client[_-]?secret|token|access[_-]?token|id[_-]?token|refresh[_-]?token|authorization|api[_-]?key|cookie|set[_-]?cookie)$",
    re.IGNORECASE,
)
_SENSITIVE_TEXT = re.compile(
    r"(?i)(\b(?:password|passwd|secret|client[_-]?secret|token|access[_-]?token|id[_-]?token|refresh[_-]?token|authorization|api[_-]?key|cookie)\b"
    r"[\"']?\s*(?:=|:)\s*)(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;}\[\{]+)"
)
_BEARER = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+")
_URL_USERINFO = re.compile(r"(?i)(https?://)[^/@\s]+@")


def register_secret(value: str | None) -> None:
    """Register a value for exact redaction, including short credentials.

    Short OAuth tokens are unusual but valid.  Ignoring them made the safety
    guarantee depend on secret length, so every non-empty value is retained.
    """
    if value:
        value = str(value)
        _BY_LENGTH.setdefault(len(value), set()).add(value)


def secret_count() -> int:
    return sum(len(bucket) for bucket in _BY_LENGTH.values())


def redact(text: str) -> str:
    if not text or not _BY_LENGTH:
        return text
    for length in sorted(_BY_LENGTH, reverse=True):   # longest first, so a secret containing another is masked whole
        if length > len(text):
            continue
        bucket = _BY_LENGTH[length]
        out: list[str] = []
        i = last = 0
        end = len(text) - length
        while i <= end:
            matched = text[i:i + length] in bucket
            # A one-character test token must still be protected, but treating
            # it as a substring would turn ordinary prose into a wall of masks.
            # Short values therefore match as complete text tokens.
            if matched and length < 4:
                before = text[i - 1] if i else ""
                after = text[i + length] if i + length < len(text) else ""
                matched = not (before.isalnum() or after.isalnum())
            if matched:
                out.append(text[last:i])
                out.append(MASK)
                i += length
                last = i
            else:
                i += 1
        if last:
            out.append(text[last:])
            text = "".join(out)
    return text


def sanitize(value: Any) -> Any:
    """Return a JSON-safe, recursively redacted copy of diagnostic/report data.

    Sensitive mapping keys are masked even when their values were not
    explicitly registered (for example, a token returned unexpectedly in an
    error response).  Unknown objects become a redacted string instead of
    leaking their repr into JSON or crashing error handling.
    """
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        text = redact(value)
        text = _URL_USERINFO.sub(r"\1***@", text)
        text = _BEARER.sub(r"\1***", text)
        return _SENSITIVE_TEXT.sub(r"\1***", text)
    if isinstance(value, bytes):
        return sanitize(value.decode("utf-8", errors="replace"))
    if isinstance(value, Mapping):
        clean: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(sanitize(str(raw_key)))
            sensitive = bool(_SENSITIVE_KEY.search(str(raw_key)))
            # Reports use `secret` for a structured stage outcome. Recursively
            # sanitize that container; the PVWA credential named `secret` is a scalar.
            if str(raw_key).casefold() == "secret" and isinstance(raw_value, (Mapping, list, tuple)):
                sensitive = False
            clean[key] = MASK if sensitive else sanitize(raw_value)
        return clean
    if isinstance(value, (list, tuple, set, frozenset)):
        return [sanitize(item) for item in value]
    return sanitize(str(value))


_TIME_LIKE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]")


def scrub_identity(document: Any) -> Any:
    """A policy GET with its identifying values replaced by stable placeholders and every key, value type and
    unrecognised field kept: what a committed tenant fixture (``tests/fixtures/tenants/``) may contain.

    Names, descriptions, ids, principals, directories, hosts, domains and IP ranges identify a customer; the *shape*
    of the object -- which keys the tenant echoes and with which value types -- is the observation worth keeping.
    Tags, time zones and settings are kept as they are: review the file before committing it.
    """
    counters: dict[str, int] = {}
    memo: dict[tuple[str, str], int] = {}

    def number(kind: str, value: str) -> int:
        key = (kind, value)
        if key not in memo:
            counters[kind] = counters.get(kind, 0) + 1
            memo[key] = counters[kind]
        return memo[key]

    def scrub_string(value: str, path: tuple[str, ...]) -> str:
        key = path[-1] if path else ""
        parent = tuple(segment for segment in path if segment != "[]")
        if parent[:2] in (("metadata", "name"),):
            return "fixture-policy"
        if parent[:2] == ("metadata", "description"):
            return "fixture description"
        if parent[:2] in (("metadata", "policyId"), ("metadata", "policy_id")):
            return "00000000-0000-4000-8000-000000000001"
        if len(parent) >= 2 and parent[0] == "metadata" and parent[1] in ("createdBy", "updatedOn"):
            return "2026-01-01T00:00:00Z" if _TIME_LIKE.match(value) else "fixture-user"
        if parent and parent[0] == "principals":
            if key == "id":
                return f"principal-{number('principal', value)}"
            if key == "name":
                return f"fixture-principal-{number('principal-name', value)}"
            if key == "sourceDirectoryId":
                return f"directory-{number('directory', value)}"
            if key == "sourceDirectoryName":
                return "fixture-directory"
        if parent and parent[0] == "targets":
            if key == "computernamePattern":
                if value.startswith("*"):
                    return "*.fixture.example.com"
                index = number("host", value)
                return f"host{index}.fixture.example.com" if "." in value else f"host{index}"
            if key == "domain":
                return "fixture.example.com"
            if key != "operator" and any(segment.lower().startswith("ip") for segment in parent[1:]):
                return f"10.0.{number('ip', value)}.0/24"
        if parent and parent[0] == "conditions" and "approvers" in parent:
            if key == "id":
                return f"approver-{number('approver', value)}"
            return "fixture-approver" if key == "name" else value
        if parent and parent[0] == "behavior":
            if key == "username":
                return "fixture-user"
            if parent[-1] in ("assignGroups", "assignDomainGroups"):
                return f"group-{number('group', value)}"
        return value

    def walk(value: Any, path: tuple[str, ...]) -> Any:
        if isinstance(value, Mapping):
            return {str(key): walk(item, path + (str(key),)) for key, item in value.items()}
        if isinstance(value, list):
            return [walk(item, path + ("[]",)) for item in value]
        if isinstance(value, str) and value:
            return scrub_string(value, path)
        return value

    return walk(document, ())


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = sanitize(record.getMessage())
        except Exception:
            record.msg = "[Log message could not be formatted safely]"
        record.args = ()
        if record.exc_info:
            record.exc_text = str(sanitize(logging.Formatter().formatException(record.exc_info)))
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = str(sanitize(record.exc_text))
        if record.stack_info:
            record.stack_info = str(sanitize(record.stack_info))
        return True


def _reset_for_tests() -> None:
    _BY_LENGTH.clear()
