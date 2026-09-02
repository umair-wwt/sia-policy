"""Keep secrets out of error messages, logs and reports.

Every secret the process learns (client secret, tokens, strong-account passwords) is registered here; `redact()`
replaces occurrences in any text, and `RedactingFilter` applies that to every log record. Secrets are bucketed by
length so redaction costs the same with ten registered passwords or seventy thousand.
"""
from __future__ import annotations

import logging

_BY_LENGTH: dict[int, set[str]] = {}
_MIN_LENGTH = 4
MASK = "***"


def register_secret(value: str | None) -> None:
    if value and len(value) >= _MIN_LENGTH:
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
            if text[i:i + length] in bucket:
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


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: (redact(v) if isinstance(v, str) else v) for k, v in record.args.items()}
            else:
                record.args = tuple(redact(a) if isinstance(a, str) else a for a in record.args)
        return True


def _reset_for_tests() -> None:
    _BY_LENGTH.clear()
