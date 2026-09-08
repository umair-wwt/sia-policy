"""Per-session state. File credentials never become persistent process environment."""
from __future__ import annotations

import os
import getpass
import warnings
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from .config import ConfigError, read_dotenv
from .redact import register_secret

_SECRET_WORDS = ("SECRET", "PASSWORD", "TOKEN")
_SHELL_SECRET_KEYS = frozenset({"SIA_CLIENT_SECRET", "PVWA_PASSWORD"})


def _looks_secret(key: str) -> bool:
    return any(word in key.upper() for word in _SECRET_WORDS)


def _consumed_shell_secret(key: str) -> bool:
    """Only the exported variables SIA itself reads. Registering every TOKEN/PASSWORD-named value in the
    shell masked ordinary words: TOKENIZERS_PARALLELISM=false hid every "false" in settings and reports."""
    name = key.upper()
    return name in _SHELL_SECRET_KEYS or (name.startswith("SIA_SA_") and name.endswith("_PASSWORD"))


def prompt_secret(prompt: str) -> str:
    """Never fall back to echoed password input when terminal controls are unavailable."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            value = getpass.getpass(prompt)
        except getpass.GetPassWarning as exc:
            raise ConfigError("Hidden password input is unavailable in this terminal. Use a terminal with hidden input, or configure the credential through the environment/.env file.") from exc
    register_secret(value)
    return value


@dataclass
class Session:
    shell_env: dict[str, str] = field(default_factory=lambda: dict(os.environ))
    secrets: dict[str, str] = field(default_factory=dict)
    last_diagnostics: list[dict] = field(default_factory=list)
    last_exit_code: int | None = None
    in_home: bool = False
    # Non-secret, in-memory editing state.  Keys are resolved configuration
    # paths so two projects can never resume one another's draft.
    config_drafts: dict[str, Any] = field(default_factory=dict)
    ignored_env_files: set[str] = field(default_factory=set)

    @staticmethod
    def path_key(path: str | Path) -> str:
        return str(Path(path).expanduser().resolve())

    def pending_drafts(self) -> tuple[Any, ...]:
        """Return only drafts whose current text differs from their baseline."""
        pending = []
        for draft in self.config_drafts.values():
            try:
                if draft.document.preview() != draft.baseline or draft.document.conflicts:
                    pending.append(draft)
            except (AttributeError, TypeError):
                continue
        return tuple(pending)

    def ignore_env_file(self, env_path: str | Path) -> None:
        self.ignored_env_files.add(self.path_key(env_path))

    def use_env_file(self, env_path: str | Path) -> None:
        self.ignored_env_files.discard(self.path_key(env_path))

    def _file_values(self, env_path: str | Path) -> dict[str, str]:
        if self.path_key(env_path) in self.ignored_env_files:
            return {}
        return read_dotenv(env_path)

    def values(self, env_path: str | Path) -> tuple[dict[str, str], dict[str, str]]:
        file_values = self._file_values(env_path)
        values = {**file_values, **self.secrets, **self.shell_env}
        sources = {key: "file" for key in file_values}
        sources.update({key: "session" for key in self.secrets})
        sources.update({key: "shell" for key in self.shell_env})
        for key, value in {**file_values, **self.secrets}.items():
            if _looks_secret(key):
                register_secret(value)
        for key, value in self.shell_env.items():
            if _consumed_shell_secret(key):
                register_secret(value)
        return values, sources

    @contextmanager
    def environment(self, env_path: str | Path) -> Iterator[None]:
        values, _ = self.values(env_path)
        # Only change explicit file/session keys. Preserve unrelated process state.
        keys = set(self._file_values(env_path)) | set(self.secrets)
        before = {key: os.environ.get(key) for key in keys}
        try:
            for key in keys:
                if key in values:
                    os.environ[key] = values[key]
            yield
        finally:
            for key, value in before.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
