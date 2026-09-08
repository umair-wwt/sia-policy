"""The non-secret project configuration included in source and installed packages."""
from __future__ import annotations

import os
import tomllib
from importlib.resources import files
from pathlib import Path

from .config import ConfigError


def ensure_starter_config(path: str | Path) -> bool:
    """Create the bundled starter only if ``path`` does not already exist.

    Existing files, directories, and symlinks are left alone. The caller decides
    when creation is appropriate; merely importing this module never writes files.
    """
    destination = Path(path)
    if destination.is_symlink():
        # POSIX refuses O_EXCL through a symlink, but Windows follows it and would create the
        # link's target. A symlinked configuration, dangling or not, is the operator's to manage.
        return False
    created_stat = None
    try:
        # Exclusive creation also protects against another process creating the
        # file after the home screen checks whether a project has configuration.
        with destination.open("xb") as stream:
            created_stat = os.fstat(stream.fileno())
            stream.write(files("sia").joinpath("config.toml").read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        return False
    except OSError as exc:
        # Do not leave a truncated starter behind if writing fails. Only remove
        # the same file this invocation created, never an intervening replacement.
        if created_stat is not None:
            try:
                current = destination.lstat()
                if (current.st_dev, current.st_ino) == (created_stat.st_dev, created_stat.st_ino):
                    destination.unlink()
            except OSError:
                pass
        raise ConfigError(
            f"Could not create starter configuration at {destination}: {exc}. "
            "Choose an existing writable project folder or create config.toml yourself."
        ) from exc
    return True


def missing_tenant_fields(path: str | Path) -> tuple[str, ...]:
    """Return tenant fields that still need setup, without validating other settings.

    Invalid TOML or unreadable files raise ConfigError. Incorrect nonempty values
    remain the normal config validator's responsibility.
    """
    destination = Path(path)
    try:
        with destination.open("rb") as stream:
            document = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"Could not read configuration at {destination}: {exc}") from exc
    tenant = document.get("tenant", {})
    if not isinstance(tenant, dict):
        raise ConfigError("[tenant] must be a table with subdomain and identity_url settings")
    return tuple(
        f"tenant.{key}" for key in ("subdomain", "identity_url")
        if key not in tenant or (isinstance(tenant[key], str) and not tenant[key].strip())
    )
