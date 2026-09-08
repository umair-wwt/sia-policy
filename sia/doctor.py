"""Read-only local checks. Tenant access is deliberately supplied by the CLI."""
from __future__ import annotations

import importlib.metadata
import os
import sys
from pathlib import Path
from typing import Callable

from .config import ConfigError
from .diagnostics import diagnose, render_diagnostic
from .windows_security import inspect_credential_permissions, windows_acl_supported


def local_checks(args, session, *, load_config: Callable, load_inputs: Callable) -> tuple[list[dict], object | None]:
    checks: list[dict] = []

    def record(name, status, message, exc=None):
        check = {"name": name, "status": status, "message": message}
        if exc is not None:
            check["diagnostic"] = diagnose(exc, stage=name).to_dict()
        checks.append(check)

    record("Python", "passed" if sys.version_info >= (3, 11) else "failed", f"{sys.version.split()[0]} (requires 3.11+)")
    for package in ("requests", "tomlkit", "tzdata", "prompt-toolkit", "rich"):
        try:
            record(package, "passed", importlib.metadata.version(package))
        except importlib.metadata.PackageNotFoundError as exc:
            record(package, "failed", "Missing dependency; run python -m pip install .", exc)
    cfg = None
    try:
        cfg = load_config(args)
        record("Configuration", "passed", str(Path(args.config).resolve()))
    except Exception as exc:
        record("Configuration", "failed", str(exc), exc)
    try:
        env_path = Path(args.env)
        if env_path.exists() and not env_path.is_file():
            raise ConfigError(f"Credentials path {env_path.resolve()} exists but is not a regular file.")
        values, sources = session.values(args.env)
        record("Credentials file", "passed" if env_path.is_file() else "not checked",
               str(env_path.resolve()) + ("" if env_path.is_file() else " (not present; environment/session credentials still supported)"))
        for key in ("SIA_CLIENT_ID", "SIA_CLIENT_SECRET"):
            present = bool(values.get(key))
            record(key, "passed" if present else "warning",
                   f"set ({sources.get(key, 'unknown')})" if present else "missing; configure in sia settings → Credentials (hidden prompts are supported)")
        if cfg is not None and cfg.pvwa.enabled:
            for key in ("PVWA_USER", "PVWA_PASSWORD"):
                present = bool(values.get(key))
                record(key, "passed" if present else "warning", f"set ({sources.get(key)})" if present else "missing; needed for configured PVWA operations")
        if env_path.exists():
            if windows_acl_supported():
                permission = inspect_credential_permissions(env_path)
                record("Credential file permissions", permission.status, permission.message)
            else:
                broad = env_path.stat().st_mode & 0o077
                record("Credential file permissions", "warning" if broad else "passed",
                       "Accessible to other users; restrict file access (chmod 600 on POSIX)." if broad else "Owner-only file access")
    except Exception as exc:
        record("Credentials file", "failed", str(exc), exc)
    if cfg is not None:
        try:
            inputs = load_inputs(cfg, args)
            record("Server input", "passed", f"{len(inputs.servers)} rows, {len(inputs.unique_fqdns)} servers; {Path(args.input).resolve()}")
            for warning in inputs.warnings:
                record("Input warning", "warning", warning)
        except Exception as exc:
            record("Server input", "failed", str(exc), exc)
        if cfg.auth.password_file:
            from .config import load_password_file
            try:
                passwords = load_password_file(cfg.auth.password_file)
                record("Strong-account password file", "passed", f"{len(passwords)} entries; {cfg.auth.password_file}")
            except Exception as exc:
                record("Strong-account password file", "failed", str(exc), exc)
    else:
        record("Server input", "not checked", "Fix configuration first so naming conventions can be applied.")
    for label, value in (("Reports path", args.report_dir), ("Input path", args.input)):
        path = Path(value).resolve()
        if path.exists() and not path.is_dir():
            record(label, "failed", f"{path} is a file; this location must be a directory.")
            continue
        ancestor = path
        while not ancestor.exists() and ancestor.parent != ancestor:
            ancestor = ancestor.parent
        if not ancestor.is_dir():
            record(label, "failed", f"{ancestor} is a file, so the directory {path} cannot be created.")
            continue
        writable = os.access(ancestor, os.W_OK)
        record(label, "passed" if writable else "warning", f"{path}; {'writable parent found' if writable else 'parent is not writable'} (no files written)")
    record("Server connection", "not checked", "API checks cannot prove RDP/SSH login or connector-to-target access. Run sia help connect for the checks to perform.")
    return checks, cfg


def print_checks(checks: list[dict], *, out, verbose: bool = False) -> None:
    for check in checks:
        print(f"[{check['status'].upper()}] {check['name']}: {check['message']}", file=out)
        if check.get("diagnostic"):
            from .diagnostics import Diagnostic
            render_diagnostic(Diagnostic(**check["diagnostic"]), out, verbose=verbose)
