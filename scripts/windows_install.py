#!/usr/bin/env python
"""Install SIA into an isolated Windows runtime without activating a venv.

This file intentionally uses Python 3.7-compatible syntax so a CMD fallback can
explain that an older Python is unsupported instead of failing to parse.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Optional, Tuple
import uuid


MIN_PYTHON = (3, 11)
POINTER_NAME = ".sia-python.path"
METADATA_NAME = ".sia-install.json"
REQUIRED_IMPORTS = ("requests", "tomlkit", "tzdata", "prompt_toolkit", "rich", "sia", "sia_onboard")


class InstallError(RuntimeError):
    pass


def project_root() -> Path:
    root = Path(__file__).resolve().parent.parent
    if not (root / "pyproject.toml").is_file() or not (root / "sia_onboard.py").is_file():
        raise InstallError("The installer is incomplete. Extract the entire project folder and run install.cmd again.")
    return root


def python_in(env: Path) -> Path:
    return env / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _run(command, *, cwd=None, timeout=300, check=True):
    try:
        completed = subprocess.run(
            [str(part) for part in command],
            cwd=str(cwd) if cwd else None,
            stdin=subprocess.DEVNULL,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError("Could not run {0}: {1}".format(command[0], exc)) from exc
    if check and completed.returncode != 0:
        detail = (completed.stdout or "").strip()
        if len(detail) > 2500:
            detail = detail[-2500:]
        raise InstallError(
            "Command failed ({0}): {1}{2}".format(
                completed.returncode,
                " ".join(str(part) for part in command[:4]),
                "\n" + detail if detail else "",
            )
        )
    return completed


def compatible_python(executable: Path) -> bool:
    result = _run(
        [
            executable,
            "-c",
            "import sys, venv, ensurepip; raise SystemExit(0 if sys.version_info >= (3, 11) else 7)",
        ],
        timeout=20,
        check=False,
    )
    return result.returncode == 0


def source_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    paths = [
        root / "pyproject.toml",
        root / "requirements.txt",
        root / "sia_onboard.py",
        root / "sia" / "config.toml",
    ]
    paths.extend(sorted((root / "sia").glob("*.py")))
    for path in paths:
        if not path.is_file():
            continue
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _metadata_matches(env: Path, root: Path, fingerprint: str) -> bool:
    try:
        data = json.loads((env / METADATA_NAME).read_text(encoding="utf-8"))
        recorded_root = Path(data["project_root"]).resolve()
    except (OSError, ValueError, KeyError, TypeError):
        return False
    return recorded_root == root.resolve() and data.get("source_fingerprint") == fingerprint


def validate_environment(env: Path, root: Path, fingerprint: str) -> bool:
    python = python_in(env)
    if not python.is_file():
        return False
    try:
        if not compatible_python(python):
            return False
        imports = ";".join("import " + name for name in REQUIRED_IMPORTS)
        if _run([python, "-c", imports], timeout=30, check=False).returncode != 0:
            return False
        # Run outside the source root so this proves the installed copy starts.
        if _run([python, "-m", "sia.bootstrap", "--help"], cwd=env, timeout=30, check=False).returncode != 0:
            return False
        return _metadata_matches(env, root, fingerprint)
    except InstallError:
        return False


def _project_is_local(root: Path) -> bool:
    if os.name != "nt":
        return True
    text = str(root)
    if text.startswith("\\\\"):
        return False
    try:
        import ctypes

        drive = root.drive + "\\"
        if drive and ctypes.windll.kernel32.GetDriveTypeW(drive) == 4:  # DRIVE_REMOTE
            return False
    except (AttributeError, OSError):
        pass
    return True


def _directory_writable(root: Path) -> bool:
    try:
        fd, name = tempfile.mkstemp(prefix=".sia-write-test-", dir=str(root))
        os.close(fd)
        os.unlink(name)
        return True
    except OSError:
        return False


def _runtime_directory_writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    return _directory_writable(path)


def _user_runtime(root: Path) -> Path:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise InstallError(
            "The project runtime folder is unavailable and LOCALAPPDATA is not set. "
            "Move the extracted folder to a writable local folder and run install.cmd again."
        )
    key = hashlib.sha256(str(root.resolve()).casefold().encode("utf-8")).hexdigest()[:16]
    runtime = Path(local) / "SIA Policy" / "projects" / key
    if not _runtime_directory_writable(runtime):
        raise InstallError(
            "Windows could not create the SIA runtime in either the project folder or LOCALAPPDATA. "
            "Check folder permissions or ask IT to allow the per-user application folder."
        )
    return runtime


def runtime_root(root: Path) -> Path:
    if not _directory_writable(root):
        raise InstallError(
            "The project folder is read-only. Copy the entire extracted folder to a writable local folder "
            "such as Documents, then run install.cmd there."
        )
    project_runtime = root / ".sia-runtime"
    if _project_is_local(root) and _runtime_directory_writable(project_runtime):
        return project_runtime
    return _user_runtime(root)


def pointer_path(root: Path, runtime: Path) -> Path:
    del runtime  # Kept in the signature to make the project-pointer contract explicit.
    if not _directory_writable(root):
        raise InstallError("The project folder became read-only before the runtime could be selected.")
    return root / POINTER_NAME


def read_pointer(path: Path) -> Optional[Path]:
    try:
        value = path.read_text(encoding="utf-8-sig").strip()
    except (OSError, UnicodeError):
        return None
    return Path(value).parent.parent if value else None


def _absolute(path: Path) -> Path:
    """Make a path absolute without dereferencing a venv's Python symlink."""
    return Path(os.path.abspath(str(path)))


def _pointer_reference_state(path: Path, python: Path) -> Optional[bool]:
    try:
        value = path.read_text(encoding="utf-8-sig").strip()
    except FileNotFoundError:
        return False
    except OSError:
        return None
    except UnicodeError:
        return False
    if not value:
        return False
    return os.path.normcase(os.path.abspath(value)) == os.path.normcase(str(_absolute(python)))


def pointer_references(path: Path, python: Path) -> bool:
    return _pointer_reference_state(path, python) is True


def atomic_write_pointer(path: Path, python: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex[:8])
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(str(_absolute(python)) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary), str(path))
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass


def _prune_superseded_environments(runtime: Path, keep: Path) -> None:
    """Remove runtime environments the pointer no longer references (best effort; never the selected one)."""
    try:
        candidates = list((runtime / "envs").iterdir())
    except OSError:
        return
    selected = os.path.normcase(str(_absolute(keep)))
    for candidate in candidates:
        if candidate.is_dir() and os.path.normcase(str(_absolute(candidate))) != selected:
            shutil.rmtree(str(candidate), ignore_errors=True)


def _new_environment_path(runtime: Path) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return runtime / "envs" / (stamp + "-" + uuid.uuid4().hex[:8])


def _create_venv(base_python: Path, env: Path) -> None:
    def attempt(command, timeout):
        try:
            return _run(command, timeout=timeout, check=False)
        except InstallError:
            return None

    env.parent.mkdir(parents=True, exist_ok=True)
    first_output = ""
    try:
        first = _run([base_python, "-m", "venv", str(env)], timeout=180, check=False)
        first_output = first.stdout or ""
    except InstallError as exc:
        first = None
        first_output = str(exc)
    if first is not None and first.returncode == 0 and python_in(env).is_file():
        pip_check = attempt([python_in(env), "-m", "pip", "--version"], 30)
        if pip_check is not None and pip_check.returncode == 0:
            return
        for ensure_args in (("--upgrade",), ("--default-pip",)):
            result = attempt([python_in(env), "-m", "ensurepip"] + list(ensure_args), 180)
            pip_check = attempt([python_in(env), "-m", "pip", "--version"], 30)
            if result is not None and result.returncode == 0 and pip_check is not None and pip_check.returncode == 0:
                return
        raise InstallError("The isolated environment was created, but Python could not initialize pip.")
    shutil.rmtree(env, ignore_errors=True)
    try:
        fallback = _run([base_python, "-m", "venv", "--without-pip", str(env)], timeout=180, check=False)
    except InstallError as exc:
        raise InstallError("Python could not create the isolated SIA environment.\n" + first_output + "\n" + str(exc)) from exc
    if fallback.returncode != 0 or not python_in(env).is_file():
        detail = (fallback.stdout or first_output or "").strip()
        raise InstallError("Python could not create the isolated SIA environment.\n" + detail)
    last = None
    for ensure_args in (("--upgrade",), ("--default-pip",)):
        last = attempt([python_in(env), "-m", "ensurepip"] + list(ensure_args), 180)
        pip_check = attempt([python_in(env), "-m", "pip", "--version"], 30)
        if last is not None and last.returncode == 0 and pip_check is not None and pip_check.returncode == 0:
            return
    detail = ((last.stdout if last else "") or "").strip()
    raise InstallError("Python created the environment but could not initialize pip.\n" + detail)


def _wheelhouse(root: Path) -> Optional[Path]:
    for candidate in (root / "wheelhouse", root / "wheels"):
        if candidate.is_dir() and any(candidate.glob("*.whl")):
            return candidate
    return None


def _install_project(env: Path, root: Path) -> None:
    python = python_in(env)
    common = [
        python,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-input",
        "--retries",
        "2",
        "--timeout",
        "25",
    ]
    wheelhouse = _wheelhouse(root)
    attempts = []
    # A TLS-inspecting proxy (Netskope, Zscaler, and similar) re-signs PyPI, and pip verifies against
    # its own bundled CA list rather than the Windows certificate store that already holds the
    # corporate root. The download then fails before truststore can ever be installed, so every
    # network attempt is retried asking pip to use this computer's certificate store instead.
    # --use-feature=truststore needs pip 22.2+, which every Python this installer accepts bundles.
    if wheelhouse:
        attempts.append(common + ["--no-index", "--find-links", wheelhouse, root])
        attempts.append(common + ["--find-links", wheelhouse, root])
        attempts.append(common + ["--find-links", wheelhouse, "--use-feature=truststore", root])
    else:
        attempts.append(common + [root])
        attempts.append(common + ["--use-feature=truststore", root])
    failures = []
    for command in attempts:
        try:
            last = _run(command, cwd=root, timeout=600, check=False)
        except InstallError as exc:
            failures.append(str(exc))
            continue
        if last.returncode == 0:
            return
        failures.append((last.stdout or "").strip())
    detail = "\n\n".join(part for part in failures[-2:] if part).strip()
    if len(detail) > 3500:
        detail = detail[-3500:]
    raise InstallError(
        "SIA's Python packages could not be installed. Check the internet connection or add a complete "
        "wheelhouse folder beside install.cmd, then run it again.\n"
        "If the message above mentions a certificate (CERTIFICATE_VERIFY_FAILED or 'self signed "
        "certificate in certificate chain'), the network re-signs HTTPS and pip does not trust the "
        "re-signing root. Ask IT for the proxy root CA as a .pem file and run:\n"
        "    py -m pip install --cert C:\\path\\to\\corp-root.pem .\n" + detail
    )


def _write_metadata(env: Path, root: Path, fingerprint: str) -> None:
    payload = {
        "format": 1,
        "project_root": str(root.resolve()),
        "source_fingerprint": fingerprint,
        "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": str(_absolute(python_in(env))),
    }
    path = env / METADATA_NAME
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def select_existing(root: Path, runtime: Path, fingerprint: str) -> Optional[Path]:
    candidates = []
    for pointer in (root / POINTER_NAME, runtime / POINTER_NAME):
        env = read_pointer(pointer)
        if env and env not in candidates:
            candidates.append(env)
    project_venv = root / ".venv"
    if project_venv not in candidates:
        candidates.append(project_venv)
    for env in candidates:
        if validate_environment(env, root, fingerprint):
            return env
    return None


def check_current(root: Path) -> bool:
    """Return whether the project pointer names a complete current runtime."""
    env = read_pointer(root / POINTER_NAME)
    if env is None:
        return False
    return validate_environment(env, root, source_fingerprint(root))


def install(base_python: Path, root: Path) -> Tuple[Path, Path, bool]:
    if not compatible_python(base_python):
        raise InstallError(
            "Python 3.11 or newer is required. Run install.cmd so it can find or install a supported version."
        )
    fingerprint = source_fingerprint(root)
    runtime = runtime_root(root)
    pointer = pointer_path(root, runtime)
    print("Checking for a reusable SIA runtime...", flush=True)
    existing = select_existing(root, runtime, fingerprint)
    if existing:
        if source_fingerprint(root) != fingerprint:
            raise InstallError("Project files changed while the existing runtime was checked. Run install.cmd again.")
        print("Using the verified existing SIA runtime...", flush=True)
        atomic_write_pointer(pointer, python_in(existing))
        _prune_superseded_environments(runtime, existing)
        return python_in(existing), pointer, True

    env = _new_environment_path(runtime)
    publication_attempted = False
    try:
        print("Creating an isolated SIA runtime...", flush=True)
        _create_venv(base_python, env)
        print("Installing SIA and its required packages...", flush=True)
        _install_project(env, root)
        _write_metadata(env, root, fingerprint)
        print("Running offline startup checks...", flush=True)
        if not validate_environment(env, root, fingerprint):
            raise InstallError("The new SIA environment did not pass its offline startup checks.")
        if source_fingerprint(root) != fingerprint:
            raise InstallError("Project files changed during installation. Run install.cmd again after the copy or update finishes.")
        print("Selecting the verified runtime...", flush=True)
        publication_attempted = True
        atomic_write_pointer(pointer, python_in(env))
        # Every source change builds a new environment; once this one is selected the earlier ones are only disk use.
        _prune_superseded_environments(runtime, env)
    except BaseException:
        # os.replace is atomic, but a signal can arrive immediately after it.
        # Never remove an environment once the durable pointer references it.
        reference_state = _pointer_reference_state(pointer, python_in(env))
        if reference_state is False or (reference_state is None and not publication_attempted):
            shutil.rmtree(env, ignore_errors=True)
        raise
    return python_in(env), pointer, False


def launch(python: Path, root: Path) -> int:
    command = [
        python,
        "-m",
        "sia.bootstrap",
        "--config",
        root / "config.toml",
        "--env",
        root / ".env",
        "--report-dir",
        root / "reports",
        "shell",
        "--input",
        root / "input",
    ]
    try:
        return subprocess.call([str(part) for part in command], cwd=str(root))
    except OSError as exc:
        raise InstallError("SIA was installed but could not be started: {0}".format(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Install and validate the local SIA application runtime.")
    parser.add_argument("--python", dest="python_executable", default=sys.executable,
                        help="compatible base Python selected by install.ps1")
    parser.add_argument("--no-launch", action="store_true", help="install and validate without opening SIA")
    parser.add_argument("--check", action="store_true", help="return success only when the project pointer is current")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = project_root()
        if args.check:
            if check_current(root):
                print("The current SIA runtime is healthy.")
                return 0
            print("The SIA runtime needs installation or repair.", file=sys.stderr)
            return 1
        selected, pointer, reused = install(Path(args.python_executable).resolve(), root)
        print("SIA is ready ({0}).".format("existing environment verified" if reused else "new environment installed"))
        print("Runtime: " + str(selected))
        print("Pointer: " + str(pointer))
        if args.no_launch:
            print("Run Start-SIA.cmd to open SIA.")
            return 0
        return launch(selected, root)
    except KeyboardInterrupt:
        print(
            "\nInstallation cancelled. Configuration and data were preserved; rerun install.cmd safely to verify or finish setup.",
            file=sys.stderr,
        )
        return 130
    except (InstallError, OSError, UnicodeError) as exc:
        print("Installation could not finish: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
