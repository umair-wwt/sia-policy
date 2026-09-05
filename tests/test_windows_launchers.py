"""Native cmd.exe smoke tests for the double-click Windows entry points.

These tests never install Python or packages.  They copy the real batch files
into an isolated project, point them at the Python already running pytest, and
replace the Python backend/application with small logging stubs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


pytestmark = pytest.mark.skipif(os.name != "nt", reason="requires native cmd.exe")

SOURCE_ROOT = Path(__file__).resolve().parents[1]


INSTALLER_STUB = r'''from __future__ import annotations
import json
import os
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
log = Path(os.environ["SIA_TEST_LOG"])
checking = "--check" in sys.argv[1:]
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"kind": "health" if checking else "backend", "argv": sys.argv[1:],
                             "executable": sys.executable, "cwd": os.getcwd(),
                             "automatic_install": os.environ.get("PYTHON_MANAGER_AUTOMATIC_INSTALL"),
                             "launcher_install": os.environ.get("PYLAUNCHER_ALLOW_INSTALL")}) + "\n")
if checking:
    configured = os.environ.get("SIA_TEST_HEALTH_EXIT", "")
    raise SystemExit(int(configured) if configured else
                     (1 if (root / ".sia-test-unhealthy").exists() else 0))
exit_code = int(os.environ.get("SIA_TEST_BACKEND_EXIT", "0"))
if exit_code == 0:
    (root / ".sia-python.path").write_text(sys.executable + "\n", encoding="utf-8")
    (root / ".sia-test-unhealthy").unlink(missing_ok=True)
raise SystemExit(exit_code)
'''


APP_STUB = r'''from __future__ import annotations
import json
import os
from pathlib import Path
import sys

if __name__ == "__main__":
    with Path(os.environ["SIA_TEST_LOG"]).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"kind": "app", "argv": sys.argv[1:],
                                 "executable": sys.executable, "cwd": os.getcwd()}) + "\n")
    raise SystemExit(int(os.environ.get("SIA_TEST_APP_EXIT", "0")))
'''


def isolated_project(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    # CMD quoting must survive ordinary enterprise folder names, non-ASCII
    # text, percent signs, and command operator characters.
    root = tmp_path / "SIA setup & café 100% ready"
    scripts = root / "scripts"
    package = root / "sia"
    scripts.mkdir(parents=True)
    package.mkdir()
    shutil.copy2(SOURCE_ROOT / "install.cmd", root / "install.cmd")
    shutil.copy2(SOURCE_ROOT / "Start-SIA.cmd", root / "Start-SIA.cmd")
    (scripts / "windows_install.py").write_text(INSTALLER_STUB, encoding="utf-8")
    (root / "sia_onboard.py").write_text("VALUE = 1\n", encoding="utf-8")
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "bootstrap.py").write_text(APP_STUB, encoding="utf-8")
    (root / ".sia-python.path").write_text(str(Path(sys.executable).resolve()) + "\n", encoding="utf-8")
    log = root / "launcher events.jsonl"
    environment = os.environ.copy()
    environment.update({
        "SIA_INSTALL_SKIP_POWERSHELL": "1",
        "SIA_TEST_LOG": str(log),
        "SIA_TEST_BACKEND_EXIT": "0",
        "SIA_TEST_HEALTH_EXIT": "",
        "SIA_TEST_APP_EXIT": "0",
    })
    return root, log, environment


def run_cmd(root: Path, launcher: str, *arguments: str, environment: dict[str, str]):
    command_processor = os.environ.get("ComSpec", r"C:\Windows\System32\cmd.exe")
    return subprocess.run(
        [command_processor, "/d", "/c", launcher, *arguments],
        cwd=root,
        env=environment,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=30,
        check=False,
    )


def events(log: Path) -> list[dict]:
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def test_install_cmd_forced_python_fallback_needs_no_launch_or_network(tmp_path):
    root, log, environment = isolated_project(tmp_path)
    environment["PYTHON_MANAGER_AUTOMATIC_INSTALL"] = "true"
    environment["PYLAUNCHER_ALLOW_INSTALL"] = "1"

    result = run_cmd(
        root, "install.cmd", "--no-launch", "--no-bootstrap", environment=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert [event["kind"] for event in events(log)] == ["backend"]
    assert events(log)[0]["argv"] == ["--no-launch"]
    assert events(log)[0]["automatic_install"] == "false"
    assert not events(log)[0]["launcher_install"]
    assert Path(events(log)[0]["executable"]).resolve() == Path(sys.executable).resolve()
    assert Path(events(log)[0]["cwd"]).resolve() == root.resolve()
    assert "Trying the Python installer route automatically" in result.stdout
    assert "SIA is ready" in result.stdout


def test_start_cmd_check_uses_verified_marker_without_repair(tmp_path):
    root, log, environment = isolated_project(tmp_path)

    result = run_cmd(root, "Start-SIA.cmd", "--help", environment=environment)

    assert result.returncode == 0, result.stdout + result.stderr
    assert [event["kind"] for event in events(log)] == ["health", "app"]
    assert events(log)[0]["argv"] == ["--check"]
    assert events(log)[-1]["argv"] == ["--help"]
    assert all(Path(event["cwd"]).resolve() == root.resolve() for event in events(log))
    assert "repairing" not in result.stdout.lower()


def test_start_cmd_repairs_once_then_rechecks_and_launches(tmp_path):
    root, log, environment = isolated_project(tmp_path)
    (root / ".sia-test-unhealthy").write_text("force one failed health check\n", encoding="utf-8")

    result = run_cmd(root, "Start-SIA.cmd", "--help", environment=environment)

    assert result.returncode == 0, result.stdout + result.stderr
    assert [event["kind"] for event in events(log)] == ["health", "backend", "health", "app"]
    assert events(log)[-1]["argv"] == ["--help"]
    assert result.stdout.lower().count("repairing the sia app automatically") == 1


def test_start_cmd_cancelled_health_check_returns_130_without_repair(tmp_path):
    root, log, environment = isolated_project(tmp_path)
    environment["SIA_TEST_HEALTH_EXIT"] = "130"

    result = run_cmd(root, "Start-SIA.cmd", "--help", environment=environment)

    assert result.returncode == 130, result.stdout + result.stderr
    assert [event["kind"] for event in events(log)] == ["health"]
    assert "repairing" not in result.stdout.lower()


def test_start_cmd_cancelled_auto_repair_returns_130_without_retry(tmp_path):
    root, log, environment = isolated_project(tmp_path)
    environment["SIA_TEST_HEALTH_EXIT"] = "1"
    environment["SIA_TEST_BACKEND_EXIT"] = "130"

    result = run_cmd(root, "Start-SIA.cmd", "--help", environment=environment)

    assert result.returncode == 130, result.stdout + result.stderr
    assert [event["kind"] for event in events(log)] == ["health", "backend"]
    assert result.stdout.lower().count("repairing the sia app automatically") == 1


def test_start_cmd_stops_after_one_repair_when_final_check_is_still_unhealthy(tmp_path):
    root, log, environment = isolated_project(tmp_path)
    environment["SIA_TEST_HEALTH_EXIT"] = "1"

    result = run_cmd(root, "Start-SIA.cmd", "--help", environment=environment)

    assert result.returncode == 1, result.stdout + result.stderr
    assert [event["kind"] for event in events(log)] == ["health", "backend", "health"]
    assert result.stdout.lower().count("repairing the sia app automatically") == 1


@pytest.mark.parametrize("backend_exit", [17, 130], ids=["failure", "cancelled"])
def test_install_cmd_does_not_retry_failed_or_cancelled_backend(tmp_path, backend_exit):
    root, log, environment = isolated_project(tmp_path)
    environment["SIA_TEST_BACKEND_EXIT"] = str(backend_exit)

    result = run_cmd(
        root, "install.cmd", "--no-launch", "--no-bootstrap", environment=environment,
    )

    assert result.returncode == backend_exit, result.stdout + result.stderr
    assert [event["kind"] for event in events(log)] == ["backend"]
    assert "SIA is ready" not in result.stdout


@pytest.mark.parametrize("app_exit", [9, 130], ids=["failure", "cancelled"])
def test_start_cmd_does_not_repair_after_application_failure_or_cancel(tmp_path, app_exit):
    root, log, environment = isolated_project(tmp_path)
    environment["SIA_TEST_APP_EXIT"] = str(app_exit)

    result = run_cmd(root, "Start-SIA.cmd", "--help", environment=environment)

    assert result.returncode == app_exit, result.stdout + result.stderr
    assert [event["kind"] for event in events(log)] == ["health", "app"]
    assert "repairing" not in result.stdout.lower()
