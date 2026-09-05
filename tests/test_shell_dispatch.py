"""Shell commands keep their CLI semantics without ending the home session."""
from __future__ import annotations

import importlib.metadata
import json

import pytest

import sia_onboard
from sia import doctor, terminal
from sia.runtime import Session


def tty(monkeypatch):
    monkeypatch.setattr(sia_onboard.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sia_onboard.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(sia_onboard, "Context", lambda cfg: pytest.fail("Shell dispatch authenticated"))


def test_child_help_returns_to_home_and_another_command_runs(monkeypatch, capsys):
    tty(monkeypatch)
    completed = []

    def home(args, session, run):
        completed.append(run(["plan", "--help"]))
        completed.append(run(["help", "settings"]))
        return 0

    monkeypatch.setattr(terminal, "home", home)
    assert sia_onboard.main(["shell"]) == 0
    assert completed == [0, 0]
    output = capsys.readouterr().out
    assert "--server" in output and "--set-policy-status" in output
    assert "Settings" in output


def test_explicit_child_flags_and_project_paths_are_forwarded(monkeypatch, tmp_path):
    tty(monkeypatch)
    original_execute = sia_onboard.execute
    session = Session(shell_env={})
    seen = []

    def capture(child, child_session):
        seen.append(child)
        assert child_session is session
        return 7

    def home(args, current_session, run):
        assert run(["plan", "--server", "web01.example.com", "--server", "web02.example.com",
                    "--group", "RDP Operators", "--workers", "3", "--only", "policies",
                    "--update", "--set-policy-status", "Suspended", "--input", "another input",
                    "--config", "override.toml", "--json"]) == 7
        return 0

    monkeypatch.setattr(terminal, "home", home)
    monkeypatch.setattr(sia_onboard, "execute", capture)
    args = sia_onboard.build_parser().parse_args([
        "shell", "--config", str(tmp_path / "config.toml"), "--env", str(tmp_path / ".env"),
        "--report-dir", str(tmp_path / "reports"), "--ca-bundle", str(tmp_path / "ca.pem"), "--verbose",
    ])
    assert original_execute(args, session) == 0
    child = seen[0]
    assert child.command == "plan" and child.config == "override.toml"
    assert child.env == str(tmp_path / ".env")
    assert child.report_dir == str(tmp_path / "reports")
    assert child.ca_bundle == str(tmp_path / "ca.pem") and child.verbose
    assert child.server == ["web01.example.com", "web02.example.com"]
    assert child.group == ["RDP Operators"] and child.workers == 3
    assert child.only == "policies" and child.update and child.set_policy_status == "Suspended"
    assert child.input == "another input" and child.json


def test_child_parse_failure_is_recoverable_within_home(monkeypatch, capsys):
    tty(monkeypatch)
    completed = []

    def home(args, session, run):
        completed.append(run(["plan", "--workers", "wrong"]))
        completed.append(run(["help", "settings"]))
        return 0

    monkeypatch.setattr(terminal, "home", home)
    assert sia_onboard.main(["shell"]) == 0
    assert completed == [2, 0]
    assert "--workers" in capsys.readouterr().err


def test_doctor_checks_terminal_dependencies_without_tenant_access(monkeypatch, tmp_path, capsys):
    checked = []

    def version(package):
        checked.append(package)
        if package == "rich":
            raise importlib.metadata.PackageNotFoundError(package)
        return "test-version"

    monkeypatch.setattr(doctor.importlib.metadata, "version", version)
    monkeypatch.setattr(sia_onboard, "Context", lambda cfg: pytest.fail("Offline doctor authenticated"))
    assert sia_onboard.main(["doctor", "--json", "--config", str(tmp_path / "missing.toml"),
                             "--env", str(tmp_path / "missing.env")]) == 1
    checks = json.loads(capsys.readouterr().out)["checks"]
    assert {"prompt-toolkit", "rich"} <= set(checked)
    assert next(check for check in checks if check["name"] == "prompt-toolkit")["status"] == "passed"
    failed = next(check for check in checks if check["name"] == "rich")
    assert failed["status"] == "failed" and "pip install" in failed["message"]
