import builtins
import json
from pathlib import Path
import subprocess
import sys

import pytest

from sia import bootstrap


@pytest.mark.parametrize("problem", [ModuleNotFoundError("absent", name="requests"),
                                    ImportError("incompatible dependency", name="requests"),
                                    ImportError("incompatible dependency")])
def test_bootstrap_explains_missing_and_incompatible_packages(monkeypatch, capsys, problem):
    original = builtins.__import__

    def broken_import(name, *args, **kwargs):
        if name == "sia_onboard":
            raise problem
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", broken_import)
    monkeypatch.setattr(sys, "argv", ["sia", "doctor", "--json"])
    assert bootstrap.main() == 2
    output = capsys.readouterr()
    assert "pip install ." in output.err and "Traceback" not in output.err
    assert json.loads(output.out)["diagnostics"][0]["code"] == "SIA-DEPENDENCY"


@pytest.mark.parametrize("package", ["requests", "tomlkit"])
def test_direct_script_reports_incompatible_dependency_as_json(package):
    root = Path(__file__).resolve().parents[1]
    # Inject a broken installed package in a separate process, so this exercises
    # the actual __main__ guard without disturbing the test runner's imports.
    script = f"""
import builtins
import runpy
import sys

original = builtins.__import__
def broken_import(name, *args, **kwargs):
    if name == {package!r}:
        raise ImportError('incompatible installed dependency', name=name)
    return original(name, *args, **kwargs)
builtins.__import__ = broken_import
sys.argv = ['sia_onboard.py', 'doctor', '--json']
runpy.run_path('sia_onboard.py', run_name='__main__')
"""
    result = subprocess.run([sys.executable, "-c", script], cwd=root, capture_output=True, text=True, timeout=15)
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["exit_code"] == 2 and payload["ok"] is False
    assert payload["diagnostics"][0]["code"] == "SIA-DEPENDENCY"
    assert package in payload["diagnostics"][0]["message"]
    assert "pip install ." in result.stderr and "Traceback" not in result.stderr
