import builtins
import json
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
