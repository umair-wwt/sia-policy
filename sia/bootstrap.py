"""Small entry point that can explain an incomplete installation."""
from __future__ import annotations

import json
import sys


def main() -> int:
    problem = ""
    if sys.version_info < (3, 11):
        problem = "SIA needs Python 3.11 or newer. Install a supported Python and recreate the virtual environment."
    if not problem:
        try:
            from sia_onboard import main as run
        except ImportError as exc:
            component = exc.name or "an installed dependency"
            problem = f"A required package could not be loaded: {component}. In the project folder run: python -m pip install ."
        else:
            return run()
    print(f"Setup problem: {problem}", file=sys.stderr)
    if "--json" in sys.argv:
        print(json.dumps({"ok": False, "exit_code": 2, "diagnostics": [{"code": "SIA-DEPENDENCY", "message": problem}]}))
    return 2


if __name__ == "__main__":
    sys.exit(main())
