import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sia import redact  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_redaction_registry():
    redact._reset_for_tests()
    yield
    redact._reset_for_tests()
