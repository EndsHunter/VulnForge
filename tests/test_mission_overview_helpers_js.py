"""Shell out to node --test for Mission Overview pure JS helpers (offline)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from vulnforge.paths import PROJECT_ROOT

HELPERS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "mission_overview_helpers.js"
TEST_JS = PROJECT_ROOT / "tests" / "js" / "mission_overview_helpers.test.js"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_mission_overview_helpers_js():
    assert HELPERS.is_file(), f"missing {HELPERS}"
    assert TEST_JS.is_file(), f"missing {TEST_JS}"
    proc = subprocess.run(
        ["node", "--test", str(TEST_JS)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, (
        f"node --test failed (rc={proc.returncode})\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
