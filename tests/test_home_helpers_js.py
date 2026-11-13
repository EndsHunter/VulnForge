"""Shell out to node --test for Home run-list helpers (offline)."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from vulnforge.paths import PROJECT_ROOT

TEST_JS = PROJECT_ROOT / "tests" / "js" / "home_helpers.test.js"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_home_helpers_js():
    proc = subprocess.run(
        ["node", "--test", str(TEST_JS)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
