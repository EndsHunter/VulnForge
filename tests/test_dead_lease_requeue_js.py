"""Offline check: dead-lease reclaim is a queue note, not a task error."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEST_JS = ROOT / "tests" / "js" / "dead_lease_requeue.test.js"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_dead_lease_requeue_js():
    assert TEST_JS.is_file(), f"missing {TEST_JS}"
    proc = subprocess.run(
        ["node", "--test", str(TEST_JS)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, (
        f"node --test failed (rc={proc.returncode})\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
