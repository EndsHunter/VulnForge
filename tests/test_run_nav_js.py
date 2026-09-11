"""Shell out to node --test for run rail nav table (offline)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from vulnforge.paths import PROJECT_ROOT

HELPERS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "run_nav.js"
TEST_JS = PROJECT_ROOT / "tests" / "js" / "run_nav.test.js"
HOME_HTML = PROJECT_ROOT / "vulnforge" / "ui" / "templates" / "index.html"
HOME_JS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "app.js"
RUN_HTML = PROJECT_ROOT / "vulnforge" / "ui" / "templates" / "run.html"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_run_nav_js():
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


def test_home_html_is_the_list():
    html = HOME_HTML.read_text(encoding="utf-8")
    js = HOME_JS.read_text(encoding="utf-8")
    assert 'id="btn-open-ai-chat"' not in html
    assert "home-cta-row" not in html
    for html_id in (
        "btn-settings",
        "btn-open-dev",
        "btn-open-tool-gaps",
        "home-search",
        "btn-new-run",
        "run-list",
    ):
        assert f'id="{html_id}"' in html
    assert 'class="run-row"' in js
    assert "No runs match." in js
    assert "No runs yet. Start a new audit" in js


def test_run_html_icon_rail_chrome():
    html = RUN_HTML.read_text(encoding="utf-8")
    assert 'data-run-rail' in html
    assert 'id="run-switch"' in html
    assert 'id="trust-line"' not in html
    assert 'href="/" title="Home"' not in html
    for mode in ("mission", "hunts", "explorer", "report", "evidence", "audit", "ai"):
        assert f'data-mode-panel="{mode}"' in html
    assert 'id="btn-start"' in html
    assert 'id="btn-refresh"' in html
    assert 'id="operator-chat-root"' in html
