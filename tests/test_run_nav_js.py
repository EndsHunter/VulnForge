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
    assert 'id="ai-fab"' in html
    assert 'id="ai-sheet"' in html
    assert "home-cta-row" not in html
    for html_id in (
        "btn-settings",
        "btn-open-dev",
        "btn-open-benchmarks",
        "btn-open-tool-gaps",
        "home-search",
        "btn-new-run",
        "run-list",
        "home-attention",
    ):
        assert f'id="{html_id}"' in html
    # Operator tools live in the header ⋯ menu, not a bottom dock.
    assert "home-dock" not in html
    assert html.index('id="btn-settings"') > html.index('class="danger-menu')
    assert "/static/shell.css" in html
    assert "/static/pages/home.css" in html
    # Helpers must load before app.js renders the list.
    assert html.index("/static/pages/home.js") < html.index("/static/app.js")
    assert 'class="run-row"' in js
    assert "No runs match." in js
    assert "No runs yet. Start a new audit" in js


def test_run_html_header_tabs_chrome():
    html = RUN_HTML.read_text(encoding="utf-8")
    assert "data-run-tabs" in html
    assert "data-run-rail" not in html
    assert 'id="run-switch"' in html
    assert 'id="run-pipeline-strip"' in html
    assert 'id="btn-command"' in html
    assert 'id="trust-line"' not in html
    assert 'href="/" title="Home"' not in html
    for mode in ("hunts", "explorer", "report", "evidence", "audit", "ai"):
        assert f'data-mode-panel="{mode}"' in html
    assert 'data-mode-panel="mission"' not in html
    for page in ("review", "campaign", "atlas"):
        assert f"<!-- BEGIN page:{page}" in html
        assert f"<!-- END page:{page} -->" in html
        assert f'id="page-{page}"' in html
        assert f"/static/pages/{page}.js" in html
    assert 'id="btn-start"' in html
    assert 'id="btn-refresh"' in html
    assert 'id="operator-chat-root"' in html
    assert 'id="ai-fab"' in html
    assert 'id="ai-sheet"' in html
    assert html.index('id="ai-sheet"') < html.index('id="operator-chat-root"')


def test_mission_hash_resolves_to_campaign():
    modes = (PROJECT_ROOT / "vulnforge" / "ui" / "static" / "modes.js").read_text(
        encoding="utf-8"
    )
    app = HOME_JS.read_text(encoding="utf-8")
    report = (PROJECT_ROOT / "vulnforge" / "ui" / "static" / "report.js").read_text(
        encoding="utf-8"
    )
    assert 'mode === "mission"' in modes
    assert 'return { mode: "hunts", tab: "hunts" };' in modes
    assert 'setMode("mission", "overview")' not in modes
    assert 'setMode?.("mission", "overview")' not in app
    assert 'setMode?.("mission", "overview")' not in report
    assert 'new CustomEvent("vf:snapshot"' in app
