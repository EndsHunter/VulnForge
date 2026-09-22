"""Offline checks for Report finding-row progression badges."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from vulnforge.paths import PROJECT_ROOT

HELPERS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "report_state_badges.js"
TEST_JS = PROJECT_ROOT / "tests" / "js" / "report_state_badges.test.js"
REPORT_JS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "report.js"
APP_JS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "app.js"
CSS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "styles.css"
RUN_HTML = PROJECT_ROOT / "vulnforge" / "ui" / "templates" / "run.html"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_report_state_badges_js():
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


def test_report_rows_use_progression_trail():
    report = REPORT_JS.read_text(encoding="utf-8")
    html = RUN_HTML.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")
    app = APP_JS.read_text(encoding="utf-8")

    assert 'src="/static/report_state_badges.js"' in html
    assert html.index('src="/static/report_state_badges.js"') < html.index(
        'src="/static/report.js"'
    )
    assert "function stateTrailHtml(" in report
    assert 'class="report-state-cell">${stateTrailHtml(f)}' in report
    assert "llm survived" not in report
    assert "wireReportStateTips(" in report
    assert "data-tip=" in report

    assert "Confirmed is human-only" in app
    assert "never auto-confirms" in app
    assert "function stateTip(" in app

    assert ".badge.step-stood" in css
    assert ".report-state-trail" in css
    confirmed_rule = next(
        line for line in css.splitlines() if ".badge.confirmed" in line and "succeeded" in line
    )
    assert "step-stood" not in confirmed_rule
    assert "step-pass" not in confirmed_rule
