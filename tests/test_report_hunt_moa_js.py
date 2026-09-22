"""Offline checks for Report/Mission hunt MoA provenance chrome."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from vulnforge.paths import PROJECT_ROOT

HELPERS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "report_hunt_moa.js"
TEST_JS = PROJECT_ROOT / "tests" / "js" / "report_hunt_moa.test.js"
REPORT_JS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "report.js"
COVERAGE_JS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "coverage.js"
CSS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "styles.css"
RUN_HTML = PROJECT_ROOT / "vulnforge" / "ui" / "templates" / "run.html"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_report_hunt_moa_js():
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


def test_report_hunt_moa_wired():
    report = REPORT_JS.read_text(encoding="utf-8")
    cov = COVERAGE_JS.read_text(encoding="utf-8")
    html = RUN_HTML.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")

    assert 'src="/static/report_hunt_moa.js"' in html
    assert html.index('src="/static/report_hunt_moa.js"') < html.index(
        'src="/static/report.js"'
    )
    assert "huntMoaBadgeHtml" in report or "ReportHuntMoa" in report
    assert "huntMoaDetailHtml" in report or "ReportHuntMoa" in report
    assert "huntMoaBadgeHtml" in report
    assert "huntMoaDetailHtml" in report
    # MoA helper tip insists agreement is not confirm
    helper = HELPERS.read_text(encoding="utf-8")
    assert "never auto-confirms" in helper
    assert "not confirmed" in helper.lower()
    assert "cellRequeueNoteHtml" in cov or "ReportHuntMoa" in cov
    assert ".badge.hunt-moa-agree" in css
    assert "confirmed" not in css.split(".badge.hunt-moa-agree", 1)[1].split("}", 1)[0]
