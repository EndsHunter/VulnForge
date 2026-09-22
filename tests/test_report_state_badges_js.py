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


def test_report_rows_show_current_state_only():
    report = REPORT_JS.read_text(encoding="utf-8")
    html = RUN_HTML.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")
    app = APP_JS.read_text(encoding="utf-8")

    assert 'src="/static/report_state_badges.js"' in html
    assert html.index('src="/static/report_state_badges.js"') < html.index(
        'src="/static/report.js"'
    )
    # Detail / context may still use the trail helper. The State column is current status only.
    assert "function stateTrailHtml(" in report
    assert 'class="report-state-cell">${badge(f.state, f)}' in report
    assert 'class="report-state-cell">${stateTrailHtml(f)}' not in report
    assert "Click a count to filter the table" not in report
    assert "report-disclaimer" not in report
    assert "Row badges follow proposed" not in report
    assert 'data-rfilter="near_dup"' in report
    assert "function nearDupGroupKey(" in report
    assert "nearDupFilterActive()" in report
    assert "near-dup-cluster-start" in report
    assert "Near-dup / Overlaps" not in html
    assert 'id="report-clusters"' not in html
    assert "Related variants" not in report
    assert "Merge metadata" not in report
    assert "llm survived" not in report
    assert "wireReportStateTips(" in report
    assert "data-tip=" in report

    assert "Confirmed is human-only" in app
    assert "never auto-confirms" in app
    assert "function stateTip(" in app

    assert ".badge.step-stood" in css
    assert ".report-state-trail" in css
    assert ".near-dup-cluster-start" in css
    confirmed_rule = next(
        line for line in css.splitlines() if ".badge.confirmed" in line and "succeeded" in line
    )
    assert "step-stood" not in confirmed_rule
    assert "step-pass" not in confirmed_rule


def test_report_folds_disk_projections_into_export():
    """Attack chains and the raw shelf stay off Report; project/* downloads live in Export."""
    report = REPORT_JS.read_text(encoding="utf-8")
    html = RUN_HTML.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")

    assert 'id="report-chains-card"' not in html
    assert 'id="report-chain-create"' not in html
    assert "report-chain-honesty" not in html
    assert "report-select-cb" not in report
    assert "function loadChains(" not in report
    assert 'id="report-raw-exports"' not in html
    assert "report-raw-card" not in html

    modal = html.split('id="report-export-modal"', 1)[1].split('id="poc-modal"', 1)[0]
    assert "Disk projections" in modal
    assert 'id="report-export-projections"' in modal
    assert "function exportRawProjection(" in report
    assert "/project/${encodeURIComponent(name)}" in report
    assert "snap.project_files" in report
    assert "No project files on disk yet." in report
    assert report.count("renderExportProjections()") >= 3
    open_body = report.split("function openExportModal", 1)[1].split(
        "function closeExportModal", 1
    )[0]
    refresh_body = report.split("function renderReport", 1)[1]
    assert "renderExportProjections()" in open_body
    assert "renderExportProjections()" in refresh_body
    assert ".report-export-projections" in css
