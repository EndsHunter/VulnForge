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


def test_mission_hover_tips_are_wired():
    """Funnel stages and presence bits expose immediate data-tip help, not title alone."""
    app = (PROJECT_ROOT / "vulnforge" / "ui" / "static" / "app.js").read_text(
        encoding="utf-8"
    )
    css = (PROJECT_ROOT / "vulnforge" / "ui" / "static" / "styles.css").read_text(
        encoding="utf-8"
    )
    funnel_start = app.index("function renderFindingFunnelHtml")
    presence_start = app.index("function renderPresenceHtml")
    strip_start = app.index("function renderCampaignStripHtml")
    funnel = app[funnel_start:presence_start]
    presence = app[presence_start:strip_start]
    assert "data-tip=" in funnel
    assert "aria-describedby=" in funnel
    assert 'title="' in funnel
    assert "arch-campaign-presence-bit" in presence
    assert "data-tip=" in presence
    assert "aria-describedby=" in presence
    assert "function wireMissionHoverTips(" in app
    assert "wireMissionHoverTips()" in app
    assert "init-floating-tip" in css
    assert "arch-campaign-presence-bit[data-tip]" in css


def test_mission_needs_review_indicator_not_inbox_card():
    """Mission uses a light top-right indicator; Report has no duplicate inbox."""
    html = (PROJECT_ROOT / "vulnforge" / "ui" / "templates" / "run.html").read_text(
        encoding="utf-8"
    )
    app = (PROJECT_ROOT / "vulnforge" / "ui" / "static" / "app.js").read_text(
        encoding="utf-8"
    )
    css = (PROJECT_ROOT / "vulnforge" / "ui" / "static" / "styles.css").read_text(
        encoding="utf-8"
    )
    report = (PROJECT_ROOT / "vulnforge" / "ui" / "static" / "report.js").read_text(
        encoding="utf-8"
    )
    helpers = HELPERS.read_text(encoding="utf-8")

    assert 'id="hitl-inbox"' not in html
    assert 'id="hitl-inbox-report"' not in html
    assert 'data-rfilter="needs_human"' in report
    assert ">Needs review<" in report

    assert "function renderNeedsReviewIndicatorHtml(" in app
    assert 'id="mission-needs-review"' in app
    assert 'goReport?.("needs_human")' in app
    assert "needsReview: needsReviewCount(snap)" in app
    assert "countFindingState," in helpers

    assert ".mission-needs-review" in css
    assert "margin-left: auto" in css.split(".mission-needs-review", 1)[1].split("}", 1)[0]
