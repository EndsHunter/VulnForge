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


def test_review_needs_review_lives_on_tab_badge_and_chip():
    """Mission is gone: needs_human shows as the Review tab badge + header strip,
    and Review's default chip. Candidates are never counted as needs review."""
    html = (PROJECT_ROOT / "vulnforge" / "ui" / "templates" / "run.html").read_text(
        encoding="utf-8"
    )
    app = (PROJECT_ROOT / "vulnforge" / "ui" / "static" / "app.js").read_text(
        encoding="utf-8"
    )
    modes = (PROJECT_ROOT / "vulnforge" / "ui" / "static" / "modes.js").read_text(
        encoding="utf-8"
    )
    review_js = (
        PROJECT_ROOT / "vulnforge" / "ui" / "static" / "pages" / "review.js"
    ).read_text(encoding="utf-8")
    helpers = HELPERS.read_text(encoding="utf-8")

    assert 'id="hitl-inbox"' not in html
    assert 'id="hitl-inbox-report"' not in html
    assert 'id="arch-panel"' not in html
    assert '{ id: "needs_human", label: "Needs review" }' in review_js
    assert 'id="tab-badge-review"' in modes
    assert "setReviewBadge?.(review ? review.count : 0)" in app
    assert "function buildHeaderStrip(" in helpers
    assert "value: String(counts.needs_human || 0)" in helpers


def test_run_header_token_usage_and_home_tokens_wired():
    """Run header strip and Home rows render token usage from llm_usage."""
    app = (PROJECT_ROOT / "vulnforge" / "ui" / "static" / "app.js").read_text(
        encoding="utf-8"
    )
    helpers = HELPERS.read_text(encoding="utf-8")
    assert 'id="run-token-usage"' in app
    assert "function renderHeaderTokensHtml(" in app
    assert "renderTokenCountsHtml" in app
    assert "function tokenCountsOf" in helpers
    assert "function modelUsageRows" in helpers
    assert "function aggregateRunUsage" in helpers
    assert "prompt_tokens" not in app.split("function renderTokenCountsHtml", 1)[1].split(
        "function renderHomeStats", 1
    )[0]
