"""Shell out to node --test for Review (Triage Desk) pure helpers (offline)."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from vulnforge.paths import PROJECT_ROOT

HELPERS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "pages" / "review.js"
TEST_JS = PROJECT_ROOT / "tests" / "js" / "review_helpers.test.js"
REPORT_JS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "report.js"
RUN_HTML = PROJECT_ROOT / "vulnforge" / "ui" / "templates" / "run.html"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_review_helpers_js():
    assert HELPERS.is_file(), f"missing {HELPERS}"
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


def test_review_desk_markup_and_honesty():
    html = RUN_HTML.read_text(encoding="utf-8")
    block = html.split("<!-- BEGIN page:review", 1)[1].split("<!-- END page:review -->", 1)[0]
    for html_id in ("page-review", "panel-report", "report-queue", "report-detail", "report-context",
                    "report-search", "report-summary", "report-export-open", "report-sort"):
        assert f'id="{html_id}"' in block, html_id
    # The five big filter cards are gone; chips live in the queue.
    assert "report-summary-grid" not in REPORT_JS.read_text(encoding="utf-8")
    report = REPORT_JS.read_text(encoding="utf-8")
    # Decisions use the explicit human-review endpoint; nothing sets state client-side.
    assert "/findings/${encodeURIComponent(fid)}/review" in report
    assert "state = \"confirmed\"" not in report
    assert "It does not prove the finding is exploitable." in report
    # Pages script loads after report.js so helpers exist at render time.
    assert html.index('src="/static/report.js"') < html.index('src="/static/pages/review.js"')
