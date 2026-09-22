"""Offline checks for organized LLM transcript turns."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from vulnforge.paths import PROJECT_ROOT

HELPERS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "transcript_turns.js"
TEST_JS = PROJECT_ROOT / "tests" / "js" / "transcript_turns.test.js"
APP_JS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "app.js"
CSS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "styles.css"
RUN_HTML = PROJECT_ROOT / "vulnforge" / "ui" / "templates" / "run.html"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_transcript_turns_js():
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


def test_run_page_uses_organized_turns():
    html = RUN_HTML.read_text(encoding="utf-8")
    app = APP_JS.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")

    assert 'src="/static/transcript_turns.js"' in html
    assert html.index('src="/static/transcript_turns.js"') < html.index('src="/static/app.js"')
    assert "TranscriptTurns" in app
    assert "prefersTurnsTab" in app
    assert "llm-log-btn" in app
    assert 'addEventListener("dblclick"' in app
    assert "JSON.stringify(m.tool_calls" not in app

    assert ".turn-tool-call" in css
    assert ".turn-tool-result" in css
    assert ".turn-text" in css
    assert ".turn-reasoning" in css
