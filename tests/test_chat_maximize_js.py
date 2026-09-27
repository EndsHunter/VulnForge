"""Bubble sheet maximize stays in place, and cockpit pages share that chat."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from vulnforge.paths import PROJECT_ROOT

CHAT_JS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "chat.js"
TEST_JS = PROJECT_ROOT / "tests" / "js" / "chat_maximize.test.js"
CSS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "styles.css"
MODES = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "modes.js"
TEMPLATES = PROJECT_ROOT / "vulnforge" / "ui" / "templates"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_chat_maximize_js():
    assert CHAT_JS.is_file()
    assert TEST_JS.is_file()
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


def test_maximize_is_in_place():
    js = CHAT_JS.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")
    modes = MODES.read_text(encoding="utf-8")
    assert "function toggleMaximize" in js
    assert "is-max" in js
    assert "sessionStorage" in js
    assert "location" not in js
    assert '"/chat"' not in js
    assert ".ai-sheet.is-max" in css
    assert '"/chat"' not in modes
    for name in ("index.html", "run.html"):
        html = (TEMPLATES / name).read_text(encoding="utf-8")
        assert 'id="ai-max"' in html
        assert 'id="ai-sheet"' in html
        assert 'id="operator-chat-root"' in html


def test_cockpit_pages_open_the_same_chat_root():
    for name in ("dev.html", "tool_gaps.html", "benchmarks.html"):
        html = (TEMPLATES / name).read_text(encoding="utf-8")
        assert 'id="ai-entry"' in html
        assert 'id="ai-sheet"' in html
        assert 'id="ai-max"' in html
        assert 'id="operator-chat-root"' in html
        assert 'data-chat-scope="home"' in html
        assert 'src="/static/chat.js"' in html
        entry = html.split('id="ai-entry"', 1)[0].rsplit("<", 1)[-1]
        assert entry.startswith("button")
        assert 'href="/chat"' not in html
