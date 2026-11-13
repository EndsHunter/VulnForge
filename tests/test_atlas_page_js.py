"""Atlas (Code Atlas) page: pure layout helpers via node --test, plus wiring checks."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from vulnforge.paths import PROJECT_ROOT

STATIC = PROJECT_ROOT / "vulnforge" / "ui" / "static"
ATLAS_JS = STATIC / "pages" / "atlas.js"
EXPLORER_JS = STATIC / "explorer.js"
TEST_JS = PROJECT_ROOT / "tests" / "js" / "atlas_helpers.test.js"
RUN_HTML = PROJECT_ROOT / "vulnforge" / "ui" / "templates" / "run.html"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_atlas_helpers_js():
    assert ATLAS_JS.is_file(), f"missing {ATLAS_JS}"
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


def test_atlas_page_wiring():
    html = RUN_HTML.read_text(encoding="utf-8")
    block = html[html.index("<!-- BEGIN page:atlas") : html.index("<!-- END page:atlas -->")]
    assert 'data-mode-panel="explorer"' in block
    assert 'id="page-atlas"' in block
    assert 'id="explorer-panel"' in block

    atlas = ATLAS_JS.read_text(encoding="utf-8")
    assert "window.VFPages.atlas" in atlas
    assert '"vf:snapshot"' in atlas
    # Hunt composer uses the existing bulk requeue route; recon/history reuse theirs.
    assert "/coverage/requeue-bulk" in atlas
    assert "/recon/rerun" in atlas
    assert "/architecture/history" in atlas
    assert "/architecture/restore/" in atlas
    # Honesty copy: no pin / calm shading is not proof of safety.
    assert "not evidence of safety" in atlas
    assert "not proof of safety" in atlas
    # Flow map (docs/harness/recon/FLOWS.md): layers, flows panel, honesty copy.
    assert "Arrows are recon's map of how data moves." in atlas
    assert "no arrow is not proof of safety" in atlas
    assert "No data flows traced yet." in atlas
    assert "Mechanical skeleton — recon has not labelled this yet." in atlas
    for layer in ("flows", "links", "imports"):
        assert f'data-layer="{layer}"' in atlas
    assert 'data-left-tab="flows"' in atlas
    assert "Hunt this flow" in atlas
    assert '"Escape"' in atlas
    assert "architecture_skeleton" in atlas
    assert (TEST_JS.parent / "fixtures" / "arch_v2_toy_sqli.json").is_file()

    explorer = EXPLORER_JS.read_text(encoding="utf-8")
    assert "listDir" in explorer
    # Snapshot refreshes must not tear down the open Monaco editor.
    assert "window.renderExplorer = renderLazy" in explorer
    assert "window.renderExplorer = mount;" not in explorer
