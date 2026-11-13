"""Benchmarks desk pages (/benchmarks): thin shell, page modules, legacy redirects."""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

from vulnforge.paths import PROJECT_ROOT
from vulnforge.ui.app import create_app

TEMPLATE = PROJECT_ROOT / "vulnforge" / "ui" / "templates" / "benchmarks.html"
MODULES = ("helpers.js", "desk.js", "scoreboard.js", "run.js", "cases.js")


def test_template_has_no_inline_script():
    html = TEMPLATE.read_text(encoding="utf-8")
    scripts = re.findall(r"<script\b([^>]*)>(.*?)</script>", html, flags=re.S)
    assert scripts, "page modules must load"
    for attrs, body in scripts:
        assert "src=" in attrs, "inline <script> is not allowed on the bench desk"
        assert body.strip() == ""
    assert "style=" not in html
    for name in MODULES:
        assert f'src="/static/pages/bench/{name}"' in html
        assert (PROJECT_ROOT / "vulnforge" / "ui" / "static" / "pages" / "bench" / name).is_file()
    assert 'href="/static/pages/bench/bench.css"' in html
    assert 'href="/static/shell.css"' in html


def test_bench_pages_render_their_view(tmp_path):
    app = create_app(runs_root=tmp_path / "runs")
    with TestClient(app) as client:
        views = {
            "/benchmarks": "scoreboard",
            "/benchmarks/cases": "cases",
            "/benchmarks/runs/br-aaaaaaaaaaaa": "run",
            "/benchmarks/compare?a=br-aaaaaaaaaaaa&b=br-bbbbbbbbbbbb": "compare",
        }
        for path, view in views.items():
            resp = client.get(path)
            assert resp.status_code == 200, path
            body = resp.text
            assert 'data-page="benchmarks"' in body
            assert f'data-bench-view="{view}"' in body
            assert 'href="/benchmarks"' in body
            assert 'href="/benchmarks/cases"' in body
            assert 'aria-current="page"' in body
            assert 'href="/dev/benchmarks' not in body
        run = client.get("/benchmarks/runs/br-aaaaaaaaaaaa").text
        assert 'data-run-id="br-aaaaaaaaaaaa"' in run
        cmp = client.get("/benchmarks/compare?a=br-aaaaaaaaaaaa&b=br-bbbbbbbbbbbb").text
        assert 'data-compare-a="br-aaaaaaaaaaaa"' in cmp
        assert 'data-compare-b="br-bbbbbbbbbbbb"' in cmp

        home = client.get("/")
        assert 'href="/benchmarks"' in home.text
        assert 'id="btn-open-benchmarks"' in home.text


def test_legacy_bench_urls_redirect(tmp_path):
    app = create_app(runs_root=tmp_path / "runs")
    with TestClient(app) as client:
        expect = {
            "/benchmarks/run": "/benchmarks",
            "/benchmarks/poc": "/benchmarks",
            "/benchmarks/results": "/benchmarks",
            "/benchmarks/library": "/benchmarks/cases",
            "/benchmarks/results/br-aaaaaaaaaaaa": "/benchmarks/runs/br-aaaaaaaaaaaa",
        }
        for old, new in expect.items():
            r = client.get(old, follow_redirects=False)
            assert r.status_code == 308, old
            assert r.headers["location"] == new
        assert client.get("/benchmarks/nope", follow_redirects=False).status_code == 404


def test_desk_states_tier_caveats_and_no_confirmed_language():
    """Honesty: L0 and directed caveats ship with the page; nothing says 'confirmed finding'."""
    base = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "pages" / "bench"
    helpers = (base / "helpers.js").read_text(encoding="utf-8")
    assert "says nothing about model quality" in helpers
    assert "told where to look" in helpers
    assert "Not proven false positives" in helpers
    for name in MODULES:
        js = (base / name).read_text(encoding="utf-8").lower()
        assert "confirmed finding" not in js
        assert "per confirmed" not in js
