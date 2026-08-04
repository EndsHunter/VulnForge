"""Coarse query_flows / flows backend tests."""

from __future__ import annotations

from pathlib import Path

from vulnforge.tools.codemap import build_codemap
from vulnforge.tools.flows import call_sites, import_neighborhood
from vulnforge.tools.agent import query_flows as qf_mod
from vulnforge.tools.registry import allowed_tool_names


def test_query_flows_in_registry():
    names = allowed_tool_names(include_extras=True)
    assert "query_flows" in names


def test_call_sites_toy_sqli(toy_sqli: Path):
    # search_users is only defined, no callers — empty is OK
    r = call_sites(toy_sqli, "search_users", max_files=50)
    assert r["ok"] is True
    assert r["kind"] == "call_heuristic"
    assert "disclaimer" in r


def test_call_sites_finds_caller(tmp_path: Path):
    (tmp_path / "lib.py").write_text(
        "def search_users(q):\n    return q\n\ndef handler():\n    return search_users('x')\n",
        encoding="utf-8",
    )
    r = call_sites(tmp_path, "search_users", max_files=20)
    assert r["ok"] is True
    assert r["count"] >= 1
    assert any(h.get("path") == "lib.py" for h in r["calls"])


def test_import_neighborhood_mono_synth(project_root: Path):
    mono = project_root / "fixtures" / "mono_synth"
    if not mono.is_dir():
        return
    cm = build_codemap(mono)
    r = import_neighborhood(
        cm,
        path="packages/api/routes.py",
        direction="both",
        max_depth=2,
        max_edges=40,
    )
    assert r["ok"] is True
    assert r["kind"] == "import"
    assert r.get("anchor", {}).get("module") is not None or r.get("nodes") is not None
    # edges may be empty if import scrape didn't resolve — still ok
    assert "edges" in r
    assert "disclaimer" in r


def test_agent_query_flows_soft_jail(tmp_path: Path, toy_sqli: Path):
    ctx = {
        "target_root": str(toy_sqli),
        "cfg": {"tools": {}, "run": {}},
        "session": {},
        "scope": {
            "enabled": True,
            "path_hints": ["app.py"],
            "widened": False,
        },
        "db": None,
    }
    # outside soft scope — first hit blocked
    out = qf_mod.run(ctx, mode="imports", path="other/dir.py")
    assert out.get("ok") is False
    assert out.get("error") == "out_of_scope"


def test_agent_query_flows_calls(tmp_path: Path):
    (tmp_path / "a.py").write_text(
        "def foo():\n    pass\n\ndef bar():\n    foo()\n",
        encoding="utf-8",
    )
    ctx = {
        "target_root": str(tmp_path),
        "cfg": {"tools": {"max_flow_call_files": 50}, "run": {}},
        "session": {},
        "scope": {"enabled": False},
        "db": None,
    }
    out = qf_mod.run(ctx, mode="calls", symbol="foo")
    assert out["ok"] is True
    assert out.get("calls", {}).get("count", 0) >= 1
