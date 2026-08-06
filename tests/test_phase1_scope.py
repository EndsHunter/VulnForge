"""Phase 1â€“2: path jail, grep safety, shallow requeue, auto-split, stable_key, merge."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnforge.db import Database, compute_stable_key
from vulnforge.llm import LLMResult, ResponseClass
from vulnforge.packet import pack_hunt
from vulnforge.stages import hunt
from vulnforge.stages.dedup import merge_key, merge_near_duplicate, primary_sink
from vulnforge.stages.recon import _apply_class_routing, plan_hunt_tasks
from vulnforge.tools import build_tool_handler
from vulnforge.tools.grep_index import validate_grep_pattern
from vulnforge.tools.scope import maybe_soft_jail, scope_roots_for_scan
from vulnforge.tools.sink_preindex import build_sink_preindex, filter_sinks_for_paths


def _ctx(toy: Path, *, path_hints: list[str] | None = None, force_depth: bool = False):
    return {
        "target_root": str(toy),
        "evidence_root": str(toy / "_ev"),
        "task_id": 1,
        "cfg": {
            "tools": {"max_grep_pattern_len": 200, "grep_timeout_seconds": 5},
            "run": {"ignore_globs": []},
        },
        "session": {},
        "scope": {
            "enabled": True,
            "path_hints": path_hints or ["app.py"],
            "path_prefix": "",
            "force_depth": force_depth,
            # force_depth must NOT start widened
            "widened": False,
        },
    }


def test_path_jail_soft_block_then_widen(toy_sqli: Path):
    ctx = _ctx(toy_sqli, path_hints=["app.py"])
    h = build_tool_handler(ctx)
    # First out-of-scope list (if other dirs exist) â€” root may soft-block
    r1 = h("list_dir", {"path": "."})
    # With only app.py as hint, listing "." is out of soft scope
    if not r1.get("ok"):
        assert r1.get("error") == "out_of_scope"
        assert r1.get("widen_available")
        r2 = h("list_dir", {"path": "."})
        assert r2.get("ok"), r2
        assert ctx["scope"].get("widened")
    # In-scope read always ok
    rd = h("read_file", {"path": "app.py"})
    assert rd["ok"], rd
    assert "search_users" in rd["content"]


def test_force_depth_keeps_soft_jail(toy_sqli: Path):
    """force_depth requires deeper tools but must not lift soft path jail."""
    ctx = _ctx(toy_sqli, path_hints=["app.py"], force_depth=True)
    assert ctx["scope"]["force_depth"] is True
    assert ctx["scope"]["widened"] is False
    # Soft jail still active
    roots = scope_roots_for_scan(ctx)
    assert roots is not None
    assert "app.py" in roots
    blocked = maybe_soft_jail(ctx, ".")
    assert blocked is not None
    assert blocked.get("error") == "out_of_scope"
    assert blocked.get("widen_available")
    # Still not auto-widened from force_depth alone
    assert not ctx["scope"].get("widened")
    h = build_tool_handler(ctx)
    rd = h("read_file", {"path": "app.py"})
    assert rd["ok"], rd


def test_path_jail_hard_deny_outside_target(toy_sqli: Path):
    ctx = _ctx(toy_sqli)
    h = build_tool_handler(ctx)
    # After widen, still hard-deny escape
    ctx["scope"]["widened"] = True
    bad = h("read_file", {"path": "../outside"})
    assert not bad["ok"]
    assert "escape" in (bad.get("error") or "").lower() or "path" in (
        bad.get("error") or ""
    ).lower()


def test_grep_rejects_nested_quantifiers():
    assert validate_grep_pattern("(a+)+") is not None
    assert validate_grep_pattern("(a*)*") is not None
    assert validate_grep_pattern("a" * 250) is not None
    assert validate_grep_pattern("SELECT") is None
    assert validate_grep_pattern(r"execute\s*\(") is None
    # Stacked .* / .+ are normal multi-hop greps â€” must not false-reject
    assert validate_grep_pattern(r"foo.*bar.*baz") is None
    assert validate_grep_pattern(r"import.*from.*module") is None
    assert validate_grep_pattern(r"a.+b.+c") is None


def test_grep_safety_via_handler(toy_sqli: Path):
    ctx = _ctx(toy_sqli)
    ctx["scope"]["widened"] = True
    h = build_tool_handler(ctx)
    bad = h("grep", {"pattern": "(x+)+"})
    assert not bad["ok"]
    assert "rejected" in (bad.get("error") or "").lower() or "nested" in (
        bad.get("error") or ""
    ).lower()
    good = h("grep", {"pattern": "SELECT"})
    assert good["ok"]
    assert good["matches"]
    multi = h("grep", {"pattern": r"SELECT.*FROM|execute"})
    assert multi["ok"], multi


def test_shallow_none_requeues_once(tmp_path: Path, toy_sqli: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    db.set_architecture({"summary": "toy", "components": []})
    db.enqueue_task(
        "hunt",
        {"area": "app", "class": "injection", "path_hints": ["app.py"]},
    )
    task = db.lease_next_task("w", 60)
    cfg = {
        "llm": {
            "fake": True,
            "fake_responses": [
                LLMResult(
                    ok=True,
                    classification=ResponseClass.OK,
                    content="",
                    tool_calls=[
                        {
                            "id": "1",
                            "name": "submit_none",
                            "arguments": {"reason": "skipped without tools"},
                        }
                    ],
                    raw=None,
                    model_id="fake",
                )
            ],
            "max_tool_rounds": 4,
        },
        "run": {"ignore_globs": [], "max_tasks": 20},
        "packet": {},
        "tools": {},
    }
    r = hunt.run(task, db, run_dir, cfg)
    assert r["status"] == "succeeded"
    assert r.get("shallow")
    assert r.get("shallow_requeued")
    assert r.get("child_task_id")
    # Coverage is shallow, not permanent none
    facts = db.list_coverage_facts()
    assert any(f.get("last_depth") == "shallow" for f in facts)
    # Child enqueued with force_depth but still carries path_hints
    tasks = db.list_tasks()
    children = [t for t in tasks if (t.payload or {}).get("force_depth")]
    assert children
    assert (children[0].payload or {}).get("path_hints") == ["app.py"]
    assert (children[0].payload or {}).get("shallow_requeued") is True
    db.close()


def test_second_shallow_none_does_not_requeue(tmp_path: Path, toy_sqli: Path):
    """After force_depth + shallow_requeued, a second shallow none is terminal."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    db.set_architecture({"summary": "toy", "components": []})
    db.enqueue_task(
        "hunt",
        {
            "area": "app",
            "class": "injection",
            "path_hints": ["app.py"],
            "force_depth": True,
            "shallow_requeued": True,
            "parent_task_id": 99,
        },
    )
    task = db.lease_next_task("w", 60)
    before = len(db.list_tasks())
    cfg = {
        "llm": {
            "fake": True,
            "fake_responses": [
                LLMResult(
                    ok=True,
                    classification=ResponseClass.OK,
                    content="",
                    tool_calls=[
                        {
                            "id": "1",
                            "name": "submit_none",
                            "arguments": {"reason": "still nothing after depth"},
                        }
                    ],
                    raw=None,
                    model_id="fake",
                )
            ],
            "max_tool_rounds": 4,
        },
        "run": {"ignore_globs": [], "max_tasks": 20},
        "packet": {},
        "tools": {},
    }
    r = hunt.run(task, db, run_dir, cfg)
    assert r["status"] == "succeeded"
    assert r.get("none_found")
    assert not r.get("shallow_requeued")
    after = len(db.list_tasks())
    assert after == before  # no new child
    facts = db.list_coverage_facts()
    assert any(f.get("last_depth") in ("shallow", "none") for f in facts)
    db.close()


def test_auto_split_on_max_rounds(tmp_path: Path, toy_sqli: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    db.set_architecture({"summary": "toy", "components": []})
    db.enqueue_task(
        "hunt",
        {
            "area": "app",
            "class": "injection",
            "path_hints": ["app.py", "other.py", "lib/x.py", "lib/y.py"],
        },
    )
    task = db.lease_next_task("w", 60)
    noise = LLMResult(
        ok=True,
        classification=ResponseClass.OK,
        content="",
        tool_calls=[{"id": "n", "name": "list_dir", "arguments": {"path": "."}}],
        raw=None,
        model_id="fake",
    )
    cfg = {
        "llm": {
            "fake": True,
            "fake_responses": [noise, noise, noise],
            "max_tool_rounds": 2,
            # Exercise abort + auto-split path (default now forces submit_none).
            "force_submit_on_round_limit": False,
        },
        "run": {"ignore_globs": [], "max_tasks": 50, "max_split_depth": 2},
        "packet": {},
        "tools": {},
    }
    r = hunt.run(task, db, run_dir, cfg)
    assert r["status"] == "failed_task"
    assert r.get("aborted_scope") or r.get("error") == "max_tool_rounds"
    # Coverage records aborted
    facts = db.list_coverage_facts()
    assert any(f.get("last_depth") == "aborted" for f in facts)
    # Split must enqueue 2â€“4 children with chunked path_hints + force_depth
    assert r.get("split"), "expected auto-split with >=2 path_hints"
    child_ids = r["split"]["child_task_ids"]
    assert 2 <= len(child_ids) <= 4
    kids = [
        t
        for t in db.list_tasks()
        if (t.payload or {}).get("parent_task_id") == task.id
        and int((t.payload or {}).get("split_depth") or 0) > 0
    ]
    assert len(kids) == len(child_ids)
    assert all((t.payload or {}).get("split_depth") == 1 for t in kids)
    assert all((t.payload or {}).get("force_depth") for t in kids)
    # Children keep non-empty chunked path_hints (soft jail still applies)
    for t in kids:
        hints = (t.payload or {}).get("path_hints") or []
        assert hints, "split child must retain path_hints for soft jail"
    db.close()


def test_count_split_tasks_excludes_shallow_requeue(tmp_path: Path):
    db = Database.create(tmp_path / "h.db")
    db.insert_run("r1", str(tmp_path), "code_static", "pin", {})
    db.enqueue_task(
        "hunt",
        {
            "area": "app",
            "class": "injection",
            "parent_task_id": 1,
            "shallow_requeued": True,
            "force_depth": True,
            # no split_depth
        },
    )
    db.enqueue_task(
        "hunt",
        {
            "area": "app",
            "class": "injection",
            "parent_task_id": 1,
            "split_depth": 1,
            "force_depth": True,
        },
    )
    assert hunt._count_split_tasks(db) == 1
    db.close()


def test_stable_key_prefers_sink_path():
    body_a = {
        "weakness_class": "injection",
        "threat_model": {"attacker": "remote user"},
        "sink_path": "src/db.py",
        "sink_symbol": "query",
        "citations": [{"path": "README.md", "symbol": "docs"}],
    }
    body_b = {
        "weakness_class": "injection",
        "threat_model": {"attacker": "remote user"},
        "sink_path": "src/db.py",
        "sink_symbol": "query",
        "citations": [{"path": "src/db.py", "symbol": "query"}],
    }
    assert compute_stable_key("code_static", body_a) == compute_stable_key(
        "code_static", body_b
    )
    path, sym = primary_sink(body_a)
    assert path == "src/db.py"
    assert sym == "query"


def test_merge_near_duplicate_same_sink(tmp_path: Path):
    db = Database.create(tmp_path / "h.db")
    db.insert_run("r1", str(tmp_path), "code_static", "pin", {})
    body1 = {
        "title": "SQLi via tool",
        "summary": "LLM tool builds SQL",
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "user",
            "boundary": "api",
            "impact": "data",
        },
        "citations": [{"path": "agent.py", "symbol": "run_sql"}],
        "sink_path": "agent.py",
        "sink_symbol": "run_sql",
    }
    fid = db.insert_finding(body1, state="candidate", profile="code_static")
    body2 = {
        "title": "AI tool SQLi",
        "summary": "same sink via agent",
        "weakness_class": "ai-llm",
        "threat_model": {
            "attacker": "user",
            "boundary": "api",
            "impact": "data",
        },
        "citations": [{"path": "agent.py", "symbol": "run_sql"}],
        "sink_path": "agent.py",
        "sink_symbol": "run_sql",
    }
    assert merge_key(body1) == merge_key(body2)
    info = merge_near_duplicate(db, body2, profile="code_static")
    assert info is not None
    assert info.get("finding_id") == fid or info.get("superseded_existing")
    assert info.get("revalidate") is True  # candidate material update
    f = db.get_finding(info["finding_id"])
    assert f is not None
    # More specific ai-llm should win or be recorded
    assert f.body.get("weakness_class") in ("ai-llm", "injection")
    db.close()


def test_merge_distinct_symbols_same_path_no_merge(tmp_path: Path):
    """Same file, different symbols â†’ distinct findings (no path-only merge)."""
    db = Database.create(tmp_path / "h.db")
    db.insert_run("r1", str(tmp_path), "code_static", "pin", {})
    body1 = {
        "title": "SQLi in query_a",
        "summary": "first sink",
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "user",
            "boundary": "api",
            "impact": "data",
        },
        "citations": [{"path": "app.py", "symbol": "query_a"}],
        "sink_path": "app.py",
        "sink_symbol": "query_a",
    }
    body2 = {
        "title": "SQLi in query_b",
        "summary": "second sink",
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "user",
            "boundary": "api",
            "impact": "data",
        },
        "citations": [{"path": "app.py", "symbol": "query_b"}],
        "sink_path": "app.py",
        "sink_symbol": "query_b",
    }
    assert merge_key(body1) != merge_key(body2)
    db.insert_finding(body1, state="candidate", profile="code_static")
    assert merge_near_duplicate(db, body2, profile="code_static") is None
    db.close()


def test_merge_empty_symbol_path_only_no_merge(tmp_path: Path):
    """Path-only identity (empty symbols) must not mechanical-merge."""
    db = Database.create(tmp_path / "h.db")
    db.insert_run("r1", str(tmp_path), "code_static", "pin", {})
    body1 = {
        "title": "Issue A",
        "summary": "one",
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "user",
            "boundary": "api",
            "impact": "data",
        },
        "citations": [{"path": "app.py"}],
        "sink_path": "app.py",
        "sink_symbol": "",
    }
    body2 = {
        "title": "Issue B different threat",
        "summary": "two",
        "weakness_class": "access-control",
        "threat_model": {
            "attacker": "admin",
            "boundary": "admin api",
            "impact": "authz bypass",
        },
        "citations": [{"path": "app.py"}],
        "sink_path": "app.py",
        "sink_symbol": "",
    }
    assert merge_key(body1) is None
    assert merge_key(body2) is None
    db.insert_finding(body1, state="candidate", profile="code_static")
    assert merge_near_duplicate(db, body2, profile="code_static") is None
    db.close()


def test_merge_confirmed_does_not_revalidate(tmp_path: Path):
    """Annotation merge of confirmed keeper must not request revalidate (no demotion)."""
    db = Database.create(tmp_path / "h.db")
    db.insert_run("r1", str(tmp_path), "code_static", "pin", {})
    body1 = {
        "title": "SQLi via tool",
        "summary": "LLM tool builds SQL",
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "user",
            "boundary": "api",
            "impact": "data",
        },
        "citations": [{"path": "agent.py", "symbol": "run_sql"}],
        "sink_path": "agent.py",
        "sink_symbol": "run_sql",
        "evidence_id": "ev-keep",
    }
    fid = db.insert_finding(body1, state="confirmed", profile="code_static")
    body2 = {
        "title": "AI tool SQLi",
        "summary": "same sink via agent â€” different evidence",
        "weakness_class": "ai-llm",
        "threat_model": {
            "attacker": "user",
            "boundary": "api",
            "impact": "data",
        },
        "citations": [{"path": "agent.py", "symbol": "run_sql"}],
        "sink_path": "agent.py",
        "sink_symbol": "run_sql",
        "evidence_id": "ev-new-foreign",
    }
    info = merge_near_duplicate(db, body2, profile="code_static")
    assert info is not None
    assert info.get("revalidate") is False
    assert info.get("confirmed_preserved") is True
    f = db.get_finding(info["finding_id"])
    assert f is not None
    assert f.state == "confirmed"
    # Material evidence of confirmed must not be overwritten by merge
    assert f.body.get("evidence_id") == "ev-keep"
    assert "ai-llm" in (f.body.get("merged_classes") or [])
    assert f.id == fid or info["finding_id"] == fid
    db.close()


def test_merge_needs_human_does_not_revalidate(tmp_path: Path):
    """needs_human keeper is annotate-only — no demotion to candidate / revalidate."""
    db = Database.create(tmp_path / "h.db")
    db.insert_run("r1", str(tmp_path), "code_static", "pin", {})
    body1 = {
        "title": "SQLi via tool",
        "summary": "LLM tool builds SQL",
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "user",
            "boundary": "api",
            "impact": "data",
        },
        "citations": [{"path": "agent.py", "symbol": "run_sql"}],
        "sink_path": "agent.py",
        "sink_symbol": "run_sql",
        "evidence_id": "ev-nh",
    }
    fid = db.insert_finding(body1, state="needs_human", profile="code_static")
    body2 = {
        "title": "AI tool SQLi",
        "summary": "same sink",
        "weakness_class": "ai-llm",
        "threat_model": {
            "attacker": "user",
            "boundary": "api",
            "impact": "data",
        },
        "citations": [{"path": "agent.py", "symbol": "run_sql"}],
        "sink_path": "agent.py",
        "sink_symbol": "run_sql",
        "evidence_id": "ev-foreign",
    }
    info = merge_near_duplicate(db, body2, profile="code_static")
    assert info is not None
    assert info.get("revalidate") is False
    assert info.get("needs_human_preserved") is True
    f = db.get_finding(info["finding_id"])
    assert f is not None
    assert f.state == "needs_human"
    assert f.body.get("evidence_id") == "ev-nh"
    assert "ai-llm" in (f.body.get("merged_classes") or [])
    assert f.id == fid or info["finding_id"] == fid
    db.close()


def test_merge_skips_rejected_human(tmp_path: Path):
    """rejected_human is terminal — near-dup must not reopen it."""
    db = Database.create(tmp_path / "h.db")
    db.insert_run("r1", str(tmp_path), "code_static", "pin", {})
    body1 = {
        "title": "Rejected",
        "summary": "human said no",
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "user",
            "boundary": "api",
            "impact": "data",
        },
        "citations": [{"path": "agent.py", "symbol": "run_sql"}],
        "sink_path": "agent.py",
        "sink_symbol": "run_sql",
        "evidence_id": "ev-rj",
    }
    db.insert_finding(body1, state="rejected_human", profile="code_static")
    body2 = {
        "title": "New claim same sink",
        "summary": "retry",
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "user",
            "boundary": "api",
            "impact": "data",
        },
        "citations": [{"path": "agent.py", "symbol": "run_sql"}],
        "sink_path": "agent.py",
        "sink_symbol": "run_sql",
    }
    assert merge_near_duplicate(db, body2, profile="code_static") is None
    f = db.list_findings()[0]
    assert f.state == "rejected_human"
    db.close()


def test_prepare_candidate_prefers_symbol_citation():
    body = {
        "title": "t",
        "summary": "s",
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "user",
            "boundary": "api",
            "impact": "data",
        },
        "citations": [
            {"path": "README.md", "symbol": ""},
            {"path": "app.py", "symbol": "search_users"},
        ],
        "evidence_id": "ev1",
    }
    path, sym = hunt._pick_primary_sink_from_citations(body["citations"])
    assert path == "app.py"
    assert sym == "search_users"


def test_pack_hunt_slim_has_sinks_and_known(tmp_path: Path):
    from vulnforge.paths import system_prompts_root

    prompts = system_prompts_root()
    cfg = {
        "llm": {"context_tokens": 32768, "max_context_fraction": 0.25},
        "packet": {"max_architecture_chars": 1800, "max_hunt_angles": 4},
    }
    pkt = pack_hunt(
        cfg,
        prompts,
        {"area": "app", "class": "injection", "path_hints": ["app.py"]},
        '{"summary":"tiny","area":"app","components":[]}',
        ["abc123"],
        [],
        seed_sinks=[{"path": "app.py", "line": 10, "kind": "sql", "text": "execute"}],
        known_findings=["app.py|injection|confirmed|SQLi"],
    )
    assert "Seed sinks" in pkt.user
    assert "Known findings" in pkt.user
    assert "path_hints" in pkt.user
    # Should not dump a huge architecture section name only
    assert "Architecture (area slice)" in pkt.user
    assert "force_depth does not lift" in pkt.user or "soft jail" in pkt.user


def test_class_routing_drops_ai_llm_without_llm_sinks():
    inventory = {
        "seed_sinks": [
            {"path": "app.py", "line": 1, "kind": "sql", "text": "SELECT"},
        ],
        "file_count": 10,
        "sample_paths": ["app.py"],
        "entrypoints": ["app.py"],
    }
    tasks = [
        {"area": "app", "class": "injection", "path_hints": ["app.py"]},
        {"area": "app", "class": "ai-llm", "path_hints": ["app.py"]},
    ]
    out = _apply_class_routing(tasks, inventory)
    classes = {t["class"] for t in out}
    assert "injection" in classes
    assert "ai-llm" not in classes


def test_sink_preindex_finds_sql(toy_sqli: Path):
    sinks = build_sink_preindex(toy_sqli, [])
    assert any(s.get("kind") == "sql" for s in sinks) or any(
        "SELECT" in (s.get("text") or "") for s in sinks
    )
    top = filter_sinks_for_paths(sinks, ["app.py"], top_k=5)
    assert isinstance(top, list)


def test_filter_sinks_no_global_fallback_when_hints_miss():
    sinks = [
        {"path": "other/mod.py", "line": 1, "kind": "sql", "text": "x"},
        {"path": "lib/z.py", "line": 2, "kind": "exec", "text": "y"},
    ]
    # Hints provided but match nothing â†’ empty, not global top-k
    assert filter_sinks_for_paths(sinks, ["app/"], top_k=5) == []
    # Empty hints still allow global
    assert len(filter_sinks_for_paths(sinks, [], top_k=5)) == 2
    assert len(filter_sinks_for_paths(sinks, None, top_k=5)) == 2


def test_plan_hunt_tasks_attaches_focus(toy_sqli: Path):
    inv = {
        "file_count": 5,
        "entrypoints": ["app.py"],
        "sample_paths": ["app.py"],
        "seed_sinks": [],
        "dir_partitions": [{"dir": ".", "file_count": 1}],
    }
    arch = {
        "summary": "x",
        "hunt_focus": [
            {"area": "app", "class": "injection", "path_hints": ["app.py"]},
        ],
        "components": [{"name": "app", "path_hints": ["app.py"]}],
    }
    tasks, src = plan_hunt_tasks(arch, inv, {"run": {"max_tasks": 10}})
    assert src == "hunt_focus"
    assert tasks
    assert tasks[0]["class"] == "injection"
