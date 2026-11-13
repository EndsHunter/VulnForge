"""Recon pipeline v2 (R1–R5): submit_architecture v2, submit_flow, flow-tracer
ordering, deterministic merge, and a scripted FakeLLM end-to-end on toy_sqli.

Offline only (FakeLLM). Spec: docs/harness/recon/FLOWS.md.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from vulnforge.architecture_schema import SCHEMA_V2
from vulnforge.db import Database
from vulnforge.llm import LLMResult, ResponseClass
from vulnforge.recon_agents import (
    FLOW_AGENT_ID,
    active_agents,
    ensure_collection,
    flow_agent,
    import_collection,
    reset_collection_root_override,
    save_agent,
    set_collection_root,
)
from vulnforge.recon_flows import (
    filter_class_ids,
    flow_tracer_settings,
    normalize_submitted_flows,
    select_flow_entrypoints,
)
from vulnforge.stages import recon
from vulnforge.stages.recon import resolve_recon_agent_ids

SCRATCH_OUT = os.environ.get("VF_RECON_V2_OUT")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def agents_root(tmp_path: Path):
    root = tmp_path / "recon_agents"
    set_collection_root(root)
    ensure_collection()
    yield root
    reset_collection_root_override()


def _tool(name: str, args: dict, content: str = "") -> LLMResult:
    return LLMResult(
        ok=True,
        classification=ResponseClass.OK,
        content=content,
        tool_calls=[{"id": name, "name": name, "arguments": args}],
        raw=None,
        model_id="fake",
    )


def _cfg(responses: list, **extra) -> dict:
    cfg = {
        "llm": {"fake": True, "fake_responses": responses, "max_tool_rounds": 4},
        "run": {"ignore_globs": [], "max_tasks": 10, "max_recon_auto_retries": 0},
        "packet": {},
        "tools": {},
    }
    for k, v in extra.items():
        cfg[k] = v
    return cfg


def _new_run(run_dir: Path, target: Path) -> Database:
    run_dir.mkdir(parents=True)
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(target), "code_static", "pin", {})
    return db


def _recon_tasks(db, *, phase: str | None = None) -> list:
    out = []
    for t in db.list_tasks(limit=500):
        if t.kind != "recon":
            continue
        pl = t.payload if isinstance(t.payload, dict) else {}
        if phase is None or pl.get("recon_phase") == phase:
            out.append(t)
    return out


def _run_next(db, run_dir: Path, cfg: dict) -> tuple[object, dict]:
    task = db.lease_next_task("w", 60)
    assert task is not None
    result = recon.run(task, db, run_dir, cfg)
    state = result.get("status") or "succeeded"
    db.complete_task(task.id, result, state=state)
    return task, result


# toy_sqli/app.py: line 9 def search_users(db_cursor, q), 11 sql = f"...{q}...",
# 12 return db_cursor.execute(sql)
V2_ARCH = {
    "summary": "Toy SQLi module: search_users builds SQL from q.",
    "zones": [
        {"id": "internet", "kind": "internet", "label": "Caller input",
         "evidence": [{"path": "app.py", "line": 9}]},
        {"id": "internal", "kind": "internal"},
    ],
    "components": [
        {
            "id": "app",
            "name": "search module",
            "kind": "module",
            "zone": "internet",
            "role": "search_users query helper",
            "path_hints": ["app.py"],
            "entrypoints": [{"label": "search_users(q)", "path": "app.py", "line": 9}],
            "sinks": [{"kind": "sql", "path": "app.py", "line": 12}],
        }
    ],
    "boundaries": [
        {"from_zone": "internet", "to_zone": "internal", "control": "none (direct call)",
         "path": "app.py", "line": 12}
    ],
    "relations": [
        {"from": "app", "to": "datastore", "kind": "data_flow",
         "evidence": {"path": "app.py", "line": 12}},
        {"from": "app", "to": "ghost-service", "kind": "calls"},  # unknown → dropped
    ],
    "trust_boundaries": ["caller → SQL"],
    "input_surfaces": ["search_users q"],
    "hunt_focus": [{"area": "app", "class": "injection", "path_hints": ["app.py"]}],
}

FLOW_ARGS = {
    "flows": [
        {
            "title": "search q -> SQL query",
            "source": {"component": "app", "label": "search_users(q)", "path": "app.py", "line": 9},
            "steps": [{"component": "app", "path": "app.py", "line": 11,
                       "note": "q formatted into the SQL string"}],
            "sink": {"component": "datastore", "kind": "sql", "path": "app.py", "line": 12},
            "classes": ["injection", "made-up-class"],
            "crosses": ["internet", "internal"],
        }
    ]
}


# ---------------------------------------------------------------------------
# submit_architecture v2 / v1
# ---------------------------------------------------------------------------


def test_submit_architecture_spec_has_v2_fields():
    from vulnforge.tools.agent.submit_architecture import SPEC

    props = SPEC.parameters
    for key in ("zones", "components", "boundaries", "relations", "hunt_focus"):
        assert key in props
    comp = props["components"]["items"]["properties"]
    for key in ("id", "kind", "zone", "entrypoints", "sinks", "path_hints"):
        assert key in comp
    rel = props["relations"]["items"]["properties"]
    assert "evidence" in rel and "confidence" in rel
    assert SPEC.required == ("summary",)


def test_submit_architecture_v2_round_trip(tmp_path: Path, toy_sqli: Path, agents_root):
    run_dir = tmp_path / "run"
    db = _new_run(run_dir, toy_sqli)
    db.enqueue_task("recon", {})
    cfg = _cfg([_tool("submit_architecture", V2_ARCH)], recon={"flow_tracer": {"enabled": False}})
    _, result = _run_next(db, run_dir, cfg)
    assert result["status"] == "succeeded", result
    arch = db.get_architecture()
    assert arch["schema"] == SCHEMA_V2
    comp = {c["id"]: c for c in arch["components"]}
    assert comp["app"]["name"] == "search module"
    assert comp["app"]["zone"] == "internet"
    assert comp["app"]["origin"] == "recon"  # skeleton component relabelled by recon
    assert {"label": "search_users(q)", "path": "app.py", "line": 9} in comp["app"]["entrypoints"]
    assert "datastore" in comp  # skeleton synthetic component kept
    rels = {(r["from"], r["to"], r["kind"]): r for r in arch["relations"]}
    assert rels[("app", "datastore", "data_flow")]["confidence"] == "cited"
    assert rels[("app", "datastore", "db")]["confidence"] == "mechanical"
    assert not any(r["to"] == "ghost-service" for r in arch["relations"])
    assert arch["boundaries"][0]["control"].startswith("none")
    assert {z["id"] for z in arch["zones"]} >= {"internet", "internal"}
    assert arch["hunt_focus"][0]["class"] == "injection"
    assert arch["citation_check"]["valid"] >= 4  # entrypoint, sink, boundary, relation
    assert arch["structure_merge"] == "deterministic"
    assert result["hunt_plan_source"] == "hunt_focus"
    db.close()


def test_submit_architecture_v1_args_still_work(tmp_path: Path, toy_sqli: Path, agents_root):
    run_dir = tmp_path / "run"
    db = _new_run(run_dir, toy_sqli)
    db.enqueue_task("recon", {})
    v1 = {
        "summary": "v1 map",
        "trust_boundaries": ["user → app"],
        "components": [{"name": "app", "path_hints": ["app.py"], "role": "search"}],
        "input_surfaces": ["q"],
        "hunt_focus": [{"area": "app", "class": "injection", "path_hints": ["app.py"]}],
        "relations": [{"from": "app", "to": "datastore", "kind": "calls", "note": "execute"}],
    }
    cfg = _cfg([_tool("submit_architecture", v1)], recon={"flow_tracer": {"enabled": False}})
    _, result = _run_next(db, run_dir, cfg)
    assert result["status"] == "succeeded"
    arch = db.get_architecture()
    assert arch["summary"] == "v1 map"
    assert arch["trust_boundaries"] == ["user → app"]
    assert arch["input_surfaces"] == ["q"]
    app = next(c for c in arch["components"] if c["id"] == "app")
    assert app["role"] == "search" and "app.py" in app["path_hints"]
    rel = next(r for r in arch["relations"] if r["kind"] == "calls")
    assert rel["confidence"] == "inferred"  # no evidence line → dashed
    assert rel["note"] == "execute"
    assert result["hunt_enqueued"] >= 1
    db.close()


def test_parse_architecture_accepts_v2_fields():
    from vulnforge.stages.recon import parse_architecture

    part = parse_architecture(None, {"architecture": V2_ARCH})
    assert part["zones"][0]["id"] == "internet"
    assert part["boundaries"][0]["from_zone"] == "internet"
    assert part["components"][0]["entrypoints"][0]["line"] == 9
    rel = part["relations"][0]
    assert rel["evidence"] == {"path": "app.py", "line": 12}


def test_store_merge_keeps_prior_and_records_revision(tmp_path: Path, toy_sqli: Path):
    from vulnforge.recon_skeleton import build_skeleton_for_target
    from vulnforge.stages.recon import store_merged_architecture

    run_dir = tmp_path / "run"
    db = _new_run(run_dir, toy_sqli)
    skel = build_skeleton_for_target(toy_sqli)
    store_merged_architecture(
        db, part=V2_ARCH, agents_run=[{"id": "default-map", "ok": True}],
        inventory={"file_count": 1}, seed_sinks=[], target_root=toy_sqli,
        skeleton=skel,
    )
    first = db.get_architecture()
    assert {c["id"] for c in first["components"]} == {"app", "datastore"}
    store_merged_architecture(
        db,
        part={
            "summary": "auth pass",
            "components": [{"id": "app", "zone": "authenticated"}],
            "relations": [{"from": "app", "to": "datastore", "kind": "db",
                           "evidence": {"path": "app.py", "line": 999}}],
        },
        agents_run=[{"id": "auth-model", "ok": True}],
        inventory={"file_count": 1}, seed_sinks=[], target_root=toy_sqli,
        cfg={"run": {"architecture_llm_merge": False}}, skeleton=skel,
    )
    arch = db.get_architecture()
    app = next(c for c in arch["components"] if c["id"] == "app")
    assert app["zone"] == "authenticated"  # newer recon wins on text
    assert app["name"] == "search module"  # prior kept where newer is empty
    assert "Toy SQLi" in arch["summary"] and "auth pass" in arch["summary"]
    rel = next(r for r in arch["relations"] if r["kind"] == "db")
    # Same key as the skeleton's mechanical db edge: it stays mechanical, and
    # the bad line 999 never replaces a valid citation.
    assert rel["confidence"] == "mechanical"
    assert rel["evidence"] == {"path": "app.py", "line": 11}
    assert arch["merge_method"] == "mechanical"
    assert len(db.list_architecture_revisions()) == 1
    db.close()


# ---------------------------------------------------------------------------
# submit_flow
# ---------------------------------------------------------------------------


def test_submit_flow_spec_registered_for_recon():
    from vulnforge.tools.registry import critical_tools_for, get_agent_spec

    spec = get_agent_spec("submit_flow")
    assert spec is not None and spec.stages == ("recon",)
    assert "submit_flow" in critical_tools_for("recon")


def test_filter_class_ids_registered_only():
    kept, dropped = filter_class_ids(["injection", "SQL_injection_lol", "access_control"])
    assert "injection" in kept
    assert "access-control" in kept
    assert dropped == ["SQL_injection_lol"]


def test_normalize_submitted_flows_validates_classes_and_citations(toy_sqli: Path):
    arch = {"components": [{"id": "app", "path_hints": ["app.py"]}, {"id": "datastore"}]}
    args = json.loads(json.dumps(FLOW_ARGS))
    args["flows"].append(
        {
            "title": "bad lines",
            "source": {"component": "typo-comp", "path": "app.py", "line": 9},
            "steps": [{"path": "app.py", "line": 400, "note": "no such line"}],
            "sink": {"kind": "sql", "path": "nope.py", "line": 3},
            "classes": ["injection"],
        }
    )
    flows, report = normalize_submitted_flows(args, arch=arch, target_root=toy_sqli)
    assert len(flows) == 2
    good, bad = flows
    assert good["confidence"] == "cited"
    assert good["classes"] == ["injection"]
    assert "made-up-class" in report["dropped_classes"]
    assert bad["confidence"] == "inferred"
    assert bad["source"]["component"] == "app"  # typo resolved via path owner
    assert "line" not in bad["steps"][0]
    assert "path" not in bad["sink"]
    assert good["id"] != bad["id"] and good["id"].startswith("f-")
    assert report["cited"] == 1 and report["inferred"] == 1


def test_submit_flow_rejected_outside_flow_phase(tmp_path: Path):
    from vulnforge.stages.recon import _make_submit_flow

    session: dict = {}
    fn = _make_submit_flow(session, tmp_path)
    out = fn(FLOW_ARGS)
    assert out["ok"] is False
    assert session.get("flows") is None


def test_flow_salvage_on_round_limit(toy_sqli: Path):
    """A model that runs out of rounds still yields the flows it described."""
    from vulnforge.agent_runtime import run_tool_loop
    from vulnforge.llm import FakeLLMClient
    from vulnforge.packet import Packet
    from vulnforge.stages.recon import _make_submit_flow

    session = {
        "flow_phase": True,
        "flow_arch": {"components": [{"id": "app", "path_hints": ["app.py"]}, {"id": "datastore"}]},
        "flow_entrypoint": {"component": "app", "path": "app.py", "line": 9},
    }
    submit = _make_submit_flow(session, toy_sqli)

    def handler(name, args):
        if name == "submit_flow":
            return submit(args)
        return {"ok": True, "content": "..."}

    described = "So far:\n```json\n" + json.dumps(FLOW_ARGS) + "\n```"
    client = FakeLLMClient(
        responses=[
            _tool("read_file", {"path": "app.py", "around_line": 9}, content=described),
            _tool("read_file", {"path": "app.py", "around_line": 12}, content="still reading"),
        ]
    )
    packet = Packet(
        system="s",
        user="u",
        tools_schema=[
            {"type": "function", "function": {"name": "read_file", "parameters": {}}},
            {"type": "function", "function": {"name": "submit_flow", "parameters": {}}},
        ],
    )
    result = run_tool_loop(client, packet, handler, max_rounds=2, temperature=0.1, cfg={})
    assert result.ok is True
    assert (result.raw or {}).get("forced_terminal") == "submit_flow"
    flows = session.get("flows")
    assert flows and flows[0]["confidence"] == "cited"
    assert flows[0]["sink"]["line"] == 12


def test_flows_from_content_never_invents():
    from vulnforge.agent_runtime.round_limit import flows_from_content

    assert flows_from_content("I could not trace anything.") is None
    assert flows_from_content('{"summary": "map"}') is None
    one = flows_from_content(json.dumps(FLOW_ARGS["flows"][0]))
    assert one and one[0]["title"].startswith("search")


# ---------------------------------------------------------------------------
# entrypoint selection + ordering
# ---------------------------------------------------------------------------


def test_select_flow_entrypoints_order_dedupe_cap():
    arch = {
        "zones": [{"id": "public-api", "kind": "internet"}, {"id": "internal", "kind": "internal"}],
        "components": [
            {"id": "worker", "zone": "internal",
             "entrypoints": [{"label": "job", "path": "w.py", "line": 3}]},
            {"id": "admin", "zone": "internal", "sinks": [{"kind": "exec", "path": "a.py", "line": 9}],
             "entrypoints": [{"label": "POST /admin", "path": "a.py", "line": 2}]},
            {"id": "api", "zone": "public-api",
             "entrypoints": [
                 {"label": "api.py", "path": "api.py"},  # file-level, dropped (lined exists)
                 {"label": "GET /a", "path": "api.py", "line": 10},
                 {"label": "GET /a again", "path": "api.py", "line": 10},  # dup path:line
                 {"label": "GET /b", "path": "api.py", "line": 20},
             ]},
        ],
    }
    eps = select_flow_entrypoints(arch, 8)
    assert [(e["component"], e.get("line")) for e in eps] == [
        ("api", 10), ("api", 20), ("admin", 2), ("worker", 3),
    ]
    assert len(select_flow_entrypoints(arch, 2)) == 2


def test_flow_tracer_settings_defaults_and_overrides():
    assert flow_tracer_settings({}) == {"enabled": True, "max_flows": 8, "max_tool_rounds": None}
    assert flow_tracer_settings({"recon": {"flow_tracer": {"enabled": False}}})["enabled"] is False
    assert flow_tracer_settings({"recon": {"flow_tracer": {"max_flows": 0}}})["enabled"] is False
    assert flow_tracer_settings({}, {"flow_tracer": False})["enabled"] is False


def test_flow_tracer_never_in_first_batch(agents_root):
    ids = [a["id"] for a in ensure_collection()["agents"]]
    assert FLOW_AGENT_ID in ids
    assert FLOW_AGENT_ID in [a["id"] for a in active_agents()]  # active = R3 enabled
    assert FLOW_AGENT_ID not in resolve_recon_agent_ids(None)
    assert resolve_recon_agent_ids([FLOW_AGENT_ID]) == [FLOW_AGENT_ID]
    assert resolve_recon_agent_ids(["default-map", FLOW_AGENT_ID]) == ["default-map"]


def test_flow_agent_falls_back_to_package_seed(agents_root):
    """Installs seeded before flow-tracer existed still run it (no config writes)."""
    import_collection(
        {"agents": [{"id": "default-map", "active": True, "body_md": "# Recon agent: default-map\n"}]},
        mode="replace",
    )
    before = sorted(p.name for p in (agents_root / "bodies").iterdir())
    agent = flow_agent()
    assert agent is not None and agent["source"] == "package_seed"
    assert "submit_flow" in agent["body_md"]
    assert sorted(p.name for p in (agents_root / "bodies").iterdir()) == before
    save_agent("default-map", active=True)
    # Operator turned it off in the collection → R3 off
    import_collection(
        {"agents": [{"id": FLOW_AGENT_ID, "active": False, "body_md": "# x\n", "output": "flows"}]},
        mode="merge",
    )
    assert flow_agent() is None


def _map_args_many_entrypoints() -> dict:
    a = json.loads(json.dumps(V2_ARCH))
    a["components"].append(
        {
            "id": "jobs",
            "name": "jobs",
            "zone": "internal",
            "path_hints": ["app.py"],
            "entrypoints": [{"label": f"job{i}", "path": "app.py", "line": i} for i in (1, 2, 3)],
        }
    )
    a["components"][0]["entrypoints"].append({"label": "other", "path": "app.py", "line": 10})
    return a


def test_flow_tasks_enqueued_after_map_batch_only(tmp_path: Path, toy_sqli: Path, agents_root):
    save_agent("surface-mapper", active=True)
    run_dir = tmp_path / "run"
    db = _new_run(run_dir, toy_sqli)
    db.enqueue_task("recon", {})
    cfg = _cfg(
        [_tool("submit_architecture", _map_args_many_entrypoints())],
        recon={"flow_tracer": {"max_flows": 3}},
    )
    # Batch member 1 (default-map) fans out surface-mapper; no flows yet.
    _, r1 = _run_next(db, run_dir, cfg)
    assert r1["status"] == "succeeded", r1
    assert r1["fanout_task_ids"]
    assert not _recon_tasks(db, phase="flows")
    assert r1["batch_finalized"] is False
    # Batch member 2 finalizes → flow fan-out (capped, internet zone first).
    _, r2 = _run_next(db, run_dir, cfg)
    assert r2["status"] == "succeeded", r2
    assert r2["batch_finalized"] is True
    assert r2["hunt_plan_source"] == "pending_flows" and r2["hunt_enqueued"] == 0
    flows_tasks = _recon_tasks(db, phase="flows")
    assert len(flows_tasks) == 3 == len(r2["flow_task_ids"])
    eps = [t.payload["flow_entrypoint"] for t in sorted(flows_tasks, key=lambda t: t.id)]
    assert eps[0]["component"] == "app" and eps[0]["line"] in (9, 10)
    assert eps[1]["component"] == "app"
    keys = {(e.get("path"), e.get("line")) for e in eps}
    assert len(keys) == 3
    for t in flows_tasks:
        assert t.payload["agent_ids"] == [FLOW_AGENT_ID]
        assert t.payload["enqueue_hunts"] is False
    # No hunts before the flow batch completes
    assert not [t for t in db.list_tasks(limit=500) if t.kind == "hunt"]
    db.close()


def test_flow_tracer_disabled_plans_hunts_directly(tmp_path: Path, toy_sqli: Path, agents_root):
    run_dir = tmp_path / "run"
    db = _new_run(run_dir, toy_sqli)
    db.enqueue_task("recon", {})
    cfg = _cfg([_tool("submit_architecture", V2_ARCH)], recon={"flow_tracer": {"enabled": False}})
    _, r = _run_next(db, run_dir, cfg)
    assert r["status"] == "succeeded"
    assert not _recon_tasks(db, phase="flows")
    assert r["hunt_enqueued"] >= 1
    db.close()


def test_flow_tracer_inprocess_mode(tmp_path: Path, toy_sqli: Path, agents_root):
    run_dir = tmp_path / "run"
    db = _new_run(run_dir, toy_sqli)
    db.enqueue_task("recon", {})
    cfg = _cfg(
        [
            _tool("submit_architecture", V2_ARCH),
            _tool("submit_flow", FLOW_ARGS),
        ]
    )
    cfg["llm"]["recon_orchestrator"] = "inprocess"
    _, r = _run_next(db, run_dir, cfg)
    assert r["status"] == "succeeded", r
    assert not _recon_tasks(db, phase="flows")
    assert r["flows_traced"] == 1
    assert r["hunt_enqueued"] >= 1
    arch = db.get_architecture()
    assert arch["flows"] and arch["flows"][0]["confidence"] == "cited"
    db.close()


# ---------------------------------------------------------------------------
# end-to-end (toy_sqli, scripted FakeLLM)
# ---------------------------------------------------------------------------


def test_recon_v2_end_to_end_toy_sqli(tmp_path: Path, toy_sqli: Path, agents_root):
    from vulnforge.ui.store import RunRef, run_snapshot

    run_dir = tmp_path / "runs" / "toy" / "run-001"
    db = _new_run(run_dir, toy_sqli)
    db.enqueue_task("recon", {})

    # R1 map (default-map only active)
    _, r_map = _run_next(db, run_dir, _cfg([_tool("submit_architecture", V2_ARCH)]))
    assert r_map["status"] == "succeeded", r_map
    assert r_map["hunt_plan_source"] == "pending_flows"
    flow_tasks = _recon_tasks(db, phase="flows")
    assert len(flow_tasks) == 1
    ep = flow_tasks[0].payload["flow_entrypoint"]
    assert (ep["component"], ep["path"], ep["line"]) == ("app", "app.py", 9)

    # R3 flow tracer: read the code, then submit_flow
    cfg_flow = _cfg(
        [
            _tool("read_file", {"path": "app.py", "around_line": 10}),
            _tool("submit_flow", FLOW_ARGS),
        ]
    )
    _, r_flow = _run_next(db, run_dir, cfg_flow)
    assert r_flow["status"] == "succeeded", r_flow
    assert r_flow["recon_phase"] == "flows"
    assert r_flow["flows_submitted"] == 1
    assert r_flow["batch_finalized"] is True
    assert r_flow["hunt_enqueued"] >= 1  # hunts after flows

    arch = db.get_architecture()
    assert arch["schema"] == SCHEMA_V2
    flows = arch["flows"]
    assert len(flows) >= 1
    f = flows[0]
    assert f["confidence"] == "cited"
    lines = (toy_sqli / "app.py").read_text().splitlines()
    assert "def search_users" in lines[f["source"]["line"] - 1]
    assert "f\"SELECT" in lines[f["steps"][0]["line"] - 1]
    assert "execute" in lines[f["sink"]["line"] - 1]
    assert f["classes"] == ["injection"]
    assert f["sink"]["component"] == "datastore"
    assert f["agent"] == FLOW_AGENT_ID
    # zones assigned, skeleton mechanical relation preserved
    assert all(c.get("zone") for c in arch["components"])
    assert any(
        r["confidence"] == "mechanical" and r["kind"] == "db" for r in arch["relations"]
    )
    # history: the flow merge snapshots the map it superseded
    sources = [r["source"] for r in db.list_architecture_revisions()]
    assert sources == ["flows"]
    assert arch["recon_flow_runs"][-1]["flows"] == 1

    snap = run_snapshot(RunRef(target_id="toy", run_id="run-001", path=run_dir.resolve()))
    snap_flows = (snap.get("architecture") or {}).get("flows") or []
    assert any(x.get("id") == f["id"] for x in snap_flows)
    if SCRATCH_OUT:
        Path(SCRATCH_OUT).write_text(json.dumps(arch, indent=2, default=str) + "\n")
    db.close()


def test_recon_never_touches_findings(tmp_path: Path, toy_sqli: Path, agents_root):
    """Honesty: no recon / flow path writes findings or sets confirmed."""
    import sqlite3

    run_dir = tmp_path / "run"
    db = _new_run(run_dir, toy_sqli)
    db.enqueue_task("recon", {})
    _run_next(db, run_dir, _cfg([_tool("submit_architecture", V2_ARCH)]))
    _run_next(db, run_dir, _cfg([_tool("submit_flow", FLOW_ARGS)]))
    db.close()
    con = sqlite3.connect(run_dir / "harness.db")
    try:
        n = con.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    finally:
        con.close()
    assert n == 0
    src = Path(recon.__file__).read_text()
    assert "confirmed" not in src
    flows_src = (Path(recon.__file__).parent.parent / "recon_flows.py").read_text()
    assert "insert_finding" not in flows_src and "insert_finding" not in src


def test_packets_include_skeleton_and_split_submit_tools(toy_sqli: Path):
    from vulnforge.packet import pack_flow_tracer, pack_recon_agent
    from vulnforge.paths import system_prompts_root
    from vulnforge.recon_skeleton import build_skeleton_for_target

    skel = build_skeleton_for_target(toy_sqli)
    cfg = {"run": {}, "packet": {"max_skeleton_chars": 800}}

    def names(pkt):
        return {(t.get("function") or {}).get("name") for t in pkt.tools_schema}

    mp = pack_recon_agent(
        cfg, system_prompts_root(), agent_body="# map", inventory={"file_count": 1},
        agent_id="default-map", skeleton=skel,
    )
    assert "## Mechanical skeleton" in mp.user
    assert "app -> datastore db (mechanical, app.py:11)" in mp.user
    assert "submit_architecture" in names(mp) and "submit_flow" not in names(mp)
    assert mp.meta["has_skeleton"] is True

    fp = pack_flow_tracer(
        cfg, system_prompts_root(), "# flow",
        entrypoint={"component": "app", "label": "search_users(q)", "path": "app.py", "line": 9},
        architecture=skel,
    )
    assert "## Entrypoint to trace" in fp.user and '"line": 9' in fp.user
    assert "`injection`" in fp.user
    got = names(fp)
    assert "submit_flow" in got and "read_file" in got and "query_flows" in got
    assert "submit_architecture" not in got and "continue_recon" not in got
