"""Step I/O + multi-pass transcript tests."""

from __future__ import annotations

from pathlib import Path

from vulnforge.step_io import build_graph_snapshot, build_task_io
from vulnforge.transcript import (
    list_transcript_ids,
    list_transcript_passes,
    load_all_transcripts,
    load_transcript,
    save_transcript,
)
from vulnforge.usage import load_usage_for_task, record_usage


def test_multipass_transcript_no_clobber(tmp_path: Path):
    run = tmp_path / "run"
    run.mkdir()
    save_transcript(
        run,
        1,
        kind="recon:surface-mapper",
        model_id="fake",
        messages=[{"role": "user", "content": "agent-a"}],
        result={"ok": True},
        pass_key="surface-mapper",
    )
    save_transcript(
        run,
        1,
        kind="recon:auth-model",
        model_id="fake",
        messages=[{"role": "user", "content": "agent-b"}],
        result={"ok": True},
        pass_key="auth-model",
    )
    passes = list_transcript_passes(run, 1)
    assert len(passes) == 2
    keys = {p.get("pass_key") for p in passes}
    assert keys == {"surface-mapper", "auth-model"}
    a = load_transcript(run, 1, pass_key="surface-mapper")
    b = load_transcript(run, 1, pass_key="auth-model")
    assert a is not None and b is not None
    assert a["messages"][0]["content"] == "agent-a"
    assert b["messages"][0]["content"] == "agent-b"
    all_t = load_all_transcripts(run, 1)
    assert len(all_t) == 2
    assert 1 in list_transcript_ids(run)


def test_legacy_single_file_still_loads(tmp_path: Path):
    run = tmp_path / "run"
    run.mkdir()
    save_transcript(
        run,
        7,
        kind="hunt",
        model_id="fake",
        messages=[
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": "done"},
        ],
        result={"ok": True},
        meta={
            "payload": {"class": "injection", "area": "api", "operator_notes": "focus login"},
            "files_created": ["evidence/e1/poc.md"],
        },
    )
    data = load_transcript(run, 7)
    assert data is not None
    assert data["kind"] == "hunt"
    assert 7 in list_transcript_ids(run)

    io = build_task_io(run, 7)
    assert io is not None
    assert io["has_transcript"] is True
    assert "sys" in io["input"]["system"]
    assert "go" in io["input"]["user"]
    assert any(s.get("type") == "md_body" for s in io["input"]["sources"])
    assert any(s.get("type") == "manual" for s in io["input"]["sources"])
    assert "evidence/e1/poc.md" in io["files"]["created"]


def test_step_io_usage_events(tmp_path: Path):
    run = tmp_path / "run"
    run.mkdir()
    save_transcript(
        run,
        3,
        kind="hunt",
        model_id="m1",
        messages=[{"role": "user", "content": "x"}],
        result={"ok": True, "total_tokens": 10},
    )
    record_usage(
        run,
        task_id=3,
        kind="hunt",
        model_id="m1",
        usage={
            "prompt_tokens": 5,
            "completion_tokens": 5,
            "total_tokens": 10,
            "source": "estimate",
            "llm_calls": 1,
        },
    )
    events = load_usage_for_task(run, 3)
    assert len(events) == 1
    io = build_task_io(run, 3)
    assert io is not None
    assert io.get("usage_events")


def test_graph_links_finding_pipeline_and_orphan_hunts():
    """Graph should link recon→hunts and hunt→validate_mech via finding_id."""
    tasks = [
        {
            "id": 1,
            "kind": "recon",
            "state": "succeeded",
            "payload": {},
            "result": {"status": "succeeded", "hunt_enqueued": 2},
        },
        {
            "id": 2,
            "kind": "hunt",
            "state": "succeeded",
            "payload": {"class": "injection", "area": "api"},
            "result": {"finding_id": 10, "status": "succeeded"},
        },
        {
            "id": 3,
            "kind": "hunt",
            "state": "succeeded",
            "payload": {"class": "access-control", "area": "api"},
            "result": {"none_found": True},
        },
        {
            "id": 4,
            "kind": "validate_mech",
            "state": "succeeded",
            "payload": {"finding_id": 10},
            "result": {"verdict": "needs_human", "finding_id": 10},
        },
        {
            "id": 5,
            "kind": "validate_llm",
            "state": "succeeded",
            "payload": {"finding_id": 10},
            "result": {"verdict": "stand", "finding_id": 10},
        },
    ]
    g = build_graph_snapshot(tasks)
    pairs = {(e["source"], e["target"], e["type"]) for e in g["edges"]}
    # Orphan hunts linked from recon
    assert ("task-1", "task-2", "enqueue_hunt") in pairs
    assert ("task-1", "task-3", "enqueue_hunt") in pairs
    # Finding pipeline
    assert ("task-2", "task-4", "finding") in pairs
    assert ("task-4", "task-5", "finding") in pairs
    assert g["edge_count"] >= 4


def test_graph_respects_explicit_parent_task_id():
    tasks = [
        {
            "id": 10,
            "kind": "hunt",
            "state": "succeeded",
            "payload": {},
            "result": {"finding_id": 1},
        },
        {
            "id": 11,
            "kind": "validate_mech",
            "state": "succeeded",
            "payload": {"finding_id": 1, "parent_task_id": 10},
            "result": {},
        },
    ]
    g = build_graph_snapshot(tasks)
    sources = [e for e in g["edges"] if e["target"] == "task-11"]
    assert any(e["source"] == "task-10" for e in sources)


def test_balanced_product_spreads_areas_under_budget():
    from vulnforge.stages.recon import balanced_product_tasks, diversify_clip_tasks

    units = [
        ("Package installation & script execution", ["setup.py"]),
        ("Auth", ["auth/session.py"]),
        ("API", ["api/routes.py"]),
    ]
    classes = ["injection", "access-control", "business-logic"]
    tasks = balanced_product_tasks(units, classes, max_tasks=3)
    assert len(tasks) == 3
    areas = {t["area"] for t in tasks}
    classes_out = {t["class"] for t in tasks}
    # With 3 areas and 3 classes, diagonal should hit 3 distinct areas and 3 classes
    assert len(areas) == 3
    assert len(classes_out) == 3

    # diversify clip: area-outer order would keep only first area for max=3
    dumped = []
    for a, hints in units:
        for c in classes:
            dumped.append({"area": a, "class": c, "path_hints": hints})
    clipped = diversify_clip_tasks(dumped, 3)
    assert len(clipped) == 3
    assert len({t["area"] for t in clipped}) == 3
    assert len({t["class"] for t in clipped}) == 3


def test_hints_for_named_area_no_global_steal():
    from vulnforge.stages.recon import _hints_for_named_area

    inv = {
        "sample_paths": [
            "setup.py",
            "auth/session.py",
            "api/routes.py",
            "install/script.sh",
        ],
        "entrypoints": ["setup.py"],
    }
    area_hints = {
        "Package installation & script execution": ["setup.py", "install/script.sh"],
    }
    h1 = _hints_for_named_area(
        "Package installation & script execution",
        area_hints=area_hints,
        inventory=inv,
    )
    h2 = _hints_for_named_area("Auth", area_hints=area_hints, inventory=inv)
    assert "setup.py" in h1
    assert "auth/session.py" in h2
    assert "setup.py" not in h2  # Auth must not inherit install entrypoints


def test_build_graph_snapshot_parent_edges():
    tasks = [
        {
            "id": 1,
            "kind": "recon",
            "state": "succeeded",
            "payload": {},
            "result": {},
        },
        {
            "id": 2,
            "kind": "hunt",
            "state": "queued",
            "payload": {"parent_task_id": 1, "class": "injection", "area": "api"},
            "result": {},
        },
        {
            "id": 3,
            "kind": "hunt",
            "state": "succeeded",
            "payload": {"class": "injection"},
            "result": {"child_task_id": 4},
        },
        {
            "id": 4,
            "kind": "hunt",
            "state": "queued",
            "payload": {"parent_task_id": 3, "force_depth": True},
            "result": {},
        },
    ]
    g = build_graph_snapshot(tasks)
    assert g["task_count"] == 4
    assert len(g["nodes"]) == 4
    edge_types = {e["type"] for e in g["edges"]}
    assert "parent" in edge_types
    assert any(n["id"] == "kind-recon" for n in g["type_nodes"])
