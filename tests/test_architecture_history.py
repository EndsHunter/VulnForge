"""Architecture revision history, restore, merge quality, and hunt slice."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnforge.db import ARCHITECTURE_REVISION_CAP, Database
from vulnforge.llm import FakeLLMClient, LLMResult, ResponseClass
from vulnforge.stages.hunt import _architecture_slice
from vulnforge.stages.recon import (
    merge_architectures,
    parse_architecture_merge_content,
    store_merged_architecture,
)


def _run_db(tmp_path: Path) -> Database:
    db = Database.create(tmp_path / "harness.db")
    db.insert_run(
        "run-001",
        target_path=str(tmp_path / "tgt"),
        profile="code_static",
        prompt_pin="pin",
        config={},
    )
    return db


def test_set_architecture_twice_lists_history(tmp_path: Path):
    db = _run_db(tmp_path)
    db.set_architecture(
        {"summary": "v1", "components": [{"name": "api"}]},
        source="recon",
        recon_generation=1,
    )
    assert db.get_architecture()["summary"] == "v1"
    assert db.list_architecture_revisions() == []

    db.set_architecture(
        {"summary": "v2", "components": [{"name": "api"}, {"name": "auth"}]},
        source="merge",
        recon_generation=2,
    )
    revs = db.list_architecture_revisions()
    assert len(revs) == 1
    assert revs[0]["source"] == "merge"
    full = db.get_architecture_revision(revs[0]["id"])
    assert full is not None
    assert full["snapshot"]["summary"] == "v1"
    assert db.get_architecture()["summary"] == "v2"
    db.close()


def test_restore_architecture_revision(tmp_path: Path):
    db = _run_db(tmp_path)
    db.set_architecture({"summary": "alpha", "components": []}, source="recon")
    db.set_architecture({"summary": "beta", "components": []}, source="recon")
    revs = db.list_architecture_revisions()
    assert len(revs) == 1
    rev_id = revs[0]["id"]
    restored = db.restore_architecture_revision(rev_id, note="undo")
    assert restored is not None
    assert restored["summary"] == "alpha"
    assert db.get_architecture()["summary"] == "alpha"
    # Current beta should have been archived on restore
    hist = db.list_architecture_revisions()
    assert len(hist) >= 2
    sources = {r["source"] for r in hist}
    assert "restore" in sources
    db.close()


def test_architecture_revision_cap(tmp_path: Path):
    db = _run_db(tmp_path)
    # First write has no history; subsequent N writes create N-1? Wait:
    # each set after first archives previous → after CAP+2 writes we have CAP revs.
    for i in range(ARCHITECTURE_REVISION_CAP + 5):
        db.set_architecture(
            {"summary": f"map-{i}", "components": []},
            source="recon",
            note=f"n{i}",
        )
    revs = db.list_architecture_revisions(limit=100)
    assert len(revs) == ARCHITECTURE_REVISION_CAP
    # Newest archived is map-(CAP+3) when current is map-(CAP+4)
    # Last write index ARCHITECTURE_REVISION_CAP+4 archives map-(CAP+3)
    summaries = []
    for r in revs:
        full = db.get_architecture_revision(r["id"])
        summaries.append(full["snapshot"]["summary"])
    assert f"map-{ARCHITECTURE_REVISION_CAP + 3}" in summaries
    assert "map-0" not in summaries  # oldest dropped
    assert db.get_architecture()["summary"] == f"map-{ARCHITECTURE_REVISION_CAP + 4}"
    db.close()


def test_store_merged_architecture_source_tags(tmp_path: Path):
    db = _run_db(tmp_path)
    store_merged_architecture(
        db,
        part={
            "summary": "first",
            "components": [{"name": "api", "role": "http"}],
            "trust_boundaries": [],
            "input_surfaces": [],
            "hunt_focus": [],
        },
        agents_run=[{"id": "default-map", "ok": True}],
        inventory={"file_count": 1},
        seed_sinks=[],
        recon_generation=1,
    )
    store_merged_architecture(
        db,
        part={
            "summary": "second pass",
            "components": [{"name": "api", "path_hints": ["api/"]}],
            "trust_boundaries": [],
            "input_surfaces": ["HTTP"],
            "hunt_focus": [],
        },
        agents_run=[{"id": "auth-model", "ok": True}],
        inventory={"file_count": 2},
        seed_sinks=[],
        merge_with_existing=True,
        recon_generation=2,
        cfg={"run": {"architecture_llm_merge": False}},
    )
    revs = db.list_architecture_revisions()
    assert len(revs) == 1
    assert revs[0]["source"] == "merge"
    arch = db.get_architecture()
    assert arch["recon_generation"] == 2
    assert "first" in arch["summary"] and "second pass" in arch["summary"]
    # Component fields merged (role kept, path_hints added)
    api = next(c for c in arch["components"] if c.get("name") == "api")
    assert api.get("role") == "http"
    assert "api/" in (api.get("path_hints") or [])
    assert arch.get("merge_method") == "mechanical"
    db.close()


def test_store_always_merges_when_prior_exists_even_without_flag(tmp_path: Path):
    """Recon batch index 0 / solo re-run must not blank-overwrite prior map."""
    db = _run_db(tmp_path)
    store_merged_architecture(
        db,
        part={
            "summary": "prior map about auth",
            "components": [{"name": "auth", "role": "jwt"}],
            "trust_boundaries": ["public/private"],
            "input_surfaces": [],
            "hunt_focus": [],
        },
        agents_run=[{"id": "default-map", "ok": True}],
        inventory={"file_count": 3},
        seed_sinks=[],
        recon_generation=1,
    )
    # merge_with_existing=False (historical first-agent payload) — still merge
    store_merged_architecture(
        db,
        part={
            "summary": "only api this pass",
            "components": [{"name": "api"}],
            "trust_boundaries": [],
            "input_surfaces": ["REST"],
            "hunt_focus": [],
        },
        agents_run=[{"id": "surface-mapper", "ok": True}],
        inventory={"file_count": 3},
        seed_sinks=[],
        merge_with_existing=False,
        recon_generation=2,
        cfg={"run": {"architecture_llm_merge": False}},
    )
    arch = db.get_architecture()
    assert "prior map" in arch["summary"]
    assert "only api" in arch["summary"]
    names = {c.get("name") for c in arch["components"] if isinstance(c, dict)}
    assert "auth" in names and "api" in names
    assert "public/private" in arch["trust_boundaries"]
    assert "REST" in arch["input_surfaces"]
    db.close()


def test_store_llm_merge_uses_model_result(tmp_path: Path):
    db = _run_db(tmp_path)
    store_merged_architecture(
        db,
        part={
            "summary": "prior only",
            "components": [{"name": "db"}],
            "trust_boundaries": [],
            "input_surfaces": [],
            "hunt_focus": [],
        },
        agents_run=[{"id": "a", "ok": True}],
        inventory={"file_count": 1},
        seed_sinks=[],
    )
    merged_json = json.dumps(
        {
            "summary": "cohesive merged summary",
            "components": [
                {"name": "db", "role": "postgres"},
                {"name": "api", "role": "http"},
            ],
            "trust_boundaries": ["edge"],
            "input_surfaces": ["HTTP"],
            "hunt_focus": [{"area": "api", "class": "injection"}],
        }
    )
    client = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content=merged_json,
                tool_calls=[],
                raw=None,
                model_id="fake-model",
            )
        ]
    )
    store_merged_architecture(
        db,
        part={
            "summary": "incoming api",
            "components": [{"name": "api"}],
            "trust_boundaries": [],
            "input_surfaces": [],
            "hunt_focus": [],
        },
        agents_run=[{"id": "b", "ok": True}],
        inventory={"file_count": 2},
        seed_sinks=[],
        merge_with_existing=True,
        client=client,
        cfg={"run": {"architecture_llm_merge": True}},
        run_dir=tmp_path,
        task_id=1,
    )
    arch = db.get_architecture()
    assert arch["summary"] == "cohesive merged summary"
    assert arch.get("merge_method") == "llm"
    names = {c.get("name") for c in arch["components"] if isinstance(c, dict)}
    assert names == {"db", "api"}
    db.close()


def test_store_llm_merge_fallback_on_bad_json(tmp_path: Path):
    db = _run_db(tmp_path)
    store_merged_architecture(
        db,
        part={
            "summary": "alpha prior",
            "components": [{"name": "core"}],
            "trust_boundaries": [],
            "input_surfaces": [],
            "hunt_focus": [],
        },
        agents_run=[{"id": "a", "ok": True}],
        inventory={},
        seed_sinks=[],
    )
    client = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content="sorry I cannot produce JSON",
                tool_calls=[],
                raw=None,
                model_id="fake-model",
            )
        ]
    )
    store_merged_architecture(
        db,
        part={
            "summary": "beta incoming",
            "components": [{"name": "edge"}],
            "trust_boundaries": [],
            "input_surfaces": [],
            "hunt_focus": [],
        },
        agents_run=[{"id": "b", "ok": True}],
        inventory={},
        seed_sinks=[],
        client=client,
        cfg={"run": {"architecture_llm_merge": True}},
    )
    arch = db.get_architecture()
    assert arch.get("merge_method") == "mechanical"
    assert "alpha prior" in arch["summary"] and "beta incoming" in arch["summary"]
    names = {c.get("name") for c in arch["components"] if isinstance(c, dict)}
    assert "core" in names and "edge" in names
    db.close()


def test_parse_architecture_merge_content_fenced():
    raw = """```json
{"summary": "ok map", "components": [{"name": "x"}], "trust_boundaries": [],
 "input_surfaces": [], "hunt_focus": []}
```"""
    p = parse_architecture_merge_content(raw)
    assert p is not None
    assert p["summary"] == "ok map"
    assert p["components"][0]["name"] == "x"
    assert parse_architecture_merge_content("") is None
    assert parse_architecture_merge_content('{"summary": ""}') is None


def test_merge_architectures_summary_concat_and_dedupe():
    a1 = {"summary": "Line one.\n\nLine two."}
    a2 = {"summary": "Line two.\n\nLine three."}  # Line two deduped
    m = merge_architectures([a1, a2])
    assert "Line one." in m["summary"]
    assert "Line three." in m["summary"]
    # normalized dedupe: only one "Line two."
    assert m["summary"].count("Line two.") == 1


def test_merge_architectures_component_field_merge():
    a1 = {
        "summary": "A",
        "components": [
            {
                "name": "api",
                "role": "short",
                "path_hints": ["api/routes.py"],
            }
        ],
        "trust_boundaries": ["edge"],
        "input_surfaces": [],
        "hunt_focus": [{"area": "api", "class": "injection"}],
    }
    a2 = {
        "summary": "B",
        "components": [
            {
                "name": "api",
                "role": "longer role description",
                "path_hints": ["api/handlers.py"],
                "notes": "extra",
            }
        ],
        "trust_boundaries": ["edge", "admin"],
        "input_surfaces": ["REST"],
        "hunt_focus": [{"area": "api", "class": "injection", "path_hints": ["x.py"]}],
    }
    m = merge_architectures([a1, a2])
    assert "A" in m["summary"] and "B" in m["summary"]
    comps = [c for c in m["components"] if isinstance(c, dict) and c.get("name") == "api"]
    assert len(comps) == 1
    c = comps[0]
    assert c["role"] == "longer role description"
    assert "api/routes.py" in c["path_hints"]
    assert "api/handlers.py" in c["path_hints"]
    assert c.get("notes") == "extra"
    assert "edge" in m["trust_boundaries"] and "admin" in m["trust_boundaries"]
    # Same area|class hunt_focus merges path_hints
    assert len(m["hunt_focus"]) == 1
    hf = m["hunt_focus"][0]
    assert "x.py" in (hf.get("path_hints") or [])


def test_architecture_slice_includes_generation_focus_and_path_match():
    arch = {
        "summary": "Full map " * 100,  # will truncate
        "recon_generation": 3,
        "components": [
            {"name": "worker", "path_hints": ["packages/worker/jobs.py"]},
            {"name": "api", "path_hints": ["packages/api/routes.py"]},
            {"name": "ui", "path_hints": ["packages/ui/app.js"]},
        ],
        "trust_boundaries": ["public/private"],
        "input_surfaces": ["HTTP"],
        "hunt_focus": [
            {"area": "api", "class": "injection", "path_hints": ["routes.py"]},
            {"area": "auth", "class": "access-control"},
            {"area": "api", "class": "business-logic"},
        ],
    }
    payload = {
        "area": "service-api",
        "class": "injection",
        "path_hints": ["packages/api/routes.py"],
    }
    txt = _architecture_slice(arch, payload)
    slim = json.loads(txt)
    assert slim["recon_generation"] == 3
    assert slim["area"] == "service-api"
    # path_hints match pulls api component even when name != area
    names = {c.get("name") for c in slim["components"] if isinstance(c, dict)}
    assert "api" in names
    assert len(slim.get("hunt_focus") or []) <= 5
    # area "service-api" matches focus items containing "api"
    focus_areas = {
        (i.get("area") if isinstance(i, dict) else None)
        for i in (slim.get("hunt_focus") or [])
    }
    assert "api" in focus_areas
    assert len(slim["summary"]) <= 800


def test_architecture_slice_empty_arch_still_works():
    txt = _architecture_slice({}, {"area": "app", "path_hints": []})
    slim = json.loads(txt)
    assert slim["area"] == "app"
    assert slim["components"] == []
    assert "recon_generation" not in slim


def test_open_existing_db_gets_revisions_table(tmp_path: Path):
    """Soft-migrate: older DBs without the table still open and can append."""
    path = tmp_path / "harness.db"
    db = Database.create(path)
    db.insert_run("r", "/t", "code_static", "p", {})
    db.set_architecture({"summary": "old"}, source="recon")
    db.close()
    # Drop table to simulate pre-feature DB, keep schema_version=1
    import sqlite3

    conn = sqlite3.connect(str(path))
    conn.execute("DROP TABLE IF EXISTS architecture_revisions")
    conn.commit()
    conn.close()

    db2 = Database.open(path)
    db2.set_architecture({"summary": "new"}, source="manual")
    revs = db2.list_architecture_revisions()
    assert len(revs) == 1
    assert revs[0]["source"] == "manual"
    db2.close()
