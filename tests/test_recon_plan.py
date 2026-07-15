"""Unit tests: recon architecture coerce + hunt planning fallback."""

from __future__ import annotations

import json
from pathlib import Path

from vulnforge.hunt_profiles import active_class_ids, all_class_ids
from vulnforge.hunt_profiles.store import SEED_ACTIVE_IDS
from vulnforge.stages.recon import (
    hunt_class_catalog,
    parse_architecture,
    plan_hunt_tasks,
    _normalize_class,
)
from vulnforge.llm import LLMResult, ResponseClass


def _inv():
    return {"entrypoints": ["app.py"], "sample_paths": ["app.py"]}


def _cfg():
    return {"run": {"max_tasks": 50}}


def _active():
    return list(active_class_ids())


def test_plan_string_hunt_focus_falls_back_to_active():
    tasks, source = plan_hunt_tasks(
        {
            "summary": "x",
            "hunt_focus": '[{"area":"a","class":"injection"',  # invalid / string
            "components": [],
        },
        _inv(),
        _cfg(),
    )
    assert source == "active_fallback"
    assert len(tasks) >= len(_active())
    assert {t["class"] for t in tasks} >= set(_active())


def test_plan_empty_focus_active_fallback():
    tasks, source = plan_hunt_tasks(
        {"summary": "x", "hunt_focus": [], "components": []},
        _inv(),
        _cfg(),
    )
    assert source == "active_fallback"
    assert len(tasks) == len(_active())


def test_plan_valid_focus_list():
    tasks, source = plan_hunt_tasks(
        {
            "summary": "x",
            "hunt_focus": [{"area": "api", "class": "injection", "path_hints": ["a.py"]}],
            "components": [],
        },
        _inv(),
        _cfg(),
    )
    assert source == "hunt_focus"
    assert len(tasks) == 1
    assert tasks[0]["area"] == "api"
    assert tasks[0]["class"] == "injection"


def test_plan_list_of_non_dicts_falls_back():
    tasks, source = plan_hunt_tasks(
        {"summary": "x", "hunt_focus": ["injection", "xss"], "components": []},
        _inv(),
        _cfg(),
    )
    assert source == "active_fallback"
    assert len(tasks) >= len(_active())


def test_parse_coerce_valid_json_string_focus():
    session = {
        "architecture": {
            "summary": "ok",
            "trust_boundaries": ["t"],
            "components": "[]",
            "input_surfaces": "[]",
            "hunt_focus": '[{"area":"a","class":"injection","path_hints":["p.py"]}]',
        }
    }
    arch = parse_architecture(
        LLMResult(
            ok=True,
            classification=ResponseClass.OK,
            content="",
            tool_calls=[],
            raw=None,
            model_id="t",
        ),
        session,
    )
    assert isinstance(arch["hunt_focus"], list)
    assert arch["hunt_focus"][0]["class"] == "injection"
    tasks, source = plan_hunt_tasks(arch, _inv(), _cfg())
    assert source == "hunt_focus"
    assert len(tasks) == 1


def test_parse_coerce_invalid_json_string_to_empty():
    session = {
        "architecture": {
            "summary": "ok",
            "hunt_focus": '[{"area":"a","class":"injection"]]',  # mangled
            "components": "not json",
            "input_surfaces": "",
            "trust_boundaries": ["x"],
        }
    }
    arch = parse_architecture(
        LLMResult(
            ok=True,
            classification=ResponseClass.OK,
            content="",
            tool_calls=[],
            raw=None,
            model_id="t",
        ),
        session,
    )
    assert arch["hunt_focus"] == []
    assert arch["components"] == []
    tasks, source = plan_hunt_tasks(arch, _inv(), _cfg())
    assert source == "active_fallback"
    assert len(tasks) >= len(_active())


def test_recon_string_focus_integration(tmp_path: Path, toy_sqli: Path):
    """End-to-end: stringified hunt_focus must not yield no_hunt_tasks."""
    from vulnforge.db import Database
    from vulnforge.stages import recon
    from vulnforge.llm import FakeLLMClient, LLMResult, ResponseClass

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    tid = db.enqueue_task("recon", {})
    task = db.lease_next_task("w", 60)

    # Mimic Ornith: nested arrays as strings (invalid JSON body → coerce to [])
    arch_args = {
        "summary": "App with stringified focus (moak failure mode)",
        "trust_boundaries": ["none"],
        "components": "[]",
        "input_surfaces": "[]",
        "hunt_focus": '[{"area":"api","class":"injection"]]',
    }
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
                            "name": "submit_architecture",
                            "arguments": arch_args,
                        }
                    ],
                    raw=None,
                    model_id="fake",
                )
            ],
            "max_tool_rounds": 4,
        },
        "run": {"ignore_globs": [], "max_tasks": 10},
        "packet": {},
        "tools": {},
    }
    result = recon.run(task, db, run_dir, cfg)
    assert result["status"] == "succeeded", result
    assert result["hunt_enqueued"] >= len(_active())
    assert result.get("hunt_plan_source") == "active_fallback"
    s = db.summary()
    assert s["tasks"].get("queued", 0) >= 1
    db.close()


def test_recon_salvages_json_architecture_after_no_submit(tmp_path: Path, toy_sqli: Path):
    """no_submit with structured JSON content still stores arch + enqueues hunts."""
    from vulnforge.db import Database
    from vulnforge.stages import recon
    from vulnforge.llm import FakeLLMClient, LLMResult, ResponseClass

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    tid = db.enqueue_task("recon", {})
    task = db.lease_next_task("w", 60)

    arch_json = json.dumps(
        {
            "summary": "Salvaged map of toy SQLi app",
            "trust_boundaries": ["user input"],
            "components": [{"name": "app", "path_hints": ["app.py"]}],
            "input_surfaces": ["q"],
            "hunt_focus": [],
        }
    )
    # FakeLLM free-text exit: content only, no tool_calls → real client would
    # mark no_submit; FakeLLM returns content as ok mid-loop. Use explicit
    # failed LLMResult to exercise salvage branch.
    cfg = {
        "llm": {
            "fake": True,
            "fake_responses": [
                LLMResult(
                    ok=False,
                    classification=ResponseClass.TRUNCATED,
                    content=arch_json,
                    tool_calls=[],
                    raw=None,
                    model_id="fake",
                    error="no_submit",
                )
            ],
            "max_tool_rounds": 4,
        },
        "run": {"ignore_globs": [], "max_tasks": 10, "max_recon_auto_retries": 0},
        "packet": {},
        "tools": {},
    }
    result = recon.run(task, db, run_dir, cfg)
    assert result["status"] == "succeeded", result
    assert result["hunt_enqueued"] >= len(_active())
    arch = db.get_architecture()
    assert arch and "Salvaged" in (arch.get("summary") or "")
    agents = arch.get("recon_agents_run") or []
    assert any(a.get("salvaged_from_content") for a in agents if isinstance(a, dict))
    db.close()


def test_hunt_class_catalog_from_registry():
    """Catalog is active+all from seeded collection; seed library covers known stems."""
    prompts = Path(__file__).resolve().parents[1] / "prompts" / "v1" / "hunt_classes"
    on_disk = {p.stem for p in prompts.glob("*.md")}
    cat = hunt_class_catalog()
    assert set(cat.keys()) == {"all", "active"}
    assert set(cat["all"]) == set(all_class_ids())
    assert set(cat["active"]) == set(active_class_ids())
    # Seeded collection includes every package seed file
    assert on_disk.issubset(set(cat["all"]))
    for cls in (
        "feature-abuse",
        "chains",
        "ai-llm",
        "obvious",
        "supply-chain",
        "graphql",
    ):
        assert cls in cat["all"]
        assert _normalize_class(cls) == cls
    assert _normalize_class("sca") == "supply-chain"
    assert _normalize_class("gql") == "graphql"
    assert _normalize_class("dependency") == "supply-chain"
    # Seeded active set matches migration seed
    assert set(cat["active"]) == set(SEED_ACTIVE_IDS)
