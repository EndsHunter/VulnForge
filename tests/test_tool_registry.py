"""Agent tool registry: discovery, aliases, critical sets, schemas, dispatch."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnforge.packet import tool_schemas_for
from vulnforge.profiles.code_static import CodeStaticProfile
from vulnforge.tools.dispatch import run_tool
from vulnforge.tools.registry import (
    agent_tool_names,
    allowed_tool_names,
    clear_registry_cache,
    critical_tools_for,
    get_agent_spec,
    openai_schemas_for_stage,
    resolve_canonical_name,
)


def test_agent_tool_names_includes_builtins():
    names = agent_tool_names()
    for n in (
        "list_dir",
        "file_inventory",
        "read_file",
        "grep",
        "note",
        "write_evidence",
        "list_hunt_profiles",
        "request_hunt",
        "submit_architecture",
        "submit_candidate",
        "submit_none",
    ):
        assert n in names


def test_file_inventory_aliases_resolve():
    assert resolve_canonical_name("inventory") == "file_inventory"
    assert resolve_canonical_name("directory_tree") == "file_inventory"
    assert get_agent_spec("dir_tree") is not None
    assert get_agent_spec("dir_tree").name == "file_inventory"


def test_critical_tools_for_stages():
    assert "submit_architecture" in critical_tools_for("recon")
    hunt = critical_tools_for("hunt")
    assert "submit_candidate" in hunt
    assert "submit_none" in hunt
    assert "list_hunt_profiles" in hunt
    assert "request_hunt" in hunt
    assert "write_evidence" in critical_tools_for("develop_poc")


def test_stage_schema_membership():
    recon_names = {
        (t.get("function") or {}).get("name")
        for t in openai_schemas_for_stage("recon")
    }
    assert "submit_architecture" in recon_names
    assert "submit_candidate" not in recon_names
    assert "list_dir" in recon_names

    hunt_names = {
        (t.get("function") or {}).get("name")
        for t in openai_schemas_for_stage("hunt")
    }
    assert "submit_candidate" in hunt_names
    assert "request_hunt" in hunt_names
    assert "submit_architecture" not in hunt_names

    poc_names = {
        (t.get("function") or {}).get("name")
        for t in openai_schemas_for_stage("develop_poc")
    }
    assert "write_evidence" in poc_names
    assert "submit_none" not in poc_names


def test_run_tool_unknown_and_empty_name():
    ctx = {"target_root": ".", "evidence_root": ".", "session": {}}
    r = run_tool("not_a_real_tool_xyz", ctx, {})
    assert r.get("ok") is False
    assert "unknown tool" in (r.get("error") or "").lower()
    r2 = run_tool("", ctx, {})
    assert r2.get("ok") is False
    assert "unknown tool name" in (r2.get("error") or "")


def test_run_tool_alias_file_inventory(tmp_path: Path):
    (tmp_path / "a.py").write_text("x=1\n", encoding="utf-8")
    ctx = {
        "target_root": str(tmp_path),
        "evidence_root": str(tmp_path / "_ev"),
        "session": {},
        "cfg": {"tools": {}, "run": {"ignore_globs": []}},
    }
    r = run_tool("inventory", ctx, {"path": ".", "format": "list"})
    assert r.get("ok") is True, r
    assert r.get("file_count", 0) >= 1


def test_clear_registry_cache_reloads():
    before = set(agent_tool_names())
    clear_registry_cache()
    after = set(agent_tool_names())
    assert before == after
    assert "grep" in after


def test_code_static_allowlist_includes_request_hunt():
    allowed = CodeStaticProfile().allowed_tools()
    assert "request_hunt" in allowed
    assert "list_hunt_profiles" in allowed
    for n in agent_tool_names():
        assert n in allowed
    # registry projection
    assert set(agent_tool_names()).issubset(set(allowed_tool_names()))


def test_write_evidence_stage_schema_differs():
    hunt = {
        (t.get("function") or {}).get("name"): t.get("function") or {}
        for t in tool_schemas_for("code_static", "hunt", apply_defaults=False)
    }
    poc = {
        (t.get("function") or {}).get("name"): t.get("function") or {}
        for t in tool_schemas_for("code_static", "develop_poc", apply_defaults=False)
    }
    h_props = (hunt["write_evidence"].get("parameters") or {}).get("properties") or {}
    p_props = (poc["write_evidence"].get("parameters") or {}).get("properties") or {}
    assert "evidence_id" not in h_props
    assert "evidence_id" in p_props
    p_desc = (poc["write_evidence"].get("description") or "").lower()
    assert "poc" in p_desc


def test_extras_empty_stages_fail_closed(monkeypatch):
    from vulnforge.tools import registry as reg

    monkeypatch.setattr(
        "vulnforge.tools.extra_registry.list_extra_specs",
        lambda: [
            {
                "name": "toy_extra_empty",
                "stages": [],
                "description": "empty stages",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
            {
                "name": "toy_extra_recon",
                "stages": ["recon"],
                "description": "recon only",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        ],
    )
    clear_registry_cache()
    hunt_names = {
        (t.get("function") or {}).get("name")
        for t in openai_schemas_for_stage("hunt")
    }
    recon_names = {
        (t.get("function") or {}).get("name")
        for t in openai_schemas_for_stage("recon")
    }
    # empty stages → default hunt only
    assert "toy_extra_empty" in hunt_names
    assert "toy_extra_empty" not in recon_names
    assert "toy_extra_recon" in recon_names
    assert "toy_extra_recon" not in hunt_names


def test_extras_schema_and_dispatch(monkeypatch, tmp_path: Path):
    def _toy(ctx, **kwargs):
        return {"ok": True, "toy": True}

    monkeypatch.setattr(
        "vulnforge.tools.extra_registry.list_extra_specs",
        lambda: [
            {
                "name": "toy_dispatch",
                "module": "tests.test_tool_registry",
                "callable": "_not_used",
                "stages": ["hunt"],
                "description": "toy",
                "parameters": {
                    "type": "object",
                    "properties": {"x": {"type": "string"}},
                    "required": [],
                },
            }
        ],
    )
    monkeypatch.setattr(
        "vulnforge.tools.extra_registry.get_extra_spec",
        lambda name: {
            "name": "toy_dispatch",
            "module": "vulnforge.tools.queue_note",
            "callable": "note",
            "stages": ["hunt"],
            "description": "toy",
            "parameters": {"type": "object", "properties": {}, "required": []},
        }
        if name == "toy_dispatch"
        else None,
    )
    hunt_names = {
        (t.get("function") or {}).get("name")
        for t in tool_schemas_for("code_static", "hunt", apply_defaults=False)
    }
    assert "toy_dispatch" in hunt_names
    ctx = {
        "target_root": str(tmp_path),
        "evidence_root": str(tmp_path / "ev"),
        "task_id": 1,
        "session": {},
    }
    # note requires kind+payload — bad args still proves dispatch reached extra
    r = run_tool("toy_dispatch", ctx, {"kind": "wishlist", "payload": {"need": "x"}})
    assert r.get("ok") is True, r


def test_paths_and_load_config_smoke(tmp_path: Path, monkeypatch):
    from vulnforge.paths import (
        CONFIG_ROOT,
        PROJECT_ROOT,
        SEEDS_ROOT,
        effective_prompt_pin_root,
        hunt_class_seeds_root,
        recon_agent_seeds_root,
        system_prompts_root,
    )
    from vulnforge.settings.load import load_config

    assert PROJECT_ROOT.is_dir()
    assert CONFIG_ROOT == PROJECT_ROOT / "config"
    assert system_prompts_root().is_dir()
    assert (system_prompts_root() / "PRINCIPLES.md").is_file()
    assert hunt_class_seeds_root().is_dir()
    assert recon_agent_seeds_root().is_dir()
    # Prefer seeds/ package library when populated
    assert system_prompts_root() == SEEDS_ROOT / "system"
    assert hunt_class_seeds_root() == SEEDS_ROOT / "hunt_classes"
    assert effective_prompt_pin_root() == SEEDS_ROOT

    # env override wins last
    monkeypatch.setenv("VF_MODEL", "registry-test-model")
    cfg = load_config()
    assert cfg["llm"]["model"] == "registry-test-model"
    monkeypatch.delenv("VF_MODEL", raising=False)


def test_paths_dual_read_fallback_when_seeds_empty(tmp_path: Path, monkeypatch):
    """When seeds/system has no markdown, loaders fall back to LEGACY_PROMPTS_V1."""
    import vulnforge.paths as paths_mod

    legacy = tmp_path / "legacy_v1"
    legacy.mkdir()
    (legacy / "PRINCIPLES.md").write_text("# legacy\n", encoding="utf-8")
    (legacy / "hunt_classes").mkdir()
    (legacy / "hunt_classes" / "injection.md").write_text("# inj\n", encoding="utf-8")
    (legacy / "recon_agents").mkdir()
    empty_seeds = tmp_path / "empty_seeds"
    empty_seeds.mkdir()
    # system dir missing or empty → fallback
    monkeypatch.setattr(paths_mod, "SEEDS_ROOT", empty_seeds)
    monkeypatch.setattr(paths_mod, "LEGACY_PROMPTS_V1", legacy)

    assert paths_mod.system_prompts_root() == legacy
    assert paths_mod.hunt_class_seeds_root() == legacy / "hunt_classes"
    assert paths_mod.recon_agent_seeds_root() == legacy / "recon_agents"
    assert paths_mod.effective_prompt_pin_root() == legacy


def test_load_prompt_slice_prefers_override(tmp_path: Path, monkeypatch):
    from vulnforge.packet import load_prompt_slice

    package = tmp_path / "system"
    package.mkdir()
    (package / "preamble.md").write_text("FROM_PACKAGE\n", encoding="utf-8")
    ov = tmp_path / "overrides"
    ov.mkdir()
    (ov / "preamble.md").write_text("FROM_OVERRIDE\n", encoding="utf-8")
    monkeypatch.setattr(
        "vulnforge.paths.prompt_overrides_root",
        lambda: ov,
    )
    assert load_prompt_slice(package, "preamble.md") == "FROM_OVERRIDE\n"
    # Nested relative paths do not use overrides (basename-only convention)
    (package / "sub").mkdir()
    (package / "sub" / "nested.md").write_text("NESTED\n", encoding="utf-8")
    assert load_prompt_slice(package, "sub/nested.md") == "NESTED\n"
