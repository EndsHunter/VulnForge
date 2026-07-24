"""Integration dry-run / apply for tool drafts (temp project files)."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnforge.toolgen.integrate import IntegrateToolError, integrate, plan_integration
from vulnforge.toolgen.store import (
    create_draft,
    reset_drafts_root_override,
    set_drafts_root,
    update_draft,
)
from vulnforge.toolgen.validate import validate_draft

GOOD_IMPL = '''\
"""count_entries tool"""
from __future__ import annotations
from pathlib import Path
from typing import Any
from vulnforge.tools.fs_read import resolve_target_path

def count_entries(ctx: dict, path: str = ".") -> dict[str, Any]:
    try:
        p = resolve_target_path(Path(ctx["target_root"]), path)
        if not p.is_dir():
            return {"ok": False, "error": "not a directory"}
        return {"ok": True, "path": path, "count": sum(1 for _ in p.iterdir())}
    except Exception as e:
        return {"ok": False, "error": str(e)}
'''


@pytest.fixture
def drafts_root(tmp_path: Path):
    root = tmp_path / "tool_drafts"
    set_drafts_root(root)
    yield root
    reset_drafts_root_override()


def _seed_draft_base(draft_id: str = "count_entries"):
    create_draft(brief="Count directory entries", suggested_id=draft_id)
    update_draft(
        draft_id,
        spec_md="# Tool: count_entries\n## Purpose\nCount entries.\n",
        impl_py=GOOD_IMPL,
        schema={
            "tools": [
                {
                    "name": draft_id,
                    "description": "Count directory entries under path",
                    "stages": ["hunt"],
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "rel path"},
                        },
                        "required": [],
                    },
                }
            ]
        },
        handler_snippet=f'if name == "{draft_id}": ...',
        test_stub=f"def test_{draft_id}():\n    assert True\n",
    )


def _seed_valid_draft_agent(draft_id: str = "count_entries"):
    """Agent SPEC path (preferred integrate target)."""
    _seed_draft_base(draft_id)
    update_draft(
        draft_id,
        wireup={
            "impl_module": f"vulnforge.tools.agent.{draft_id}",
            "impl_path": f"vulnforge/tools/agent/{draft_id}.py",
            "handler_branches": [draft_id],
            "allowed_tools_add": [draft_id],
            "packet_stages": ["hunt"],
            "test_file": f"tests/test_tool_{draft_id}.py",
        },
    )
    report = validate_draft(draft_id, for_integrate=True, persist=True)
    assert report["ok"], report["hard_fail"]
    return draft_id


def _seed_valid_draft_legacy(draft_id: str = "count_entries"):
    """Legacy extra_registry path with explicit non-agent wireup."""
    # Use a distinct id that still matches the impl def name via schema rename
    lid = "legacy_count"
    create_draft(brief="Count directory entries (legacy)", suggested_id=lid)
    impl = GOOD_IMPL.replace("def count_entries", f"def {lid}")
    update_draft(
        lid,
        spec_md=f"# Tool: {lid}\n## Purpose\nCount entries.\n",
        impl_py=impl,
        schema={
            "tools": [
                {
                    "name": lid,
                    "description": "Count directory entries under path",
                    "stages": ["hunt"],
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "rel path"},
                        },
                        "required": [],
                    },
                }
            ]
        },
        wireup={
            "impl_module": f"vulnforge.tools.{lid}",
            "impl_path": f"vulnforge/tools/{lid}.py",
            "handler_branches": [lid],
            "allowed_tools_add": [lid],
            "packet_stages": ["hunt"],
            "test_file": f"tests/test_tool_{lid}.py",
        },
        handler_snippet=f'if name == "{lid}": ...',
        test_stub=f"def test_{lid}():\n    assert True\n",
    )
    report = validate_draft(lid, for_integrate=True, persist=True)
    assert report["ok"], report["hard_fail"]
    return lid


def test_plan_integration_agent_default_path(drafts_root: Path):
    did = _seed_valid_draft_agent()
    plan = plan_integration(did)
    assert plan["ok"]
    assert plan["tool_name"] == did
    assert plan.get("write_agent_spec") is True
    assert plan["impl_path"].replace("\\", "/").startswith("vulnforge/tools/agent/")
    assert any("tools/agent/" in o["path"].replace("\\", "/") for o in plan["ops"])
    # Agent path does not rewrite extra_registry
    assert not any("extra_registry" in o["path"] for o in plan["ops"])


def test_plan_integration_legacy_extra_registry(drafts_root: Path):
    did = _seed_valid_draft_legacy()
    plan = plan_integration(did)
    assert plan["ok"]
    assert plan.get("write_agent_spec") is False
    assert plan["impl_path"].replace("\\", "/") == f"vulnforge/tools/{did}.py"
    assert any("extra_registry" in o["path"] for o in plan["ops"])


def test_integrate_dry_run_api_shape(drafts_root: Path):
    did = _seed_valid_draft_agent("count_entries")
    out = integrate(did, dry_run=True, apply=False)
    assert out.get("dry_run") is True
    assert "ops" in out


def test_integrate_rejects_invalid(drafts_root: Path):
    create_draft(brief="incomplete", suggested_id="nope_tool")
    with pytest.raises(IntegrateToolError):
        plan_integration("nope_tool")
