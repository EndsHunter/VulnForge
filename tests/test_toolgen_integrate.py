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


def _seed_valid_draft(draft_id: str = "count_entries"):
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
        wireup={
            "impl_module": f"vulnforge.tools.{draft_id}",
            "impl_path": f"vulnforge/tools/{draft_id}.py",
            "handler_branches": [draft_id],
            "allowed_tools_add": [draft_id],
            "packet_stages": ["hunt"],
            "test_file": f"tests/test_tool_{draft_id}.py",
        },
        handler_snippet=f'if name == "{draft_id}": ...',
        test_stub=f"def test_{draft_id}():\n    assert True\n",
    )
    report = validate_draft(draft_id, for_integrate=True, persist=True)
    assert report["ok"], report["hard_fail"]
    return draft_id


def test_plan_integration_dry_run(drafts_root: Path):
    did = _seed_valid_draft()
    plan = plan_integration(did)
    assert plan["ok"]
    assert plan["tool_name"] == did
    assert any(o["path"].endswith(f"{did}.py") for o in plan["ops"])


def test_integrate_dry_run_api_shape(drafts_root: Path):
    did = _seed_valid_draft("count_entries")
    out = integrate(did, dry_run=True, apply=False)
    assert out.get("dry_run") is True
    assert "ops" in out


def test_integrate_rejects_invalid(drafts_root: Path):
    create_draft(brief="incomplete", suggested_id="nope_tool")
    with pytest.raises(IntegrateToolError):
        plan_integration("nope_tool")
