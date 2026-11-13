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
    # Planned module is a SPEC + run() agent tool
    impl = plan.get("impl_py") or ""
    assert "SPEC = ToolSpec" in impl
    assert "def run(" in impl


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


# ---- apply gate: dry-run plan_hash, diffs, overwrite refusal ----


@pytest.fixture
def fake_project(tmp_path: Path, monkeypatch):
    """Point integrate writes at a temp project root (never the real package)."""
    import vulnforge.toolgen.integrate as integ

    root = tmp_path / "proj"
    (root / "vulnforge" / "tools" / "agent").mkdir(parents=True)
    (root / "tests").mkdir()
    monkeypatch.setattr(integ, "PROJECT_ROOT", root)
    return root


def test_dry_run_reports_diff_and_plan_hash(drafts_root: Path, fake_project: Path):
    did = _seed_valid_draft_agent()
    out = integrate(did, dry_run=True)
    assert out["dry_run"] is True
    assert len(out["plan_hash"]) == 64
    assert out["overwrites"] == []
    impl_op = next(o for o in out["ops"] if "tools/agent/" in o["path"])
    assert impl_op["exists"] is False
    assert impl_op["overwrite"] is False
    assert impl_op["diff"].startswith("--- /dev/null")
    assert "+SPEC = ToolSpec(" in impl_op["diff"]
    assert "contents" not in out
    # Same draft + same tree → same hash
    assert integrate(did, dry_run=True)["plan_hash"] == out["plan_hash"]


def test_apply_requires_plan_hash(drafts_root: Path, fake_project: Path):
    from vulnforge.toolgen.integrate import IntegrateConflictError

    did = _seed_valid_draft_agent()
    with pytest.raises(IntegrateConflictError, match="dry-run"):
        integrate(did, apply=True)
    assert not (fake_project / "vulnforge/tools/agent/count_entries.py").exists()


def test_apply_refuses_stale_plan(drafts_root: Path, fake_project: Path):
    from vulnforge.toolgen.integrate import IntegrateConflictError

    did = _seed_valid_draft_agent()
    h = integrate(did, dry_run=True)["plan_hash"]
    update_draft(did, impl_py=GOOD_IMPL + "\n# edited after dry-run\n")
    with pytest.raises(IntegrateConflictError, match="changed since the dry-run"):
        integrate(did, apply=True, plan_hash=h)
    assert not (fake_project / "vulnforge/tools/agent/count_entries.py").exists()


def test_apply_with_fresh_plan_writes_files(drafts_root: Path, fake_project: Path):
    did = _seed_valid_draft_agent()
    dry = integrate(did, dry_run=True)
    out = integrate(did, apply=True, plan_hash=dry["plan_hash"])
    assert out["ok"]
    impl = fake_project / "vulnforge/tools/agent/count_entries.py"
    assert impl.is_file()
    assert "SPEC = ToolSpec" in impl.read_text()
    assert "vulnforge/tools/agent/count_entries.py" in out["written"]
    assert (fake_project / "tests/test_tool_count_entries.py").is_file()


def test_apply_refuses_overwrite_without_consent(drafts_root: Path, fake_project: Path):
    from vulnforge.toolgen.integrate import IntegrateConflictError

    did = _seed_valid_draft_agent()
    existing = fake_project / "vulnforge/tools/agent/count_entries.py"
    existing.write_text("# builtin tool, do not clobber\n", encoding="utf-8")
    dry = integrate(did, dry_run=True)
    assert dry["overwrites"] == ["vulnforge/tools/agent/count_entries.py"]
    op = next(o for o in dry["ops"] if o["path"] == dry["overwrites"][0])
    assert op["exists"] is True and op["overwrite"] is True
    assert "-# builtin tool, do not clobber" in op["diff"]
    with pytest.raises(IntegrateConflictError, match="overwrite"):
        integrate(did, apply=True, plan_hash=dry["plan_hash"])
    assert existing.read_text() == "# builtin tool, do not clobber\n"
    integrate(did, apply=True, plan_hash=dry["plan_hash"], allow_overwrite=True)
    assert "SPEC = ToolSpec" in existing.read_text()


def test_existing_test_file_is_skipped_not_overwritten(drafts_root: Path, fake_project: Path):
    did = _seed_valid_draft_agent()
    t = fake_project / "tests/test_tool_count_entries.py"
    t.write_text("# operator test\n", encoding="utf-8")
    dry = integrate(did, dry_run=True)
    op = next(o for o in dry["ops"] if o["path"].endswith("test_tool_count_entries.py"))
    assert op["op"] == "skip" and op["overwrite"] is False
    assert dry["overwrites"] == []
    out = integrate(did, apply=True, plan_hash=dry["plan_hash"])
    assert t.read_text() == "# operator test\n"
    assert not any(p.endswith("test_tool_count_entries.py") for p in out["written"])


def test_integrate_api_maps_conflict_to_409(drafts_root: Path, fake_project: Path, tmp_path: Path):
    from fastapi.testclient import TestClient

    from vulnforge.ui.app import create_app

    did = _seed_valid_draft_agent()
    with TestClient(create_app(runs_root=tmp_path / "runs")) as c:
        r = c.post(f"/api/tool-drafts/{did}/integrate", json={"apply": True})
        assert r.status_code == 409
        dry = c.post(f"/api/tool-drafts/{did}/integrate", json={"dry_run": True})
        assert dry.status_code == 200
        h = dry.json()["plan_hash"]
        ok = c.post(f"/api/tool-drafts/{did}/integrate", json={"apply": True, "plan_hash": h})
        assert ok.status_code == 200, ok.text
        assert ok.json()["tool_name"] == did
