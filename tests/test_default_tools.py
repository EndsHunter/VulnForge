"""Global default tools config + packet resolution."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vulnforge.packet import tool_schemas_for
from vulnforge.tools.default_tools import (
    STAGE_CRITICAL_TOOLS,
    load_default_tools,
    reset_default_tools_path_override,
    resolve_stage_tools,
    save_default_tools,
    set_default_tools_path,
)
from vulnforge.ui.app import create_app


@pytest.fixture
def defaults_path(tmp_path: Path):
    path = tmp_path / "default_tools.json"
    set_default_tools_path(path)
    yield path
    reset_default_tools_path_override()


def _names(stage: str, *, apply_defaults: bool = True) -> list[str]:
    tools = tool_schemas_for("code_static", stage, apply_defaults=apply_defaults)
    out: list[str] = []
    for t in tools:
        fn = (t.get("function") or {}) if isinstance(t, dict) else {}
        n = fn.get("name") if isinstance(fn, dict) else None
        if n:
            out.append(str(n))
    return out


def test_null_uses_builtin(defaults_path: Path):
    # Missing file → all null
    assert load_default_tools() == {
        "recon": None,
        "hunt": None,
        "develop_poc": None,
    }
    built_in = _names("hunt", apply_defaults=False)
    assert resolve_stage_tools("hunt", built_in) == built_in
    assert _names("hunt", apply_defaults=True) == built_in
    assert "submit_candidate" in built_in
    assert "read_file" in built_in


def test_custom_list_filters(defaults_path: Path):
    save_default_tools(
        {
            "hunt": ["read_file", "grep", "shell", "not_a_real_tool"],
            "recon": None,
            "develop_poc": None,
        }
    )
    built_in = _names("hunt", apply_defaults=False)
    resolved = resolve_stage_tools("hunt", built_in)
    assert "read_file" in resolved
    assert "grep" in resolved
    assert "shell" not in resolved
    assert "not_a_real_tool" not in resolved
    # Critical always kept
    for c in STAGE_CRITICAL_TOOLS["hunt"]:
        assert c in resolved

    names = _names("hunt", apply_defaults=True)
    assert "read_file" in names
    assert "grep" in names
    assert "list_dir" not in names
    assert "file_inventory" not in names
    assert "submit_candidate" in names
    assert "submit_none" in names


def test_critical_tools_kept_when_omitted(defaults_path: Path):
    save_default_tools({"hunt": ["read_file"]})
    resolved = resolve_stage_tools("hunt", _names("hunt", apply_defaults=False))
    assert "read_file" in resolved
    assert "submit_candidate" in resolved
    assert "submit_none" in resolved
    assert "list_hunt_profiles" in resolved
    assert "request_hunt" in resolved


def test_recon_and_develop_poc_defaults(defaults_path: Path):
    save_default_tools(
        {
            "recon": ["read_file", "grep"],
            "develop_poc": ["read_file"],
            "hunt": None,
        }
    )
    recon = resolve_stage_tools("recon", _names("recon", apply_defaults=False))
    assert "read_file" in recon
    assert "grep" in recon
    assert "submit_architecture" in recon
    assert "list_dir" not in recon

    poc = resolve_stage_tools("develop_poc", _names("develop_poc", apply_defaults=False))
    assert "read_file" in poc
    assert "write_evidence" in poc
    assert "list_dir" not in poc


def test_empty_after_filter_falls_back(defaults_path: Path):
    save_default_tools({"hunt": ["shell", "not_real"]})
    built_in = _names("hunt", apply_defaults=False)
    # Only critical may remain; if nothing from list matches, fall back to full built-in
    # (after force-add critical from empty filtered list — if only critical, keep those)
    resolved = resolve_stage_tools("hunt", built_in)
    # shell dropped; critical forced in → non-empty selected → not full fallback
    # but critical-only is OK
    for c in STAGE_CRITICAL_TOOLS["hunt"]:
        assert c in resolved
    assert "shell" not in resolved


def test_catalog_ignores_defaults(defaults_path: Path):
    save_default_tools({"hunt": ["read_file"]})
    full = set(_names("hunt", apply_defaults=False))
    narrowed = set(_names("hunt", apply_defaults=True))
    assert "list_dir" in full
    assert "list_dir" not in narrowed
    # catalog path uses apply_defaults=False
    from vulnforge.toolgen.catalog import list_tools

    names = {t["name"] for t in list_tools()}
    assert "list_dir" in names
    assert "read_file" in names


def test_api_get_put_defaults(tmp_path: Path, defaults_path: Path):
    app = create_app(runs_root=tmp_path / "runs")
    with TestClient(app) as client:
        g = client.get("/api/tools/defaults")
        assert g.status_code == 200, g.text
        data = g.json()
        assert data["ok"]
        assert data["defaults"]["hunt"] is None
        assert "read_file" in data["builtin"]["hunt"]
        assert "submit_candidate" in data["effective"]["hunt"]

        put = client.put(
            "/api/tools/defaults",
            json={"hunt": ["read_file", "grep", "shell"]},
        )
        assert put.status_code == 200, put.text
        saved = put.json()["defaults"]
        assert "read_file" in saved["hunt"]
        assert "grep" in saved["hunt"]
        assert "shell" not in (saved["hunt"] or [])
        # critical forced into saved list
        assert "submit_candidate" in saved["hunt"]

        g2 = client.get("/api/tools/defaults")
        assert g2.json()["defaults"]["hunt"] is not None
        assert "list_dir" not in g2.json()["effective"]["hunt"]

        # reset
        r = client.put(
            "/api/tools/defaults",
            json={"recon": None, "hunt": None, "develop_poc": None},
        )
        assert r.status_code == 200
        assert r.json()["defaults"]["hunt"] is None


def test_no_shell_in_code_static_defaults(defaults_path: Path):
    save_default_tools({"hunt": ["shell", "bash", "exec", "read_file"]})
    cfg = load_default_tools()
    for blocked in ("shell", "bash", "exec"):
        assert blocked not in (cfg["hunt"] or [])
    names = _names("hunt")
    for blocked in ("shell", "bash", "exec"):
        assert blocked not in names
