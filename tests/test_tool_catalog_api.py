"""API tests for tools catalog, hunt tools allowlist, tool drafts."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vulnforge.hunt_profiles import ensure_collection, reset_collection_root_override, set_collection_root
from vulnforge.packet import pack_hunt, tool_schemas_for
from vulnforge.toolgen.catalog import list_tools
from vulnforge.toolgen.store import reset_drafts_root_override, set_drafts_root
from vulnforge.ui.app import create_app


@pytest.fixture
def client(tmp_path: Path):
    set_collection_root(tmp_path / "hunt_profiles")
    ensure_collection()
    set_drafts_root(tmp_path / "tool_drafts")
    app = create_app(runs_root=tmp_path / "runs")
    with TestClient(app) as c:
        yield c
    reset_collection_root_override()
    reset_drafts_root_override()


def test_list_tools_api(client: TestClient):
    r = client.get("/api/tools")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"]
    names = {t["name"] for t in data["tools"]}
    assert "read_file" in names
    assert "grep" in names
    detail = client.get("/api/tools/read_file")
    assert detail.status_code == 200
    tool = detail.json()["tool"]
    assert "path" in (tool.get("parameters") or {}).get("properties", {})
    assert "hunt" in tool.get("stages", [])


def test_catalog_module_lists_params():
    tools = list_tools()
    grep = next(t for t in tools if t["name"] == "grep")
    assert grep["description"]
    assert "pattern" in grep["parameters"]["properties"]


def test_hunt_profile_tools_allowlist(client: TestClient, tmp_path: Path):
    # Create profile with restricted tools
    r = client.post(
        "/api/hunt-profiles",
        json={
            "id": "tools-test",
            "title": "Tools test",
            "active": False,
            "body_md": "# Hunt class: tools-test\n\n## Mission\n\nx\n\n## Method\n\n1.\n\n## Submit\n\n- ok\n",
            "tools": ["read_file", "grep"],
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["profile"]["tools"] == ["read_file", "grep"]

    g = client.get("/api/hunt-profiles/tools-test")
    assert g.json()["profile"]["tools"] == ["read_file", "grep"]

    # pack_hunt should filter
    from vulnforge.cli import PROJECT_ROOT

    cfg = {"packet": {}, "llm": {}}
    prompts = PROJECT_ROOT / "prompts" / "v1"
    pkt = pack_hunt(
        cfg,
        prompts,
        {"class": "tools-test", "area": "x", "path_hints": []},
        architecture="arch",
        known_keys=[],
        codemap_notes=[],
    )
    names = {
        (t.get("function") or {}).get("name")
        for t in (pkt.tools_schema or [])
    }
    # always keep submit_*
    assert "submit_candidate" in names
    assert "submit_none" in names
    assert "read_file" in names
    assert "grep" in names
    assert "list_dir" not in names
    assert "file_inventory" not in names

    # clear tools
    u = client.put(
        "/api/hunt-profiles/tools-test",
        json={"clear_tools": True},
    )
    assert u.status_code == 200
    assert u.json()["profile"]["tools"] is None


def test_tool_draft_crud(client: TestClient):
    r = client.post(
        "/api/tool-drafts",
        json={
            "brief": "Need a symbol lookup without thrashing grep",
            "suggested_id": "ast_query",
            "stages": ["hunt"],
            "risk_class": "read_only",
        },
    )
    assert r.status_code == 200, r.text
    did = r.json()["draft"]["id"]
    assert did == "ast_query"

    g = client.get(f"/api/tool-drafts/{did}")
    assert g.status_code == 200
    assert g.json()["draft"]["brief"]["brief"]

    u = client.put(
        f"/api/tool-drafts/{did}",
        json={
            "spec_md": "# Tool: ast_query\n## Purpose\nFind symbols.\n",
            "slots": {"problem_statement": "symbol lookup"},
        },
    )
    assert u.status_code == 200

    prev = client.post(
        f"/api/tool-drafts/{did}/prompts/preview",
        json={"stage": "spec"},
    )
    assert prev.status_code == 200
    assert "system" in prev.json()
    assert "user" in prev.json()

    v = client.post(f"/api/tool-drafts/{did}/validate")
    assert v.status_code == 200
    assert v.json()["validation"]["ok"] is False  # no impl yet

    exp = client.get(f"/api/tool-drafts/{did}/export")
    assert exp.status_code == 200
    assert exp.json()["format"] == "vulnforge.tool_draft/v1"

    d = client.delete(f"/api/tool-drafts/{did}")
    assert d.status_code == 200


def test_from_gap(client: TestClient):
    r = client.post(
        "/api/tool-drafts/from-gap",
        json={
            "gap": {
                "tool_or_capability": "wishlist:http_fetch",
                "suggestion": "Need HTTP fetch for docs",
                "severity": "medium",
            },
            "brief": "",
        },
    )
    assert r.status_code == 200, r.text
    draft = r.json()["draft"]
    assert draft["meta"]["source"] == "tool_gap"
    assert "http_fetch" in draft["id"]


def test_dev_page_has_tools_tab(client: TestClient):
    r = client.get("/dev")
    assert r.status_code == 200
    assert "Tools" in r.text
    assert "toolgen-wizard-modal" in r.text
    assert "Approved tools" in r.text


def test_filter_empty_allowlist_keeps_full_set():
    tools = tool_schemas_for("code_static", "hunt")
    from vulnforge.packet import _filter_tools_by_allowlist, HUNT_ALWAYS_KEEP_TOOLS

    filtered = _filter_tools_by_allowlist(tools, None, always_keep=HUNT_ALWAYS_KEEP_TOOLS)
    assert len(filtered) == len(tools)
