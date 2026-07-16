"""Tests for recon agent collection store + architecture merge."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnforge.recon_agents import (
    COLLECTION_FORMAT,
    ReconAgentError,
    active_agents,
    ensure_collection,
    export_collection,
    get_agent,
    get_body,
    import_collection,
    list_agents,
    reseed_from_package,
    reset_collection_root_override,
    save_agent,
    set_collection_root,
)
from vulnforge.stages.recon import merge_architectures


@pytest.fixture
def agents_root(tmp_path: Path):
    root = tmp_path / "recon_agents"
    set_collection_root(root)
    ensure_collection()
    yield root
    reset_collection_root_override()


def test_ensure_seeds_default_map(agents_root: Path):
    coll = ensure_collection()
    assert coll["format"] == COLLECTION_FORMAT
    ids = [a["id"] for a in coll["agents"]]
    assert "default-map" in ids
    assert "surface-mapper" in ids
    assert "dependency-risk" in ids
    assert "auth-model" in ids
    active = [a for a in coll["agents"] if a.get("active")]
    assert any(a["id"] == "default-map" for a in active)
    body = get_body("default-map")
    assert "submit_architecture" in body or "Mission" in body
    # Ordered
    orders = [a["order"] for a in coll["agents"]]
    assert orders == sorted(orders)


def test_active_agents_filter(agents_root: Path):
    save_agent("surface-mapper", active=True)
    active = active_agents()
    ids = [a["id"] for a in active]
    assert "default-map" in ids
    assert "surface-mapper" in ids
    # Filter by agent_ids ignores active flag and preserves request order
    filtered = active_agents(agent_ids=["auth-model", "default-map"])
    assert [a["id"] for a in filtered] == ["auth-model", "default-map"]


def test_save_and_export_import(agents_root: Path):
    a = save_agent(
        "custom-recon",
        body_md="# Recon agent: custom-recon\n\n**Mission:** test\n",
        title="Custom",
        active=True,
        order=15,
        temperature=0.2,
        max_tool_rounds=8,
        tools=["read_file", "grep"],
        create=True,
    )
    assert a["id"] == "custom-recon"
    assert a["order"] == 15
    assert a["temperature"] == 0.2
    assert a["tools"] == ["read_file", "grep"]
    assert get_agent("custom-recon")["body_md"]

    blob = export_collection()
    assert blob["format"] == COLLECTION_FORMAT
    assert any(x["id"] == "custom-recon" for x in blob["agents"])

    # Merge re-import
    r = import_collection(blob, mode="merge")
    assert r["ok"]
    assert "custom-recon" in r["agents"]


def test_cannot_delete_last(agents_root: Path):
    agents = list_agents()
    # Delete all but one
    for a in agents[1:]:
        from vulnforge.recon_agents import delete_agent

        delete_agent(a["id"])
    remaining = list_agents()
    assert len(remaining) == 1
    with pytest.raises(ReconAgentError, match="last"):
        from vulnforge.recon_agents import delete_agent

        delete_agent(remaining[0]["id"])


def test_reseed(agents_root: Path):
    save_agent(
        "tmp-agent",
        body_md="# tmp\n\nbody\n",
        create=True,
        active=False,
    )
    r = reseed_from_package(replace=True)
    assert r["ok"]
    ids = set(r["agents"])
    assert "default-map" in ids
    assert "tmp-agent" not in ids


def test_merge_architectures_lists_and_summary():
    a1 = {
        "summary": "First map",
        "trust_boundaries": ["public/private"],
        "components": [{"name": "api", "path_hints": ["api/"]}],
        "input_surfaces": ["HTTP"],
        "hunt_focus": [{"area": "api", "class": "injection", "path_hints": ["a.py"]}],
    }
    a2 = {
        "summary": "Auth refined",
        "trust_boundaries": ["user/admin", "public/private"],
        "components": [{"name": "auth", "path_hints": ["auth/"]}],
        "input_surfaces": ["CLI"],
        "hunt_focus": [
            {"area": "api", "class": "access-control", "path_hints": ["b.py"]}
        ],
    }
    m = merge_architectures([a1, a2], agents_run=[{"id": "default-map", "ok": True}])
    # Summaries concatenate unique paragraphs (not pure last-wins)
    assert "First map" in m["summary"]
    assert "Auth refined" in m["summary"]
    assert "public/private" in m["trust_boundaries"]
    assert "user/admin" in m["trust_boundaries"]
    names = {c["name"] for c in m["components"] if isinstance(c, dict)}
    assert names == {"api", "auth"}
    assert "HTTP" in m["input_surfaces"]
    assert "CLI" in m["input_surfaces"]
    assert len(m["hunt_focus"]) == 2
    assert m["recon_agents_run"][0]["id"] == "default-map"

    # Empty summary does not clobber prior paragraphs
    m2 = merge_architectures(
        [a2, {"summary": "", "components": [], "trust_boundaries": [], "input_surfaces": [], "hunt_focus": []}]
    )
    assert m2["summary"] == "Auth refined"


def test_pack_recon_agent_uses_body():
    from vulnforge.packet import pack_recon_agent

    cfg = {"llm": {"context_tokens": 8192, "max_context_fraction": 0.5}}
    packet = pack_recon_agent(
        cfg,
        Path("/Users/jonathankooy/Coding/AI/prompts/v1"),
        agent_body="# Recon agent: test\n\n**Mission:** unit\n",
        inventory={
            "file_count": 1,
            "extensions": {".py": 1},
            "entrypoints": ["app.py"],
            "sample_paths": ["app.py"],
        },
        tools_allowlist=["read_file", "list_dir"],
        agent_id="test",
    )
    assert "unit" in packet.user or "Mission" in packet.user
    assert "test" in packet.system
    names = {
        (t.get("function") or {}).get("name")
        for t in packet.tools_schema
        if isinstance(t, dict)
    }
    assert "submit_architecture" in names
    assert "read_file" in names
    # allowlist drops others except submit_architecture
    assert "write_evidence" not in names
