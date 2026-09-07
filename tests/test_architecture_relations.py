"""Ticket 3: additive architecture relations schema + persistence."""

from __future__ import annotations

from pathlib import Path

from vulnforge.agent_runtime.round_limit import architecture_from_content
from vulnforge.control import ops as dashops
from vulnforge.db import Database
from vulnforge.tools.agent import submit_architecture as sa_mod
from vulnforge.stages.recon import (
    merge_architectures,
    normalize_relations,
    parse_architecture,
    parse_architecture_merge_content,
)


def test_submit_architecture_spec_has_optional_relations():
    props = sa_mod.SPEC.parameters
    assert "relations" in props
    assert "summary" in sa_mod.SPEC.required
    assert "relations" not in (sa_mod.SPEC.required or ())
    items = props["relations"]["items"]
    assert set(items.get("required") or []) >= {"from", "to"}
    assert "kind" in items["properties"]
    assert "note" in items["properties"]


def test_normalize_relations_validates_and_dedupes():
    assert normalize_relations(None) == []
    assert normalize_relations("nope") == []
    assert normalize_relations([{"from": "A"}]) == []
    out = normalize_relations(
        [
            {"from": "API", "to": "Auth", "kind": "calls", "note": "api→auth"},
            {"from": "API", "to": "Auth", "kind": "calls"},  # dup
            {"from": " Auth ", "to": "DB", "kind": "", "note": "x" * 500},
            "string-ignored",
            {"from": "", "to": "X"},
        ]
    )
    assert len(out) == 2
    assert out[0] == {
        "from": "API",
        "to": "Auth",
        "kind": "calls",
        "note": "api→auth",
    }
    assert out[1]["from"] == "Auth"
    assert out[1]["to"] == "DB"
    assert out[1]["kind"] == "related"
    assert len(out[1]["note"]) == 400


def test_parse_architecture_persists_relations():
    session = {
        "architecture": {
            "summary": "toy",
            "components": [{"name": "API"}],
            "relations": [{"from": "API", "to": "DB", "kind": "data_flow"}],
        }
    }
    arch = parse_architecture(None, session)
    assert arch["summary"] == "toy"
    assert arch["relations"] == [
        {"from": "API", "to": "DB", "kind": "data_flow"}
    ]
    # Old maps without relations still work
    arch2 = parse_architecture(
        None, {"architecture": {"summary": "old", "components": []}}
    )
    assert arch2["relations"] == []
    assert arch2["summary"] == "old"


def test_architecture_from_content_keeps_relations():
    raw = """```json
{"summary":"svc","components":[{"name":"A"}],"relations":[{"from":"A","to":"B","kind":"depends_on"}]}
```"""
    parsed = architecture_from_content(raw)
    assert parsed is not None
    assert parsed["relations"][0]["from"] == "A"
    merged = parse_architecture_merge_content(raw)
    assert merged is not None
    assert merged["relations"][0]["kind"] == "depends_on"


def test_merge_architectures_unions_relations():
    a = {
        "summary": "one",
        "relations": [{"from": "API", "to": "Auth", "kind": "calls"}],
    }
    b = {
        "summary": "two",
        "relations": [
            {"from": "API", "to": "Auth", "kind": "calls", "note": "login"},
            {"from": "Auth", "to": "DB", "kind": "data_flow"},
        ],
    }
    m = merge_architectures([a, b])
    assert len(m["relations"]) == 2
    by = {(r["from"], r["to"], r["kind"]): r for r in m["relations"]}
    assert by[("API", "Auth", "calls")].get("note") == "login"
    assert ("Auth", "DB", "data_flow") in by


def test_db_stores_relations_with_architecture(tmp_path: Path):
    db = Database.create(tmp_path / "harness.db")
    db.insert_run(
        "run-001",
        target_path=str(tmp_path / "tgt"),
        profile="code_static",
        prompt_pin="pin",
        config={},
    )
    arch = {
        "summary": "map",
        "components": [{"name": "API", "path_hints": ["api/"]}],
        "relations": [
            {"from": "API", "to": "Auth", "kind": "trust_boundary", "note": "session"}
        ],
    }
    db.set_architecture(arch, source="recon")
    got = db.get_architecture()
    assert got["relations"][0]["kind"] == "trust_boundary"
    db.close()


def test_architecture_summary_includes_relations():
    s = dashops.architecture_summary(
        {
            "summary": "hello",
            "components": [{"name": "api"}],
            "relations": [{"from": "api", "to": "db", "kind": "calls"}],
        }
    )
    assert s["has_architecture"] is True
    assert s["relations"][0]["from"] == "api"
    empty = dashops.architecture_summary(None)
    assert empty["relations"] == []
