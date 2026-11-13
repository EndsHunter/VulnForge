"""vulnforge/architecture@2 normalizer, citation validator and merge."""

from __future__ import annotations

import json
from pathlib import Path

from vulnforge.architecture_schema import (
    MAX_COMPONENTS,
    MAX_RELATIONS,
    SCHEMA_V2,
    ZONE_KINDS,
    merge_v2,
    normalize_architecture_v2,
    validate_citations,
)

V1 = {
    "summary": "Toy invoice app",
    "trust_boundaries": ["internet -> app"],
    "components": [
        {"name": "api/invoices", "path_hints": ["app.py"], "description": "Invoice CRUD"},
        {"name": "DB", "path_hints": []},
        "worker",
    ],
    "input_surfaces": ["GET /invoices/search?q"],
    "hunt_focus": [{"area": "api/invoices", "class": "injection", "path_hints": ["app.py"]}],
    "relations": [
        {"from": "API/Invoices", "to": "db", "kind": "uses", "note": "SQL"},
        {"from": "api/invoices", "to": "ghost", "kind": "weird"},
    ],
}

V2 = {
    "schema": SCHEMA_V2,
    "summary": "x",
    "zones": [
        {"id": "internet", "label": "Internet-facing", "kind": "internet"},
        {"id": "core", "label": "Core", "kind": "private"},
    ],
    "components": [
        {
            "id": "api-invoices",
            "name": "api/invoices",
            "kind": "http_router",
            "zone": "Internet-facing",
            "path_hints": ["app.py"],
            "entrypoints": [{"label": "GET /invoices/search", "path": "app.py", "line": 40}],
            "sinks": [{"kind": "sql", "path": "app.py", "line": 52}],
        },
        {"id": "db", "name": "Database", "zone": "core"},
    ],
    "boundaries": [
        {"from_zone": "internet", "to_zone": "core", "control": "login_required", "path": "auth.py", "line": 18}
    ],
    "relations": [
        {"from": "api/invoices", "to": "Database", "kind": "db", "evidence": "app.py:52"},
    ],
    "flows": [
        {
            "id": "f1",
            "title": "search -> SQL",
            "source": {"component": "API/Invoices", "label": "GET /invoices/search?q", "path": "app.py", "line": 40},
            "steps": [{"component": "api-invoices", "path": "app.py", "line": 47, "note": "concat"}],
            "sink": {"component": "Database", "kind": "sql", "path": "app.py", "line": 52},
            "crosses": ["internet", "core"],
            "classes": ["Injection"],
            "confidence": "cited",
        }
    ],
}


def test_normalize_v1_to_v2_shape():
    out = normalize_architecture_v2(V1)
    assert out["schema"] == SCHEMA_V2
    for key in ("zones", "components", "boundaries", "relations", "flows"):
        assert isinstance(out[key], list)
    ids = [c["id"] for c in out["components"]]
    assert ids == ["api-invoices", "db", "worker"]
    api = out["components"][0]
    assert api["role"] == "Invoice CRUD"
    assert api["origin"] == "recon"
    assert set(api) >= {"id", "name", "kind", "zone", "role", "path_hints", "entrypoints", "sinks", "origin"}
    # v1 fields kept
    assert out["summary"] == "Toy invoice app"
    assert out["trust_boundaries"] == ["internet -> app"]
    assert out["input_surfaces"] == ["GET /invoices/search?q"]
    assert out["hunt_focus"][0]["class"] == "injection"
    rels = out["relations"]
    # name → id resolution (case-insensitive); unknown kinds → related / synonyms
    assert rels[0]["from"] == "api-invoices" and rels[0]["to"] == "db"
    assert rels[0]["kind"] == "depends_on"
    assert rels[0]["confidence"] == "inferred"
    # Unknown endpoint is kept as-is in normalize (merge drops it)
    assert rels[1]["to"] == "ghost" and rels[1]["kind"] == "related"


def test_normalize_v2_resolution_and_zones():
    out = normalize_architecture_v2(V2)
    zones = {z["id"]: z for z in out["zones"]}
    assert zones["core"]["kind"] == "internal"
    assert all(z["kind"] in ZONE_KINDS for z in out["zones"])
    comps = {c["id"]: c for c in out["components"]}
    assert comps["api-invoices"]["zone"] == "internet"  # label → id
    assert comps["db"]["zone"] == "core"
    rel = out["relations"][0]
    assert (rel["from"], rel["to"]) == ("api-invoices", "db")
    assert rel["evidence"] == {"path": "app.py", "line": 52}
    flow = out["flows"][0]
    assert flow["source"]["component"] == "api-invoices"
    assert flow["sink"]["component"] == "db"
    assert flow["classes"] == ["injection"]
    assert flow["confidence"] == "cited"
    assert out["boundaries"][0]["line"] == 18


def test_normalize_idempotent():
    for src in (V1, V2):
        once = normalize_architecture_v2(src)
        twice = normalize_architecture_v2(once)
        assert once == twice


def test_normalize_junk_never_raises():
    junk_inputs = [
        None,
        "nope",
        42,
        [],
        {"components": "not a list", "relations": 5, "flows": [None, 1, "x"]},
        {"components": [None, {}, {"name": ""}, 7, ["a"]], "zones": [{}, None, 3]},
        {"relations": [{"from": "", "to": "x"}, {"from": "a", "to": "a"}]},
        {"flows": [{"id": "f", "steps": "zz"}, {}], "summary": {"x": 1}},
        {"components": json.dumps([{"name": "Encoded"}])},
    ]
    for j in junk_inputs:
        out = normalize_architecture_v2(j)
        assert out["schema"] == SCHEMA_V2
        assert isinstance(out["components"], list)
    enc = normalize_architecture_v2({"components": json.dumps([{"name": "Encoded"}])})
    assert enc["components"][0]["id"] == "encoded"
    assert normalize_architecture_v2({"relations": [{"from": "a", "to": "a"}]})["relations"] == []


def test_normalize_caps():
    big = {
        "summary": "s" * 20000,
        "components": [{"name": f"c{i}", "role": "r" * 5000} for i in range(500)],
        "relations": [{"from": f"c{i}", "to": f"c{i + 1}", "kind": "calls"} for i in range(500)],
    }
    out = normalize_architecture_v2(big)
    assert len(out["components"]) == MAX_COMPONENTS
    assert len(out["relations"]) == MAX_RELATIONS
    assert len(out["summary"]) <= 8000
    assert all(len(c["role"]) <= 400 for c in out["components"])


def test_validate_citations(tmp_path: Path):
    (tmp_path / "app.py").write_text("\n".join(f"line {i}" for i in range(1, 61)) + "\n")
    outside = tmp_path.parent / "secret.py"
    outside.write_text("x\n" * 100)
    arch = {
        "components": [{"name": "api"}, {"name": "db"}],
        "relations": [
            {"from": "api", "to": "db", "kind": "db", "evidence": {"path": "app.py", "line": 52}},
            {"from": "db", "to": "api", "kind": "calls", "evidence": {"path": "app.py", "line": 999}},
            {"from": "api", "to": "db", "kind": "calls", "evidence": {"path": "../secret.py", "line": 1}},
            {"from": "api", "to": "db", "kind": "imports", "confidence": "mechanical",
             "evidence": {"path": "app.py", "line": 5000}},
            {"from": "db", "to": "api", "kind": "queue", "evidence": {"path": str(outside), "line": 1}},
        ],
        "flows": [
            {"id": "good", "source": {"component": "api", "path": "app.py", "line": 40},
             "steps": [{"path": "app.py", "line": 47}], "sink": {"path": "app.py", "line": 52}},
            {"id": "bad", "source": {"path": "app.py", "line": 40},
             "steps": [{"path": "app.py", "line": 470}], "confidence": "cited"},
            {"id": "uncited", "steps": [{"note": "trust me"}], "confidence": "cited"},
        ],
    }
    report: dict = {}
    out = validate_citations(arch, tmp_path, report=report)
    r = out["relations"]
    assert r[0]["confidence"] == "cited"
    assert r[1]["confidence"] == "inferred" and "line" not in r[1]["evidence"]
    assert r[1]["evidence"].get("path") == "app.py"
    assert r[2]["confidence"] == "inferred" and r[2]["evidence"] == {}  # escape removed
    assert r[3]["confidence"] == "mechanical"  # mechanical stays mechanical
    assert r[4]["confidence"] == "inferred" and r[4]["evidence"] == {}  # absolute path
    flows = {f["id"]: f for f in out["flows"]}
    assert flows["good"]["confidence"] == "cited"
    assert flows["bad"]["confidence"] == "inferred"
    assert "line" not in flows["bad"]["steps"][0]
    assert flows["uncited"]["confidence"] == "inferred"
    assert report["valid"] >= 4 and report["invalid"] >= 4
    # input untouched (read-only, copy semantics)
    assert arch["relations"][1]["evidence"]["line"] == 999


def test_validate_citations_symlink_escape(tmp_path: Path):
    root = tmp_path / "t"
    root.mkdir()
    secret = tmp_path / "secret.py"
    secret.write_text("a\nb\n")
    try:
        (root / "link.py").symlink_to(secret)
    except OSError:
        return
    out = validate_citations(
        {"components": ["a", "b"], "relations": [
            {"from": "a", "to": "b", "evidence": {"path": "link.py", "line": 1}}]},
        root,
    )
    assert out["relations"][0]["confidence"] == "inferred"


def test_merge_v2_dedupe_and_origin_upgrade():
    base = {
        "schema": SCHEMA_V2,
        "origin": "mechanical",
        "components": [
            {"id": "packages-api", "name": "packages/api", "origin": "mechanical",
             "zone": "internet", "zone_source": "heuristic", "path_hints": ["packages/api"],
             "sinks": [{"kind": "sql", "path": "packages/api/routes.py", "line": 8}]},
            {"id": "datastore", "name": "datastore", "origin": "mechanical", "zone": "internal"},
        ],
        "relations": [
            {"from": "packages-api", "to": "datastore", "kind": "db", "confidence": "mechanical",
             "evidence": {"path": "packages/api/routes.py", "line": 8}},
        ],
    }
    newer = {
        "summary": "Recon summary",
        "components": [
            {"name": "Packages/API", "role": "HTTP API", "zone": "authenticated",
             "path_hints": ["packages/api/routes.py"],
             "sinks": [{"kind": "sql", "path": "packages/api/routes.py", "line": 8}]},
            {"name": "Billing", "path_hints": ["billing"]},
        ],
        "relations": [
            {"from": "packages/api", "to": "DATASTORE", "kind": "db", "confidence": "inferred", "note": "SQL"},
            {"from": "billing", "to": "nowhere", "kind": "calls"},
        ],
        "flows": [
            {"id": "f1", "source": {"component": "packages-api", "path": "x.py", "line": 1},
             "sink": {"component": "datastore"}, "steps": [{"component": "ghost", "path": "x.py", "line": 2}]},
            {"id": "f2", "source": {"component": "ghost"}, "sink": {"kind": "sql"}},
            {"id": "f3", "source": {"label": "cli arg"}, "sink": {"kind": "exec"}},
        ],
    }
    out = merge_v2(base, newer)
    assert out["origin"] == "recon"
    assert out["summary"] == "Recon summary"
    comps = {c["id"]: c for c in out["components"]}
    assert list(comps) == ["packages-api", "datastore", "billing"]
    api = comps["packages-api"]
    assert api["origin"] == "recon"
    assert api["role"] == "HTTP API"
    assert api["zone"] == "authenticated" and api["zone_source"] == "recon"
    assert api["path_hints"] == ["packages/api", "packages/api/routes.py"]
    assert len(api["sinks"]) == 1  # union deduped
    assert comps["datastore"]["origin"] == "mechanical"
    rels = out["relations"]
    assert len(rels) == 1  # deduped + unknown endpoint dropped
    assert rels[0]["confidence"] == "mechanical" and rels[0]["note"] == "SQL"
    flows = {f["id"]: f for f in out["flows"]}
    assert set(flows) == {"f1", "f3"}  # f2's unknown source component dropped
    assert "component" not in flows["f1"]["steps"][0]
    # deterministic
    assert merge_v2(base, newer) == out


def test_merge_mechanical_refresh_does_not_overwrite_recon():
    recon = {"components": [{"id": "api", "name": "api", "role": "Recon role", "zone": "internet"}]}
    mech = {"origin": "mechanical", "components": [
        {"id": "api", "name": "api", "role": "Mechanical: 2 files", "zone": "internal",
         "origin": "mechanical", "path_hints": ["api"]}]}
    out = merge_v2(recon, mech)
    c = out["components"][0]
    assert c["role"] == "Recon role" and c["zone"] == "internet"
    assert c["path_hints"] == ["api"]
    assert out["origin"] == "recon"


def test_merge_self_is_normalize():
    n = normalize_architecture_v2(V2)
    m = merge_v2(V2, V2)
    m.pop("origin", None)
    # merge marks recon-assigned zones; otherwise identical to normalize
    for c in m["components"]:
        assert c.pop("zone_source", "recon") == "recon"
    assert m == n
