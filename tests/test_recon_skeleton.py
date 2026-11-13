"""R0 mechanical skeleton: fixtures, determinism, init hook, snapshot."""

from __future__ import annotations

from pathlib import Path

from vulnforge.architecture_schema import SCHEMA_V2, ZONE_KINDS, normalize_architecture_v2
from vulnforge.cli import EXIT_PROGRESS, main
from vulnforge.db import Database
from vulnforge.recon_skeleton import (
    SKELETON_FILENAME,
    build_skeleton,
    build_skeleton_for_target,
    read_skeleton,
)
from vulnforge.tools.codemap import build_codemap
from vulnforge.tools.sink_preindex import build_sink_preindex
from vulnforge.ui.store import RunRef, run_snapshot

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
MONO = FIXTURES / "mono_synth"


def _skel(target: Path) -> dict:
    cm = build_codemap(target)
    sinks = build_sink_preindex(target)
    return build_skeleton(cm, sinks, None, target)


def _check_common(s: dict) -> None:
    assert s["schema"] == SCHEMA_V2
    assert s["origin"] == "mechanical"
    assert s["summary"] == ""
    assert s["flows"] == []
    used = {c["zone"] for c in s["components"]}
    assert {z["id"] for z in s["zones"]} == used
    for z in s["zones"]:
        assert z["kind"] in ZONE_KINDS
    for c in s["components"]:
        assert c["origin"] == "mechanical"
        assert c["zone"] in ZONE_KINDS
        assert c["zone_source"] == "heuristic"
    for r in s["relations"]:
        assert r["confidence"] == "mechanical"
    ids = {c["id"] for c in s["components"]}
    for r in s["relations"]:
        assert r["from"] in ids and r["to"] in ids
    assert len(s["components"]) <= 24
    # Already normalized (stable through the schema normalizer)
    norm = normalize_architecture_v2(s)
    assert norm["components"] == s["components"]
    assert norm["relations"] == s["relations"]


def test_skeleton_toy_sqli(toy_sqli: Path):
    s = _skel(toy_sqli)
    _check_common(s)
    comps = {c["id"]: c for c in s["components"]}
    assert "app" in comps
    app = comps["app"]
    assert app["path_hints"] == ["app.py"]
    assert {(x["kind"], x["line"]) for x in app["sinks"]} >= {("sql", 11), ("sql", 12)}
    assert "datastore" in comps
    db_rel = [r for r in s["relations"] if r["kind"] == "db"]
    assert db_rel and db_rel[0]["from"] == "app" and db_rel[0]["evidence"]["path"] == "app.py"


def test_skeleton_mono_synth():
    s = _skel(MONO)
    _check_common(s)
    comps = {c["id"]: c for c in s["components"]}
    for cid in ("packages-api", "packages-auth", "packages-ui", "packages-worker"):
        assert cid in comps
    assert "packages" not in comps  # pure container collapsed
    assert comps["packages-api"]["zone"] == "internet"
    assert comps["packages-auth"]["zone"] == "authenticated"
    assert comps["packages-worker"]["zone"] == "internal"
    kinds = {x["kind"] for x in comps["packages-worker"]["sinks"]}
    assert "exec" in kinds


def test_skeleton_deterministic(toy_sqli: Path):
    assert _skel(MONO) == _skel(MONO)
    assert _skel(toy_sqli) == _skel(toy_sqli)


def test_skeleton_routes_auth_imports_http(tmp_path: Path):
    t = tmp_path / "svc"
    (t / "web").mkdir(parents=True)
    (t / "admin").mkdir()
    (t / "core").mkdir()
    (t / "web" / "__init__.py").write_text("")
    (t / "web" / "views.py").write_text(
        "from core import store\n"
        "import requests\n\n"
        "@app.route('/search')\n"
        "def search():\n"
        "    return store.find(request.args['q'])\n\n"
        "@app.get('/fetch')\n"
        "def fetch():\n"
        "    return requests.get(request.args['u']).text\n"
    )
    (t / "admin" / "__init__.py").write_text("")
    (t / "admin" / "panel.py").write_text(
        "from core import store\n\n"
        "@bp.route('/admin')\n"
        "@login_required\n"
        "def admin():\n"
        "    return store.all()\n"
    )
    (t / "core" / "__init__.py").write_text("")
    (t / "core" / "store.py").write_text(
        "def find(q):\n    return cursor.execute(f\"SELECT * FROM t WHERE q='{q}'\")\n"
    )
    s = _skel(t)
    _check_common(s)
    comps = {c["id"]: c for c in s["components"]}
    assert comps["web"]["zone"] == "internet"
    labels = {e["label"] for e in comps["web"]["entrypoints"]}
    assert "/search" in labels
    assert "GET /fetch" in labels
    assert comps["admin"]["zone"] == "authenticated"
    assert any(b["control"] == "login_required" and b["line"] == 4 for b in s["boundaries"])
    rel = {(r["from"], r["to"], r["kind"]): r for r in s["relations"]}
    imp = rel.get(("web", "core", "imports"))
    assert imp is not None
    assert imp["evidence"]["path"] == "web/views.py" and imp["evidence"]["line"] == 1
    assert ("admin", "core", "imports") in rel
    assert ("web", "external-http", "http_out") in rel
    assert comps["external-http"]["zone"] == "external"
    assert ("core", "datastore", "db") in rel


def test_skeleton_single_file_target(tmp_path: Path):
    f = tmp_path / "lonely.py"
    f.write_text("import os\nos.system(input())\n")
    s = build_skeleton_for_target(f, {})
    _check_common(s)
    assert [c["id"] for c in s["components"]] == ["lonely"]
    assert s["components"][0]["sinks"][0]["line"] == 2


def test_skeleton_junk_inputs():
    s = build_skeleton(None, None, None, None)
    assert s["schema"] == SCHEMA_V2 and s["components"] == []
    s = build_skeleton({"modules": "x", "edges": [1, None]}, [{"bad": 1}, None], {"x": 1}, None)
    assert s["components"] == []


def test_init_stores_skeleton_and_keeps_architecture_empty(toy_sqli: Path, tmp_path: Path):
    runs = tmp_path / "runs"
    code = main(["init", "--target", str(toy_sqli), "--runs-root", str(runs)])
    assert code == EXIT_PROGRESS
    run_dir = next(next(runs.iterdir()).iterdir())
    assert (run_dir / SKELETON_FILENAME).is_file()
    skel = read_skeleton(run_dir)
    assert skel and skel["origin"] == "mechanical"
    assert any(c["id"] == "app" for c in skel["components"])
    db = Database.open(run_dir / "harness.db")
    try:
        assert db.get_architecture() is None
        card = db.summary().get("run") or {}
        assert not card.get("has_architecture")
    finally:
        db.close()
    ref = RunRef(target_id=run_dir.parent.name, run_id=run_dir.name, path=run_dir.resolve())
    snap = run_snapshot(ref)
    assert snap["architecture"] is None
    assert snap["architecture_summary"].get("has_architecture") is False
    assert snap["architecture_skeleton"]["origin"] == "mechanical"


def _bare_run(runs_root: Path, target: Path) -> RunRef:
    run = runs_root / "toy" / "run-001"
    run.mkdir(parents=True)
    (run / "evidence").mkdir()
    db = Database.create(run / "harness.db")
    db.insert_run("run-001", str(target.resolve()), "code_static", "pin", {"run": {}})
    return RunRef(target_id="toy", run_id="run-001", path=run.resolve()), db


def test_snapshot_lazily_builds_skeleton_for_old_runs(tmp_path: Path, toy_sqli: Path):
    ref, db = _bare_run(tmp_path / "runs", toy_sqli)
    db.set_codemap(build_codemap(toy_sqli), source="mechanical")
    db.close()
    assert not (ref.path / SKELETON_FILENAME).exists()
    snap = run_snapshot(ref)
    sk = snap["architecture_skeleton"]
    assert sk and sk["schema"] == SCHEMA_V2
    assert (ref.path / SKELETON_FILENAME).is_file()  # cached
    assert snap["architecture"] is None


def test_snapshot_without_codemap_has_null_skeleton(tmp_path: Path, toy_sqli: Path):
    ref, db = _bare_run(tmp_path / "runs", toy_sqli)
    db.close()
    snap = run_snapshot(ref)
    assert snap["architecture_skeleton"] is None


def test_snapshot_v2_passthrough_and_v1_unchanged(tmp_path: Path, toy_sqli: Path):
    ref, db = _bare_run(tmp_path / "runs", toy_sqli)
    v2 = {
        "schema": SCHEMA_V2,
        "summary": "toy",
        "zones": [{"id": "internet", "kind": "internet", "label": "Internet-facing"}],
        "components": [
            {"id": "app", "name": "app", "zone": "internet", "kind": "http_router",
             "entrypoints": [{"label": "search", "path": "app.py", "line": 9}],
             "sinks": [{"kind": "sql", "path": "app.py", "line": 12}]},
            {"id": "db", "name": "db", "zone": "internet"},
        ],
        "relations": [{"from": "app", "to": "db", "kind": "db",
                       "evidence": {"path": "app.py", "line": 12}, "confidence": "cited"}],
        "flows": [{"id": "f1", "source": {"component": "app", "path": "app.py", "line": 9},
                   "sink": {"component": "db", "kind": "sql", "path": "app.py", "line": 12},
                   "steps": [], "classes": ["injection"], "confidence": "cited"}],
        "boundaries": [],
        "seed_sinks": [{"path": "app.py", "line": 12, "kind": "sql"}],
    }
    db.set_architecture(v2)
    db.close()
    snap = run_snapshot(ref)
    summ = snap["architecture_summary"]
    assert summ["schema"] == SCHEMA_V2
    assert summ["zones"][0]["id"] == "internet"
    comp = summ["components"][0]
    assert comp["id"] == "app" and comp["zone"] == "internet"
    assert comp["entrypoints"][0]["line"] == 9 and comp["sinks"][0]["kind"] == "sql"
    assert summ["relations"][0]["evidence"] == {"path": "app.py", "line": 12}
    assert summ["relations"][0]["confidence"] == "cited"
    assert summ["flows"][0]["id"] == "f1"
    assert snap["architecture"]["schema"] == SCHEMA_V2
    assert snap["architecture"]["seed_sinks"]  # extra keys preserved

    # v1 map: summary keeps the old shape (no schema key)
    ref2, db2 = _bare_run(tmp_path / "runs2", toy_sqli)
    db2.set_architecture({"summary": "v1", "components": [{"name": "app"}]})
    db2.close()
    snap2 = run_snapshot(ref2)
    assert "schema" not in snap2["architecture_summary"]
    assert snap2["architecture_summary"]["components"][0]["name"] == "app"


def test_codemap_rebuild_refreshes_skeleton(tmp_path: Path, toy_sqli: Path):
    from fastapi.testclient import TestClient

    from vulnforge.ui.app import create_app

    runs_root = tmp_path / "runs"
    ref, db = _bare_run(runs_root, toy_sqli)
    db.close()
    client = TestClient(create_app(runs_root=runs_root))
    r = client.post(f"/api/runs/{ref.target_id}/{ref.run_id}/codemap/rebuild")
    assert r.status_code == 200, r.text
    sk = read_skeleton(ref.path)
    assert sk and any(c["id"] == "app" for c in sk["components"])
    assert any(r["kind"] == "db" for r in sk["relations"])
    detail = client.get(f"/api/runs/{ref.target_id}/{ref.run_id}").json()
    assert detail["architecture_skeleton"]["origin"] == "mechanical"
    assert detail["architecture"] is None
