"""API + snapshot coverage for first-class codemap."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from vulnforge.db import Database
from vulnforge.tools.codemap import build_codemap
from vulnforge.ui.app import create_app
from vulnforge.ui.store import RunRef, run_snapshot


def _make_run(runs_root: Path, target: Path) -> RunRef:
    target_id = "toy"
    run_id = "run-001"
    run = runs_root / target_id / run_id
    run.mkdir(parents=True)
    (run / "evidence").mkdir()
    (run / "project").mkdir()
    db = Database.create(run / "harness.db")
    db.insert_run(
        run_id,
        target_path=str(target.resolve()),
        profile="code_static",
        prompt_pin="test",
        config={"run": {"ignore_globs": []}},
    )
    cm = build_codemap(target, cfg={"run": {"ignore_globs": []}})
    db.set_codemap(cm, source="mechanical")
    db.close()
    return RunRef(target_id=target_id, run_id=run_id, path=run.resolve())


def test_api_codemap_get_and_rebuild(tmp_path: Path, toy_sqli: Path):
    runs_root = tmp_path / "runs"
    ref = _make_run(runs_root, toy_sqli)
    app = create_app(runs_root=runs_root)
    client = TestClient(app)
    base = f"/api/runs/{ref.target_id}/{ref.run_id}"

    r = client.get(f"{base}/codemap")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("has_codemap") is True
    assert isinstance(body.get("codemap"), dict)
    assert isinstance(body.get("summary"), dict)
    assert (body["summary"].get("module_count") or 0) >= 0
    # Architecture must still be independent
    arch = client.get(f"{base}/architecture")
    assert arch.status_code == 200
    assert arch.json().get("architecture") is None

    # Rebuild preserves architecture (still none) and refreshes codemap
    rb = client.post(f"{base}/codemap/rebuild")
    assert rb.status_code == 200, rb.text
    out = rb.json()
    assert out.get("ok") is True
    assert out.get("has_codemap") is True
    assert isinstance(out.get("codemap"), dict)

    arch2 = client.get(f"{base}/architecture")
    assert arch2.status_code == 200
    assert arch2.json().get("architecture") is None


def test_run_snapshot_includes_codemap(tmp_path: Path, toy_sqli: Path):
    runs_root = tmp_path / "runs"
    ref = _make_run(runs_root, toy_sqli)
    snap = run_snapshot(ref)
    assert "codemap" in snap
    assert "codemap_summary" in snap
    assert snap.get("has_codemap") is True
    assert isinstance(snap["codemap_summary"], dict)
    assert snap["codemap_summary"].get("has_codemap") is True
