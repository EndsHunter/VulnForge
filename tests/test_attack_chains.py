"""PR-E: attack chain CRUD under evidence/chains/."""

from __future__ import annotations

from pathlib import Path

from vulnforge.chains import (
    build_chain_from_findings,
    chain_to_markdown,
    delete_chain,
    get_chain,
    list_chains,
    save_chain,
)
from vulnforge.db import Database
from vulnforge.ui import ops as dashops


def _setup(tmp_path: Path):
    run_dir = tmp_path / "run-001"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", str(tmp_path), "code_static", "pin", {})
    return run_dir, db


def _finding_body(title: str, **extra) -> dict:
    b = {
        "title": title,
        "summary": title,
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "user",
            "boundary": "api",
            "impact": "data",
        },
        "citations": [{"path": "app.py", "symbol": "f"}],
        "sink_path": "app.py",
        "sink_symbol": title.replace(" ", "_"),
    }
    b.update(extra)
    return b


def test_chain_file_crud(tmp_path: Path):
    run_dir = tmp_path / "run-001"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()

    doc = save_chain(
        run_dir,
        {
            "title": "Test chain",
            "include_states": ["confirmed"],
            "steps": [
                {"finding_id": 1, "role": "entry", "notes": "first", "poc_path": None},
                {"finding_id": 2, "role": "pivot", "notes": "", "poc_path": "poc.py"},
            ],
        },
    )
    assert doc["id"]
    assert (run_dir / "evidence" / "chains" / f"{doc['id']}.json").is_file()

    listed = list_chains(run_dir)
    assert len(listed) == 1
    assert listed[0]["title"] == "Test chain"
    assert len(listed[0]["steps"]) == 2

    got = get_chain(run_dir, doc["id"])
    assert got is not None
    assert got["steps"][0]["role"] == "entry"

    got["title"] = "Renamed"
    got["steps"] = list(reversed(got["steps"]))
    saved = save_chain(run_dir, got)
    assert saved["title"] == "Renamed"
    assert saved["steps"][0]["finding_id"] == 2
    assert saved["created_at"] == doc["created_at"]

    md = chain_to_markdown(saved)
    assert "Renamed" in md
    assert "disclaimer" in md.lower()
    assert "exploit proof" in md.lower()

    assert delete_chain(run_dir, doc["id"]) is True
    assert get_chain(run_dir, doc["id"]) is None
    assert list_chains(run_dir) == []


def test_build_chain_from_findings_filters_states(tmp_path: Path):
    run_dir, db = _setup(tmp_path)
    id_c = db.insert_finding(
        _finding_body("Confirmed issue"), state="confirmed", profile="code_static"
    )
    id_nh = db.insert_finding(
        _finding_body("Needs human issue"),
        state="needs_human",
        profile="code_static",
    )
    id_cand = db.insert_finding(
        _finding_body("Candidate issue"),
        state="candidate",
        profile="code_static",
    )
    findings = db.list_findings()
    db.close()

    chain = build_chain_from_findings(
        run_dir,
        include_states=["confirmed"],
        title="Conf only",
        findings=findings,
    )
    fids = [s["finding_id"] for s in chain["steps"]]
    assert fids == [id_c]

    chain2 = build_chain_from_findings(
        run_dir,
        include_states=["confirmed", "needs_human"],
        findings=findings,
    )
    fids2 = set(s["finding_id"] for s in chain2["steps"])
    assert fids2 == {id_c, id_nh}
    assert id_cand not in fids2


def test_build_chain_ops_selected_ids(tmp_path: Path):
    run_dir, db = _setup(tmp_path)
    a = db.insert_finding(
        _finding_body("A"), state="confirmed", profile="code_static"
    )
    b = db.insert_finding(
        _finding_body("B"), state="confirmed", profile="code_static"
    )
    db.insert_finding(
        _finding_body("C"), state="confirmed", profile="code_static"
    )
    db.close()

    r = dashops.build_chain_from_findings_op(
        run_dir,
        finding_ids=[b, a],  # preserve selection order intent via findings load
        include_states=["confirmed"],
        title="AB chain",
    )
    assert r["ok"] is True
    chain = r["chain"]
    assert chain["title"] == "AB chain"
    # filtered confirmed only; order follows finding_ids list
    assert [s["finding_id"] for s in chain["steps"]] == [b, a]
    assert "markdown" in r
    assert "Disclaimer" in r["markdown"] or "disclaimer" in r["markdown"].lower()

    listed = dashops.list_chains_op(run_dir)
    assert listed["count"] >= 1

    got = dashops.get_chain_op(run_dir, chain["id"])
    assert got["ok"] is True

    # reorder steps via save
    steps = list(reversed(got["chain"]["steps"]))
    saved = dashops.save_chain_op(
        run_dir,
        {
            "id": chain["id"],
            "title": "AB reversed",
            "include_states": ["confirmed"],
            "steps": steps,
        },
    )
    assert saved["ok"] is True
    assert [s["finding_id"] for s in saved["chain"]["steps"]] == [a, b]

    exp = dashops.export_chain_markdown_op(run_dir, chain["id"])
    assert exp["ok"] is True
    assert "AB reversed" in exp["markdown"]

    deleted = dashops.delete_chain_op(run_dir, chain["id"])
    assert deleted["ok"] is True
    assert dashops.get_chain_op(run_dir, chain["id"])["ok"] is False


def test_build_chain_no_match_returns_error(tmp_path: Path):
    run_dir, db = _setup(tmp_path)
    db.insert_finding(
        _finding_body("Only candidate"),
        state="candidate",
        profile="code_static",
    )
    db.close()
    r = dashops.build_chain_from_findings_op(
        run_dir, include_states=["confirmed"]
    )
    assert r["ok"] is False
    assert "no findings" in (r.get("error") or "").lower()


def test_chain_never_changes_finding_state(tmp_path: Path):
    run_dir, db = _setup(tmp_path)
    fid = db.insert_finding(
        _finding_body("NH"), state="needs_human", profile="code_static"
    )
    db.close()
    r = dashops.build_chain_from_findings_op(
        run_dir,
        finding_ids=[fid],
        include_states=["needs_human", "confirmed"],
    )
    assert r["ok"] is True
    db2 = Database.open(run_dir / "harness.db")
    try:
        f = db2.get_finding(fid)
        assert f is not None
        assert f.state == "needs_human"
    finally:
        db2.close()
