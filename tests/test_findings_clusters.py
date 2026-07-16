"""PR-D: findings cluster_findings + operator merge_findings."""

from __future__ import annotations

from pathlib import Path

from vulnforge.db import Database
from vulnforge.stages.dedup import cluster_findings, merge_findings, merge_key
from vulnforge.ui import ops as dashops


def _body(
    title: str,
    *,
    weakness_class: str = "injection",
    path: str = "app.py",
    symbol: str = "search_users",
    **extra,
) -> dict:
    b = {
        "title": title,
        "summary": f"summary for {title}",
        "weakness_class": weakness_class,
        "threat_model": {
            "attacker": "user",
            "boundary": "api",
            "impact": "data",
        },
        "citations": [{"path": path, "symbol": symbol}],
        "sink_path": path,
        "sink_symbol": symbol,
    }
    b.update(extra)
    return b


def test_cluster_by_merge_key_labels_and_primary(tmp_path: Path):
    db = Database.create(tmp_path / "h.db")
    db.insert_run("r1", str(tmp_path), "code_static", "pin", {})
    # candidate lower priority than needs_human / confirmed
    id_cand = db.insert_finding(
        _body("Cand SQLi", weakness_class="injection"),
        state="candidate",
        profile="code_static",
    )
    id_nh = db.insert_finding(
        _body("NH SQLi", weakness_class="access-control"),
        state="needs_human",
        profile="code_static",
    )
    id_conf = db.insert_finding(
        _body("Conf SQLi", weakness_class="ai-llm"),
        state="confirmed",
        profile="code_static",
    )
    # different sink → not in same cluster
    id_other = db.insert_finding(
        _body("Other", path="other.py", symbol="foo"),
        state="needs_human",
        profile="code_static",
    )

    assert merge_key(_body("x")) == "app.py|search_users"
    clusters = cluster_findings(db)
    assert len(clusters) == 1
    c = clusters[0]
    assert c["strength"] == "merge_key"
    assert c["size"] == 3
    assert c["primary_id"] == id_conf  # confirmed first
    labels = {m["id"]: m["label"] for m in c["members"]}
    assert labels[id_conf] == "1A"
    assert labels[id_nh] == "1B"
    assert labels[id_cand] == "1C"
    # other not clustered alone
    member_ids = {m["id"] for m in c["members"]}
    assert id_other not in member_ids
    db.close()


def test_cluster_path_only_weak(tmp_path: Path):
    db = Database.create(tmp_path / "h.db")
    db.insert_run("r1", str(tmp_path), "code_static", "pin", {})
    # empty symbols → merge_key is None → weak path cluster
    a = db.insert_finding(
        _body("A", symbol="", weakness_class="injection"),
        state="needs_human",
        profile="code_static",
    )
    b = db.insert_finding(
        _body("B", symbol="", weakness_class="access-control"),
        state="candidate",
        profile="code_static",
    )
    assert merge_key(_body("A", symbol="")) is None
    clusters = cluster_findings(db)
    assert len(clusters) == 1
    assert clusters[0]["strength"] == "path_only"
    assert clusters[0]["size"] == 2
    assert clusters[0]["primary_id"] == a  # needs_human > candidate
    assert {m["id"] for m in clusters[0]["members"]} == {a, b}
    db.close()


def test_cluster_skips_superseded(tmp_path: Path):
    db = Database.create(tmp_path / "h.db")
    db.insert_run("r1", str(tmp_path), "code_static", "pin", {})
    keep = db.insert_finding(
        _body("Keep"), state="needs_human", profile="code_static"
    )
    drop = db.insert_finding(
        _body("Drop", weakness_class="ai-llm"),
        state="candidate",
        profile="code_static",
    )
    # Only one active after merge
    merge_findings(db, keep, [drop])
    f_drop = db.get_finding(drop)
    assert f_drop is not None
    assert f_drop.state == "superseded"
    assert f_drop.body.get("superseded_by") == keep
    clusters = cluster_findings(db)
    assert clusters == []  # single remaining member
    db.close()


def test_merge_findings_annotates_keeper_no_auto_confirm(tmp_path: Path):
    db = Database.create(tmp_path / "h.db")
    db.insert_run("r1", str(tmp_path), "code_static", "pin", {})
    keep = db.insert_finding(
        _body("Keep me", weakness_class="injection"),
        state="needs_human",
        profile="code_static",
    )
    drop = db.insert_finding(
        _body("Variant title", weakness_class="ai-llm"),
        state="candidate",
        profile="code_static",
    )
    result = merge_findings(db, keep, [drop])
    assert result["ok"] is True
    assert result["keep_state"] == "needs_human"
    assert drop in result["dropped_ids"]
    keeper = db.get_finding(keep)
    assert keeper is not None
    assert keeper.state == "needs_human"  # never promoted to confirmed
    assert "ai-llm" in (keeper.body.get("merged_classes") or [])
    assert "injection" in (keeper.body.get("merged_classes") or [])
    assert "Variant title" in (keeper.body.get("near_dup_titles") or [])
    dropped = db.get_finding(drop)
    assert dropped is not None
    assert dropped.state == "superseded"
    assert dropped.body.get("superseded_by") == keep
    db.close()


def test_merge_findings_op_via_dashboard(tmp_path: Path):
    run_dir = tmp_path / "run-001"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", str(tmp_path), "code_static", "pin", {})
    keep = db.insert_finding(
        _body("K", weakness_class="injection"),
        state="confirmed",
        profile="code_static",
    )
    drop = db.insert_finding(
        _body("D", weakness_class="cryptography"),
        state="needs_human",
        profile="code_static",
    )
    db.close()

    r = dashops.merge_findings_op(run_dir, keep, [drop])
    assert r["ok"] is True
    assert r["keep_state"] == "confirmed"
    assert r["dropped_ids"] == [drop]

    clusters = dashops.list_finding_clusters(run_dir)
    assert clusters["ok"] is True
    assert clusters["count"] == 0  # only keeper left

    db2 = Database.open(run_dir / "harness.db")
    try:
        k = db2.get_finding(keep)
        assert k is not None
        assert k.state == "confirmed"
        assert "cryptography" in (k.body.get("merged_classes") or [])
    finally:
        db2.close()


def test_merge_op_rejects_empty_drops(tmp_path: Path):
    run_dir = tmp_path / "run-001"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", str(tmp_path), "code_static", "pin", {})
    keep = db.insert_finding(_body("K"), state="candidate", profile="code_static")
    db.close()
    r = dashops.merge_findings_op(run_dir, keep, [])
    assert r["ok"] is False
    assert "drop_ids" in (r.get("error") or "")
