"""Sink-level coverage facts + preindex truncation honesty."""

from __future__ import annotations

from pathlib import Path

from vulnforge.db import Database
from vulnforge.tools.sink_preindex import (
    build_sink_preindex,
    build_sink_preindex_with_meta,
    empty_sink_meta,
    record_sink_coverage,
    sink_key,
    sink_key_from_record,
)


def test_sink_key_stable():
    assert sink_key("pkg/a.py", 10, "sql") == "pkg/a.py:10:sql"
    assert sink_key(r"pkg\a.py", "10", "SQL") == "pkg/a.py:10:sql"
    rec = {"path": "app.py", "line": 3, "kind": "sql"}
    assert sink_key_from_record(rec) == "app.py:3:sql"
    assert sink_key_from_record({"path": "x", "kind": "sql"}) is None  # no line


def test_build_sink_preindex_meta_toy(toy_sqli: Path):
    sinks, meta = build_sink_preindex_with_meta(toy_sqli)
    assert isinstance(sinks, list) and sinks
    assert any(s.get("kind") == "sql" for s in sinks)
    assert meta["sink_count"] == len(sinks)
    assert meta["files_scanned"] >= 1
    assert meta["files_capped"] is False
    assert meta["sinks_capped"] is False
    # Backward-compat list API still works
    sinks2 = build_sink_preindex(toy_sqli)
    assert len(sinks2) == len(sinks)


def test_build_sink_preindex_caps(tmp_path: Path):
    # Many tiny files with SQL-ish lines so max_sinks trips
    for i in range(20):
        p = tmp_path / f"f{i}.py"
        p.write_text(f"db.cursor.execute('SELECT {i}')\n", encoding="utf-8")
    sinks, meta = build_sink_preindex_with_meta(tmp_path, max_files=100, max_sinks=5)
    assert len(sinks) == 5
    assert meta["sinks_capped"] is True
    assert meta["sink_count"] == 5

    sinks_f, meta_f = build_sink_preindex_with_meta(
        tmp_path, max_files=3, max_sinks=500
    )
    assert meta_f["files_capped"] is True
    assert meta_f["files_scanned"] == 3
    assert len(sinks_f) <= 3


def test_sink_coverage_soft_migrate_open(tmp_path: Path):
    """Create DB, close, reopen via open — table must exist without wipe."""
    db_path = tmp_path / "harness.db"
    db = Database.create(db_path)
    db.insert_run(
        "run-001",
        target_path=str(tmp_path / "tgt"),
        profile="code_static",
        prompt_pin="pin",
        config={},
    )
    db.close()

    db2 = Database.open(db_path)
    db2.upsert_sink_coverage_fact(
        sink_key="app.py:1:sql",
        path="app.py",
        line=1,
        kind="sql",
        area="app",
        attack_class="injection",
        visit_delta=0,
        last_depth="planned",
    )
    rows = db2.list_sink_coverage_facts(area="app", attack_class="injection")
    assert len(rows) == 1
    assert rows[0]["sink_key"] == "app.py:1:sql"
    assert rows[0]["last_depth"] == "planned"
    assert rows[0]["visit_count"] == 0
    summary = db2.sink_coverage_summary()
    assert summary["total"] == 1
    assert summary["planned"] == 1
    assert summary["residual"] == 1
    db2.close()


def test_upsert_sink_coverage_visit_and_depth(tmp_path: Path):
    db = Database.create(tmp_path / "harness.db")
    db.insert_run("run-001", str(tmp_path), "code_static", "pin", {})
    sinks = [
        {"path": "routes.py", "line": 12, "kind": "sql", "text": "execute"},
        {"path": "jobs.py", "line": 4, "kind": "exec", "text": "subprocess"},
    ]
    n = record_sink_coverage(
        db,
        sinks,
        area="api",
        attack_class="injection",
        visit_delta=0,
        last_depth="planned",
    )
    assert n == 2
    n2 = record_sink_coverage(
        db,
        sinks[:1],
        area="api",
        attack_class="injection",
        visit_delta=1,
        last_depth="candidate",
    )
    assert n2 == 1
    rows = db.sink_coverage_for_cell("api", "injection")
    by_key = {r["sink_key"]: r for r in rows}
    assert by_key["routes.py:12:sql"]["last_depth"] == "candidate"
    assert by_key["routes.py:12:sql"]["visit_count"] == 1
    assert by_key["jobs.py:4:exec"]["last_depth"] == "planned"
    assert by_key["jobs.py:4:exec"]["visit_count"] == 0
    db.close()


def test_empty_sink_meta_shape():
    m = empty_sink_meta(max_files=10, max_sinks=20)
    assert m["max_files"] == 10
    assert m["max_sinks"] == 20
    assert m["files_capped"] is False
    assert m["sinks_capped"] is False
