"""Init strategies: discovery, file_by_file, recon_docs."""

from __future__ import annotations

import json
from pathlib import Path

from vulnforge.cli import EXIT_CONFIG, EXIT_PROGRESS, main
from vulnforge.db import Database
from vulnforge.docs_ingest import ingest_docs
from vulnforge.hunt_profiles import active_class_ids
from vulnforge.strategies import plan_file_by_file_hunts


def _run_dir_from_init(runs: Path) -> Path:
    targets = list(runs.iterdir())
    assert len(targets) == 1
    runs_list = list(targets[0].iterdir())
    assert len(runs_list) == 1
    return runs_list[0]


def test_discovery_still_enqueues_recon(toy_sqli: Path, tmp_path: Path):
    runs = tmp_path / "runs"
    code = main(
        [
            "init",
            "--target",
            str(toy_sqli),
            "--runs-root",
            str(runs),
            "--strategy",
            "discovery",
        ]
    )
    assert code == EXIT_PROGRESS
    run_dir = _run_dir_from_init(runs)
    db = Database.open(run_dir / "harness.db")
    s = db.summary()
    assert s["tasks"].get("queued") == 1
    row = db.get_run()
    cfg = json.loads(row["config_json"])
    assert cfg["run"]["strategy"] == "discovery"
    tasks = db.conn.execute("SELECT kind, payload_json FROM tasks").fetchall()
    assert len(tasks) == 1
    assert tasks[0]["kind"] == "recon"
    db.close()


def test_default_strategy_is_discovery(toy_sqli: Path, tmp_path: Path):
    runs = tmp_path / "runs"
    code = main(["init", "--target", str(toy_sqli), "--runs-root", str(runs)])
    assert code == EXIT_PROGRESS
    run_dir = _run_dir_from_init(runs)
    db = Database.open(run_dir / "harness.db")
    row = db.get_run()
    cfg = json.loads(row["config_json"])
    assert cfg["run"].get("strategy") == "discovery"
    kinds = [r["kind"] for r in db.conn.execute("SELECT kind FROM tasks").fetchall()]
    assert kinds == ["recon"]
    db.close()


def test_file_by_file_enqueues_hunts(toy_sqli: Path, tmp_path: Path):
    runs = tmp_path / "runs"
    code = main(
        [
            "init",
            "--target",
            str(toy_sqli),
            "--runs-root",
            str(runs),
            "--strategy",
            "file_by_file",
        ]
    )
    assert code == EXIT_PROGRESS
    run_dir = _run_dir_from_init(runs)
    db = Database.open(run_dir / "harness.db")
    rows = db.conn.execute("SELECT kind, payload_json FROM tasks ORDER BY id").fetchall()
    assert rows
    assert all(r["kind"] == "hunt" for r in rows)
    # toy_sqli has app.py → active class hunts
    payloads = [json.loads(r["payload_json"]) for r in rows]
    classes = {p["class"] for p in payloads}
    assert classes <= set(active_class_ids())
    assert all(p.get("path_hints") for p in payloads)
    assert all(p.get("strategy") == "file_by_file" for p in payloads)
    # no recon
    assert not any(r["kind"] == "recon" for r in rows)
    cfg = json.loads(db.get_run()["config_json"])
    assert cfg["run"]["strategy"] == "file_by_file"
    db.close()


def test_file_by_file_respects_max_tasks(tmp_path: Path):
    # Build a mini tree with several source files
    root = tmp_path / "src"
    root.mkdir()
    for i in range(10):
        (root / f"mod{i}.py").write_text(f"x = {i}\n", encoding="utf-8")
    payloads = plan_file_by_file_hunts(root, ignore=[], max_tasks=7)
    assert len(payloads) == 7
    # Full uncapped would be 10 * len(active)
    full = plan_file_by_file_hunts(root, ignore=[], max_tasks=500)
    assert len(full) == 10 * len(active_class_ids())


def test_plan_skips_binary_and_huge(tmp_path: Path):
    root = tmp_path / "mix"
    root.mkdir()
    (root / "ok.py").write_text("print(1)\n", encoding="utf-8")
    (root / "blob.bin").write_bytes(b"\x00\x01\x02" * 100)
    (root / "pic.png").write_bytes(b"\x89PNG\r\n" + b"\x00" * 50)
    huge = root / "huge.py"
    huge.write_bytes(b"x = 1\n" * 100_000)  # > 400k
    payloads = plan_file_by_file_hunts(root, ignore=[], max_tasks=50)
    paths = {p["path_hints"][0] for p in payloads}
    assert "ok.py" in paths
    assert "blob.bin" not in paths
    assert "pic.png" not in paths
    assert "huge.py" not in paths


def test_recon_docs_requires_path(toy_sqli: Path, tmp_path: Path):
    runs = tmp_path / "runs"
    code = main(
        [
            "init",
            "--target",
            str(toy_sqli),
            "--runs-root",
            str(runs),
            "--strategy",
            "recon_docs",
        ]
    )
    assert code == EXIT_CONFIG
    assert not runs.exists() or not any(runs.rglob("harness.db"))


def test_recon_docs_ingests_and_enqueues_recon(toy_sqli: Path, tmp_path: Path):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "threat_model.md").write_text(
        "# Threat model\n\nAuth boundary at /api.\nSQL inputs on search.\n",
        encoding="utf-8",
    )
    (docs / "notes.txt").write_text("Look at session cookies.\n", encoding="utf-8")
    runs = tmp_path / "runs"
    code = main(
        [
            "init",
            "--target",
            str(toy_sqli),
            "--runs-root",
            str(runs),
            "--strategy",
            "recon_docs",
            "--docs-path",
            str(docs),
        ]
    )
    assert code == EXIT_PROGRESS
    run_dir = _run_dir_from_init(runs)
    assert (run_dir / "docs_digest.md").is_file()
    digest = (run_dir / "docs_digest.md").read_text(encoding="utf-8")
    assert "threat_model.md" in digest or "Threat model" in digest
    assert "Auth boundary" in digest or "session cookies" in digest

    db = Database.open(run_dir / "harness.db")
    rows = db.conn.execute("SELECT kind, payload_json FROM tasks").fetchall()
    assert len(rows) == 1
    assert rows[0]["kind"] == "recon"
    payload = json.loads(rows[0]["payload_json"])
    assert payload.get("strategy") == "recon_docs"
    assert payload.get("docs_digest")
    assert Path(payload["docs_digest"]).is_file()
    assert "Docs ingest" in (payload.get("operator_brief") or "")
    cfg = json.loads(db.get_run()["config_json"])
    assert cfg["run"]["strategy"] == "recon_docs"
    assert cfg["run"].get("docs_path")
    db.close()


def test_ingest_docs_html_and_caps(tmp_path: Path):
    docs = tmp_path / "d"
    docs.mkdir()
    (docs / "a.html").write_text(
        "<html><body><h1>Title</h1><p>Hello world</p>"
        "<script>evil()</script></body></html>",
        encoding="utf-8",
    )
    out = tmp_path / "digest.md"
    meta = ingest_docs(docs, out)
    assert meta["files"] >= 1
    text = out.read_text(encoding="utf-8")
    assert "Hello world" in text
    assert "evil()" not in text
    assert meta["chars"] <= 12_000 + 500  # soft bound on extract body
