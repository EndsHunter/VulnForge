"""PoC handoff: frontmatter, readiness, export, harness runner, validate_poc."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from vulnforge.db import Database
from vulnforge.poc_handoff import (
    assess_poc_readiness,
    export_validation_job,
    parse_hub_frontmatter,
)
from vulnforge.poc_runner import classify_run_result, execute_poc_for_pack, run_poc_local
from vulnforge.stages import validate_poc
from vulnforge.ui import ops as dashops
from vulnforge.util import build_target_manifest, write_json


def _setup(tmp_path: Path, toy_sqli: Path):
    run_dir = tmp_path / "run-001"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    write_json(run_dir / "target_manifest.json", build_target_manifest(toy_sqli, []))
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", str(toy_sqli), "code_static", "pin", {})
    return run_dir, db


def _body() -> dict:
    return {
        "title": "SQL injection in search_users",
        "summary": "User input is concatenated into SQL.",
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "unauthenticated user",
            "boundary": "HTTP query parameter to SQL engine",
            "impact": "read or modify arbitrary user rows",
        },
        "citations": [{"path": "app.py", "start_line": 10, "symbol": "search_users"}],
        "severity_claim": "HIGH",
    }


def test_parse_hub_frontmatter():
    text = """---
run: python poc.py --url http://x
entry: poc.py
success_regex: ASSERT_OK
timeout_s: 30
network: none
env: TARGET_URL=http://x FOO=bar
---

# Hub

## Expected signal

ASSERT_OK printed
"""
    meta, body = parse_hub_frontmatter(text)
    assert meta["run"].startswith("python poc.py")
    assert meta["entry"] == "poc.py"
    assert meta["success_regex"] == "ASSERT_OK"
    assert meta["timeout_s"] == 30
    assert meta["network"] == "none"
    assert meta["env"]["TARGET_URL"] == "http://x"
    assert meta["env"]["FOO"] == "bar"
    assert body.strip().startswith("# Hub")


def test_readiness_requires_code_and_signal(tmp_path: Path):
    pack = tmp_path / "pack"
    pack.mkdir()
    hub = """---
run: python poc.py
success_regex: ASSERT_OK
---

## Expected signal

body contains ASSERT_OK
"""
    (pack / "poc_develop.md").write_text(hub, encoding="utf-8")
    r0 = assess_poc_readiness(finding_body=_body(), pack_dir=pack, hub_text=hub)
    assert r0["ready"] is False
    assert "missing_poc_code" in r0["issues"]

    (pack / "poc.py").write_text("print('ASSERT_OK')\n", encoding="utf-8")
    r1 = assess_poc_readiness(finding_body=_body(), pack_dir=pack, hub_text=hub)
    assert r1["ready"] is True
    assert r1["run_command"].startswith("python")
    assert r1["entry"] == "poc.py"


def test_run_poc_local_signal(tmp_path: Path):
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "poc.py").write_text("print('ASSERT_OK')\n", encoding="utf-8")
    raw = run_poc_local(pack, "python poc.py", timeout_s=15)
    assert raw["exit_code"] == 0
    assert "ASSERT_OK" in (raw["stdout"] or "")

    result = execute_poc_for_pack(
        pack,
        cfg={"poc_harness": {"enabled": True, "runner": "local_subprocess", "timeout_s": 15}},
        hub_text="---\nrun: python poc.py\nsuccess_regex: ASSERT_OK\n---\n\n## Expected signal\nok\n",
        finding_id=1,
    )
    assert result["verdict"] == "signal_observed"
    assert result["signal_matched"] is True


def test_classify_verdicts():
    assert (
        classify_run_result(
            ran=True,
            exit_code=0,
            timed_out=False,
            spawn_error=None,
            signal_matched=True,
        )
        == "signal_observed"
    )
    assert (
        classify_run_result(
            ran=True,
            exit_code=0,
            timed_out=False,
            spawn_error=None,
            signal_matched=False,
        )
        == "signal_absent"
    )
    assert (
        classify_run_result(
            ran=False,
            exit_code=None,
            timed_out=True,
            spawn_error="timeout",
            signal_matched=None,
        )
        == "poc_broken"
    )


def test_export_validation_job(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    body = _body()
    body["evidence_id"] = "e1"
    pack = run_dir / "evidence" / "e1"
    pack.mkdir()
    (pack / "poc.py").write_text("print('ASSERT_OK')\n", encoding="utf-8")
    (pack / "poc_develop.md").write_text(
        "---\nrun: python poc.py\nsuccess_regex: ASSERT_OK\n---\n\n"
        "## Expected signal\nASSERT_OK\n",
        encoding="utf-8",
    )
    fid = db.insert_finding(body, state="needs_human", evidence_id="e1")
    finding = db.get_finding(fid)
    r = export_validation_job(
        run_dir,
        finding,
        target_path=str(toy_sqli),
        run_id="run-001",
        as_zip=True,
        include_citations=True,
    )
    assert r["ok"] is True
    out = Path(r["out_dir"])
    assert (out / "finding.json").is_file()
    assert (out / "HANDOFF.md").is_file()
    assert (out / "meta.json").is_file()
    assert (out / "evidence" / "poc.py").is_file()
    assert Path(r["zip_path"]).is_file()
    handoff = (out / "HANDOFF.md").read_text(encoding="utf-8")
    assert "Validation job" in handoff
    assert "ASSERT_OK" in handoff or "success" in handoff.lower()
    db.close()


def test_validate_poc_stage_writes_run_json(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    body = _body()
    body["evidence_id"] = "e2"
    pack = run_dir / "evidence" / "e2"
    pack.mkdir()
    (pack / "poc.py").write_text("print('ASSERT_OK')\n", encoding="utf-8")
    (pack / "poc_develop.md").write_text(
        "---\nrun: python poc.py\nsuccess_regex: ASSERT_OK\ntimeout_s: 20\n---\n\n"
        "## Expected signal\nASSERT_OK\n",
        encoding="utf-8",
    )
    fid = db.insert_finding(body, state="needs_human", evidence_id="e2")
    task = SimpleNamespace(
        id=99,
        kind="validate_poc",
        payload={"finding_id": fid, "operator": "test"},
    )
    cfg = {
        "poc_harness": {
            "enabled": True,
            "runner": "local_subprocess",
            "timeout_s": 20,
        },
        # Offline unit test: mechanical harness only (no live multi-model referee)
        "stages": {"validate_poc_referee": False},
        "llm": {"fake": True, "fake_responses": []},
        "packet": {},
    }
    result = validate_poc.run(task, db, run_dir, cfg)
    assert result["status"] == "succeeded"
    assert result["verdict"] == "signal_observed"
    assert (pack / "poc_run.json").is_file()
    data = json.loads((pack / "poc_run.json").read_text(encoding="utf-8"))
    assert data["verdict"] == "signal_observed"

    f2 = db.get_finding(fid)
    assert f2 is not None
    assert f2.state == "needs_human"  # never auto-confirm
    assert f2.body.get("poc_validation_latest", {}).get("verdict") == "signal_observed"
    db.close()


def test_enqueue_validate_poc_op(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = db.insert_finding(_body(), state="needs_human")
    db.close()
    r = dashops.enqueue_validate_poc(run_dir, fid, operator="tester")
    assert r["ok"] is True
    assert r["task_id"]
    db2 = Database.open(run_dir / "harness.db")
    rows = db2.conn.execute(
        "SELECT kind, state, payload_json FROM tasks WHERE id=?",
        (r["task_id"],),
    ).fetchone()
    assert rows is not None
    assert rows[0] == "validate_poc"
    payload = json.loads(rows[2])
    assert payload["finding_id"] == fid
    db2.close()


def test_get_poc_includes_readiness(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    body = _body()
    body["evidence_id"] = "e3"
    pack = run_dir / "evidence" / "e3"
    pack.mkdir()
    (pack / "poc.py").write_text("print('x')\n", encoding="utf-8")
    (pack / "poc_develop.md").write_text(
        "---\nrun: python poc.py\nsuccess_regex: ASSERT_OK\n---\n\n"
        "## Expected signal\nASSERT_OK\n",
        encoding="utf-8",
    )
    fid = db.insert_finding(body, state="needs_human", evidence_id="e3")
    db.close()
    r = dashops.get_finding_poc(run_dir, fid)
    assert r["ok"] is True
    assert "readiness" in r
    assert r["harness_ready"] is True
    assert "poc.py" in r["poc_code_files"]


def test_cli_export_validation_job(tmp_path: Path, toy_sqli: Path, monkeypatch):
    from vulnforge import cli as vf_cli

    run_dir, db = _setup(tmp_path, toy_sqli)
    body = _body()
    body["evidence_id"] = "e4"
    pack = run_dir / "evidence" / "e4"
    pack.mkdir()
    (pack / "poc.py").write_text("print('ASSERT_OK')\n", encoding="utf-8")
    (pack / "poc_develop.md").write_text(
        "---\nrun: python poc.py\nsuccess_regex: ASSERT_OK\n---\n\n## Expected signal\nok\n",
        encoding="utf-8",
    )
    fid = db.insert_finding(body, state="needs_human", evidence_id="e4")
    db.close()

    cfg = {"run": {"runs_root": str(tmp_path)}, "poc_harness": {"enabled": True}}
    args = SimpleNamespace(
        finding_id=fid,
        run_dir=run_dir,
        out=None,
        no_zip=False,
        no_citations=False,
    )
    code = vf_cli.cmd_export_validation_job(args, cfg)
    assert code == vf_cli.EXIT_PROGRESS
    exports = list((run_dir / "exports").glob("validation-job-finding-*"))
    assert exports


def test_dispatch_validate_poc(tmp_path: Path, toy_sqli: Path):
    from vulnforge.cli import dispatch_task

    run_dir, db = _setup(tmp_path, toy_sqli)
    body = _body()
    body["evidence_id"] = "e5"
    pack = run_dir / "evidence" / "e5"
    pack.mkdir()
    (pack / "poc.py").write_text("print('ASSERT_OK')\n", encoding="utf-8")
    (pack / "poc_develop.md").write_text(
        "---\nrun: python poc.py\nsuccess_regex: ASSERT_OK\n---\n\n## Expected signal\nok\n",
        encoding="utf-8",
    )
    fid = db.insert_finding(body, state="needs_human", evidence_id="e5")
    task = SimpleNamespace(
        id=1,
        kind="validate_poc",
        payload={"finding_id": fid},
    )
    cfg = {
        "poc_harness": {"enabled": True, "runner": "local_subprocess", "timeout_s": 20},
        "stages": {"validate_poc_referee": False},
        "llm": {"fake": True, "fake_responses": []},
        "packet": {},
    }
    r = dispatch_task(task, db, run_dir, cfg)
    assert r["status"] == "succeeded"
    assert r["verdict"] == "signal_observed"
    db.close()
