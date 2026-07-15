"""Develop POC: operator scaffold/save + optional develop_poc agent stage."""

from __future__ import annotations

from pathlib import Path

from vulnforge.db import Database
from vulnforge.llm import LLMResult, ResponseClass
from vulnforge.stages import develop_poc
from vulnforge.ui import ops as dashops
from vulnforge.util import build_target_manifest, write_json


def _setup(tmp_path: Path, toy_sqli: Path):
    run_dir = tmp_path / "run-001"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    man = build_target_manifest(toy_sqli, [])
    write_json(run_dir / "target_manifest.json", man)
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


def test_get_scaffold_without_pack(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = db.insert_finding(_body(), state="needs_human")
    db.close()

    r = dashops.get_finding_poc(run_dir, fid)
    assert r["ok"] is True
    assert r["scaffolded"] is True
    assert r["exists"] is False
    assert "How to run" in r["content"]
    assert "Working PoC code" in r["content"]
    assert "SQL injection" in r["content"]
    assert "Reproduction steps" not in r["content"]  # code-first hub, not step checklist
    assert r["poc_relpath"] == "poc_develop.md"
    assert r.get("poc_code_files") == []
    assert r.get("pack_files") == []


def test_save_creates_pack_and_preserves_state(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = db.insert_finding(_body(), state="needs_human")
    db.close()

    draft = (
        "# PoC\n\n"
        "## How to run\n"
        "python poc.py --url http://127.0.0.1:5000\n\n"
        "## Working PoC code\n"
        "```python\nprint('probe')\n```\n"
    )
    r = dashops.save_finding_poc(
        run_dir, fid, content=draft, enqueue_agent=False, operator="tester"
    )
    assert r["ok"] is True
    assert r["state"] == "needs_human"
    assert r["evidence_id"] == f"human-{fid}"
    assert r["poc_relpath"] == "poc_develop.md"
    path = run_dir / "evidence" / f"human-{fid}" / "poc_develop.md"
    assert path.is_file()
    assert "poc.py" in path.read_text(encoding="utf-8")

    db2 = Database.open(run_dir / "harness.db")
    f = db2.get_finding(fid)
    assert f is not None
    assert f.state == "needs_human"
    assert f.evidence_id == f"human-{fid}"
    assert f.body.get("poc_relpath") == "poc_develop.md"
    assert f.body.get("poc_development_latest", {}).get("action") == "save"
    db2.close()

    g = dashops.get_finding_poc(run_dir, fid)
    assert g["exists"] is True
    assert "How to run" in g["content"]
    assert "poc_develop.md" in (g.get("pack_files") or [])


def test_get_poc_lists_code_artifacts(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    body = _body()
    body["evidence_id"] = "e-code"
    pack = run_dir / "evidence" / "e-code"
    pack.mkdir()
    (pack / "poc_develop.md").write_text("# hub\n\npython poc.py\n", encoding="utf-8")
    (pack / "poc.py").write_text(
        "#!/usr/bin/env python3\nprint('probe')\n", encoding="utf-8"
    )
    fid = db.insert_finding(body, state="needs_human", evidence_id="e-code")
    db.close()

    r = dashops.get_finding_poc(run_dir, fid)
    assert r["ok"] is True
    assert r["exists"] is True
    assert "poc.py" in r["pack_files"]
    assert r["poc_code_files"] == ["poc.py"]


def test_save_enqueue_agent_task(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = db.insert_finding(_body(), state="needs_human")
    db.close()

    r = dashops.save_finding_poc(
        run_dir,
        fid,
        content="# draft with enough bytes for the evidence minimum gate xx\n",
        enqueue_agent=True,
        operator_notes="use python boolean blind",
    )
    assert r["ok"] is True
    assert r["task_id"] is not None

    db2 = Database.open(run_dir / "harness.db")
    tasks = db2.conn.execute(
        "SELECT kind, payload_json, state FROM tasks WHERE id=?",
        (r["task_id"],),
    ).fetchone()
    assert tasks is not None
    assert tasks["kind"] == "develop_poc"
    assert tasks["state"] == "queued"
    f = db2.get_finding(fid)
    assert f.state == "needs_human"
    db2.close()


def test_develop_poc_stage_fake_llm(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    body = _body()
    body["evidence_id"] = "e-poc"
    (run_dir / "evidence" / "e-poc").mkdir()
    (run_dir / "evidence" / "e-poc" / "poc_develop.md").write_text(
        "# skeleton draft for agent — keep operator notes here\n",
        encoding="utf-8",
    )
    fid = db.insert_finding(body, state="needs_human", evidence_id="e-poc")
    tid = db.enqueue_task(
        "develop_poc",
        {"finding_id": fid, "evidence_id": "e-poc", "operator_notes": "use python"},
    )
    task = db.lease_next_task("w", 60)
    assert task and task.id == tid

    hub = (
        "# skeleton draft for agent — keep operator notes here\n\n"
        "## How to run\n"
        "python poc.py --url http://127.0.0.1:5000/search\n\n"
        "## Expected signal\n"
        "Response body contains all user rows without auth.\n"
    )
    script = (
        "#!/usr/bin/env python3\n"
        '"""SQLi probe for search_users — not executed by agent."""\n'
        "import argparse\n"
        "import urllib.request\n"
        "\n"
        "def main() -> None:\n"
        "    p = argparse.ArgumentParser()\n"
        '    p.add_argument("--url", default="http://127.0.0.1:5000/search")\n'
        "    args = p.parse_args()\n"
        "    q = \"' OR '1'='1\"\n"
        "    req = urllib.request.Request(args.url + \"?q=\" + urllib.parse.quote(q))\n"
        "    print(urllib.request.urlopen(req, timeout=10).read()[:500])\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    main()\n"
    )
    cfg = {
        "llm": {
            "fake": True,
            "fake_responses": [
                LLMResult(
                    ok=True,
                    classification=ResponseClass.OK,
                    content="",
                    tool_calls=[
                        {
                            "id": "1",
                            "name": "write_evidence",
                            "arguments": {
                                "relpath": "poc.py",
                                "content": script,
                                "evidence_id": "e-poc",
                            },
                        }
                    ],
                    raw=None,
                    model_id="fake",
                ),
                LLMResult(
                    ok=True,
                    classification=ResponseClass.OK,
                    content="",
                    tool_calls=[
                        {
                            "id": "2",
                            "name": "write_evidence",
                            "arguments": {
                                "relpath": "poc_develop.md",
                                "content": hub,
                                "evidence_id": "e-poc",
                            },
                        }
                    ],
                    raw=None,
                    model_id="fake",
                ),
                LLMResult(
                    ok=True,
                    classification=ResponseClass.OK,
                    content="Wrote poc.py and hub run instructions.",
                    tool_calls=[],
                    raw=None,
                    model_id="fake",
                ),
            ],
            "max_tool_rounds": 6,
        },
        "run": {"ignore_globs": [], "max_tasks": 10},
        "packet": {},
        "tools": {},
    }
    result = develop_poc.run(task, db, run_dir, cfg)
    assert result["status"] == "succeeded", result
    assert result["finding_state"] == "needs_human"
    assert "poc.py" in (result.get("poc_code_files") or [])
    path = run_dir / "evidence" / "e-poc" / "poc_develop.md"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "How to run" in text
    assert "keep operator notes" in text
    py = run_dir / "evidence" / "e-poc" / "poc.py"
    assert py.is_file()
    assert "OR '1'='1" in py.read_text(encoding="utf-8")
    f = db.get_finding(fid)
    assert f is not None
    assert f.state == "needs_human"
    assert f.body.get("poc_relpath") == "poc_develop.md"
    assert f.body.get("poc_code_files") == ["poc.py"]
    assert f.body.get("poc_development_latest", {}).get("action") == "agent_develop"
    db.close()


def test_cli_dispatch_develop_poc(tmp_path: Path, toy_sqli: Path):
    from vulnforge.cli import dispatch_task

    run_dir, db = _setup(tmp_path, toy_sqli)
    body = _body()
    body["evidence_id"] = "e2"
    (run_dir / "evidence" / "e2").mkdir()
    fid = db.insert_finding(body, state="confirmed", evidence_id="e2")
    tid = db.enqueue_task("develop_poc", {"finding_id": fid, "evidence_id": "e2"})
    task = db.lease_next_task("w", 60)
    assert task and task.id == tid

    deep = "Agent note with sufficient content for the twenty-byte gate.\n"
    cfg = {
        "llm": {
            "fake": True,
            "fake_responses": [
                LLMResult(
                    ok=True,
                    classification=ResponseClass.OK,
                    content="",
                    tool_calls=[
                        {
                            "id": "1",
                            "name": "write_evidence",
                            "arguments": {
                                "relpath": "poc_develop.md",
                                "content": deep,
                                "evidence_id": "e2",
                            },
                        }
                    ],
                    raw=None,
                    model_id="fake",
                ),
                LLMResult(
                    ok=True,
                    classification=ResponseClass.OK,
                    content="done",
                    tool_calls=[],
                    raw=None,
                    model_id="fake",
                ),
            ],
            "max_tool_rounds": 4,
        },
        "run": {},
        "packet": {},
        "tools": {},
    }
    out = dispatch_task(task, db, run_dir, cfg)
    assert out["status"] == "succeeded"
    # confirmed must not be changed by agent
    assert db.get_finding(fid).state == "confirmed"
    db.close()
