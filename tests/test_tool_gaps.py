"""Tests for deterministic tool-gap analysis."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnforge.control.exit_codes import EXIT_CONFIG, EXIT_PROGRESS
from vulnforge.db import Database
from vulnforge.tool_gaps import (
    KNOWN_TOOLS,
    analyze_run,
    format_markdown,
    write_reports,
)

CONFIG = Path(__file__).resolve().parents[1] / "config" / "default.yaml"


def _write_transcript(run_dir: Path, task_id: int, messages: list, kind: str = "hunt") -> None:
    tdir = run_dir / "transcripts"
    tdir.mkdir(parents=True, exist_ok=True)
    payload = {
        "task_id": task_id,
        "kind": kind,
        "model_id": "fake",
        "saved_at": "2026-07-10T00:00:00Z",
        "message_count": len(messages),
        "messages": messages,
        "result": {},
        "meta": {},
    }
    (tdir / f"task-{task_id}.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )


@pytest.fixture
def synth_run(tmp_path: Path) -> Path:
    run = tmp_path / "runs" / "t" / "run-001"
    run.mkdir(parents=True)
    (run / "evidence").mkdir()
    (run / "project").mkdir()
    (run / "transcripts").mkdir()

    messages = [
        {"role": "system", "content": "Use only allowed tools."},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "1",
                    "type": "function",
                    "function": {
                        "name": "run_shell",
                        "arguments": '{"cmd": "ls"}',
                    },
                }
            ],
        },
        {
            "role": "tool",
            "tool_call_id": "1",
            "name": "run_shell",
            "content": json.dumps({"ok": False, "error": "unknown tool run_shell"}),
        },
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "2",
                    "type": "function",
                    "function": {
                        "name": "note",
                        "arguments": json.dumps(
                            {
                                "kind": "wishlist",
                                "payload": {
                                    "tool": "shell",
                                    "reason": "need bash to reproduce PoC",
                                },
                            }
                        ),
                    },
                }
            ],
        },
        {
            "role": "tool",
            "tool_call_id": "2",
            "name": "note",
            "content": json.dumps(
                {
                    "ok": True,
                    "stored": True,
                    "kind": "wishlist",
                    "payload": {
                        "tool": "shell",
                        "reason": "need bash to reproduce PoC",
                    },
                }
            ),
        },
        {
            "role": "assistant",
            "content": "I cannot run sqlmap; if I had a shell I would execute it.",
            "reasoning_content": "Need exec/shell tool for dynamic PoC.",
        },
    ]
    _write_transcript(run, 1, messages, kind="hunt")

    db = Database.create(run / "harness.db")
    db.insert_run("run-001", str(tmp_path / "toy"), "code_static", "pin", {})
    db.insert_note(
        "wishlist",
        {"tool": "curl", "want": "http fetch of /admin"},
        task_id=1,
    )
    # task with no_submit abort
    tid = db.enqueue_task("hunt", {"area": "app", "class": "injection"}, priority=50)
    db.conn.execute(
        "UPDATE tasks SET state='succeeded', result_json=? WHERE id=?",
        (json.dumps({"status": "failed_task", "error": "no_submit"}), tid),
    )
    db.conn.commit()
    db.close()
    return run


def test_known_tools_include_static_allowlist():
    for name in (
        "list_dir",
        "file_inventory",
        "read_file",
        "grep",
        "note",
        "write_evidence",
        "submit_candidate",
        "submit_none",
        "submit_architecture",
        # binary_re curated tools (union into KNOWN_TOOLS)
        "ghidra_imports",
        "ghidra_import_callers",
        "ghidra_decompile",
    ):
        assert name in KNOWN_TOOLS


def test_analyze_unknown_tool_and_wishlist(synth_run: Path):
    analysis = analyze_run(synth_run)
    assert analysis["gap_count"] >= 1
    caps = {g["tool_or_capability"] for g in analysis["gaps"]}
    # unknown tool call
    assert any(c.startswith("unknown:run_shell") for c in caps)
    # wishlist note -> exec_job (shell/bash)
    assert any("exec_job" in c or "wishlist" in c for c in caps)
    # no_submit from task result
    assert any("no_submit" in c for c in caps)

    unknown = next(g for g in analysis["gaps"] if g["tool_or_capability"].startswith("unknown:"))
    assert unknown["count"] >= 1
    assert unknown["severity"] in ("high", "medium")
    assert unknown["evidence"]


def test_write_reports_projection(synth_run: Path):
    analysis = analyze_run(synth_run)
    paths = write_reports(synth_run, analysis)
    assert len(paths) == 2
    md = synth_run / "project" / "TOOL_GAPS.md"
    js = synth_run / "project" / "tool_gaps.json"
    assert md.is_file()
    assert js.is_file()
    text = md.read_text(encoding="utf-8")
    assert "Tool gaps" in text
    assert "run_shell" in text or "unknown" in text
    data = json.loads(js.read_text(encoding="utf-8"))
    assert data["gap_count"] == analysis["gap_count"]
    assert format_markdown(analysis).startswith("# Tool gaps")


def test_cli_tool_gaps(synth_run: Path):
    from vulnforge import cli as vf_cli

    code = vf_cli.main(
        ["--config", str(CONFIG), "tool-gaps", "--run-dir", str(synth_run)]
    )
    assert code == EXIT_PROGRESS
    assert (synth_run / "project" / "tool_gaps.json").is_file()


def test_cli_bad_path():
    from vulnforge import cli as vf_cli

    code = vf_cli.main(
        [
            "--config",
            str(CONFIG),
            "tool-gaps",
            "--run-dir",
            str(Path("C:/does/not/exist-vf-tool-gaps")),
        ]
    )
    assert code == EXIT_CONFIG


def test_stage_tool_gaps(synth_run: Path):
    from vulnforge.stages import tool_gaps as stage

    db = Database.open(synth_run / "harness.db")
    try:

        class T:
            id = 99
            kind = "tool_gaps"
            payload = {"mode": "mechanical"}

        result = stage.run(T(), db, synth_run, {"run": {"tool_gaps_mode": "mechanical"}})
        assert result["status"] == "succeeded"
        assert result["gap_count"] >= 1
        assert (synth_run / "project" / "TOOL_GAPS.md").is_file()
    finally:
        db.close()


def test_analyze_run_llm_with_fake(synth_run: Path):
    from vulnforge.llm import FakeLLMClient, LLMResult, ResponseClass
    from vulnforge.tool_gaps import analyze_run_hybrid, analyze_run_llm

    fake_json = json.dumps(
        {
            "gaps": [
                {
                    "tool_or_capability": "exec_job",
                    "category": "wishlist",
                    "severity": "high",
                    "count": 3,
                    "suggestion": "Sandboxed shell for PoC reproduction",
                    "evidence": [
                        {"task_id": 1, "snippet": "need bash to reproduce PoC"}
                    ],
                }
            ],
            "notes": "shell is the main gap",
        }
    )
    client = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content=fake_json,
                tool_calls=[],
                raw=None,
                model_id="fake",
            )
        ]
    )
    llm = analyze_run_llm(synth_run, {"llm": {"fake": True}}, client=client)
    assert llm["mode"] == "llm"
    assert llm["gap_count"] >= 1
    caps = {g["tool_or_capability"] for g in llm["gaps"]}
    assert "exec_job" in caps

    client2 = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content=fake_json,
                tool_calls=[],
                raw=None,
                model_id="fake",
            )
        ]
    )
    hybrid = analyze_run_hybrid(synth_run, {}, client=client2)
    assert hybrid["mode"] == "hybrid"
    assert hybrid["gap_count"] >= 1
    sources = {g.get("source") for g in hybrid["gaps"]}
    assert sources & {"mech", "llm", "hybrid"}


def test_aggregate_tool_gaps(synth_run: Path, tmp_path: Path):
    from vulnforge.tool_gaps import aggregate_tool_gaps, analyze_run, write_reports

    write_reports(synth_run, analyze_run(synth_run))
    runs_root = tmp_path / "runs"
    rollup = aggregate_tool_gaps(runs_root)
    assert rollup["runs_scanned"] >= 1
    assert rollup["capability_count"] >= 1
    assert any(
        "run_shell" in str(c.get("tool_or_capability")) or "exec" in str(c.get("tool_or_capability"))
        for c in rollup["capabilities"]
    )
