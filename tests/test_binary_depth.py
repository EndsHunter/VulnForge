"""Profile-aware hunt depth (is_shallow) for binary_re vs code_static."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from vulnforge.db import Database
from vulnforge.llm import FakeLLMClient, LLMResult, ResponseClass
from vulnforge.stages import hunt
from vulnforge.stages.hunt import BINARY_DEEP_TOOLS, is_shallow


def test_binary_re_shallow_with_status_and_imports_only():
    session = {"tools_used": ["ghidra_status", "ghidra_imports"]}
    assert is_shallow(session, profile="binary_re") is True


def test_binary_re_not_shallow_after_decompile():
    session = {"tools_used": ["ghidra_status", "ghidra_decompile"]}
    assert is_shallow(session, profile="binary_re") is False


def test_binary_re_not_shallow_after_xrefs():
    session = {"tools_used": ["ghidra_xrefs"]}
    assert is_shallow(session, profile="binary_re") is False


def test_binary_re_not_shallow_after_disassemble():
    session = {"tools_used": ["ghidra_disassemble"]}
    assert is_shallow(session, profile="binary_re") is False


def test_binary_re_not_shallow_after_call_graph():
    session = {"tools_used": ["ghidra_call_graph"]}
    assert is_shallow(session, profile="binary_re") is False


def test_binary_re_not_shallow_after_function_at():
    session = {"tools_used": ["ghidra_function_at"]}
    assert is_shallow(session, profile="binary_re") is False


def test_binary_re_not_shallow_after_import_callers():
    session = {"tools_used": ["ghidra_import_callers"]}
    assert is_shallow(session, profile="binary_re") is False


def test_binary_re_shallow_with_empty_tools():
    assert is_shallow({"tools_used": []}, profile="binary_re") is True
    assert is_shallow({}, profile="binary_re") is True


def test_binary_re_read_file_grep_not_enough():
    """Source-tree tools do not satisfy binary_re depth."""
    session = {"tools_used": ["read_file", "grep"]}
    assert is_shallow(session, profile="binary_re") is True


def test_code_static_still_needs_read_file_or_grep():
    assert is_shallow({"tools_used": ["ghidra_decompile"]}, profile="code_static") is True
    assert is_shallow({"tools_used": ["ghidra_status"]}, profile="") is True
    assert is_shallow({"tools_used": ["list_dir"]}, profile="code_static") is True
    assert is_shallow({"tools_used": ["read_file"]}, profile="code_static") is False
    assert is_shallow({"tools_used": ["grep"]}, profile="code_static") is False
    assert is_shallow({"tools_used": ["read_file", "grep"]}, profile="") is False


def test_binary_deep_tools_frozenset():
    assert "ghidra_decompile" in BINARY_DEEP_TOOLS
    assert "ghidra_xrefs" in BINARY_DEEP_TOOLS
    assert "ghidra_status" not in BINARY_DEEP_TOOLS
    assert "ghidra_imports" not in BINARY_DEEP_TOOLS


def test_profile_case_insensitive():
    session = {"tools_used": ["ghidra_decompile"]}
    assert is_shallow(session, profile="Binary_RE") is False
    assert is_shallow(session, profile=" BINARY_RE ") is False


def test_hunt_binary_re_calls_ensure_ghidra(tmp_path: Path):
    """hunt.run soft-calls ensure_ghidra_for_run when profile is binary_re."""
    pe = tmp_path / "app.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 64)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()

    db = Database.create(run_dir / "harness.db")
    try:
        db.insert_run(
            "r1",
            str(pe),
            "binary_re",
            "pin",
            {"run": {"profile": "binary_re"}, "binary_re": {"i_am_authorized": True}},
        )
        db.set_architecture({"summary": "binary", "components": []})
        tid = db.enqueue_task(
            "hunt",
            {
                "area": "binary",
                "class": "bin-memory-safety",
                "path_hints": [],
            },
        )
        task = db.lease_next_task("w", 60)
        assert task and task.id == tid

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
                                "name": "submit_none",
                                "arguments": {
                                    "reason": "offline test — no decompile needed"
                                },
                            }
                        ],
                        raw=None,
                        model_id="fake",
                    )
                ],
                "max_tool_rounds": 4,
            },
            "run": {"profile": "binary_re", "ignore_globs": []},
            "binary_re": {"i_am_authorized": True},
            "packet": {},
            "tools": {},
        }

        ensure_mock = MagicMock()
        client_mock = MagicMock()

        with (
            patch(
                "vulnforge.ghidra.runtime.ensure_ghidra_for_run",
                ensure_mock,
            ),
            patch(
                "vulnforge.ghidra.runtime.client_from_cfg",
                return_value=client_mock,
            ),
        ):
            r = hunt.run(task, db, run_dir, cfg)

        ensure_mock.assert_called_once()
        assert r["status"] == "succeeded"
        # only status-level tools (none used) → shallow for binary_re
        assert r.get("shallow") is True
    finally:
        db.close()
