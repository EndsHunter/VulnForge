"""Offline toolgen generate path (FakeLLM — no live model)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnforge.llm import FakeLLMClient, LLMResult, ResponseClass
from vulnforge.toolgen.generate import (
    GenerateToolError,
    _parse_json_content,
    generate_impl,
    generate_spec,
)
from vulnforge.toolgen.store import (
    create_draft,
    get_draft,
    reset_drafts_root_override,
    set_drafts_root,
)


@pytest.fixture
def drafts_root(tmp_path: Path):
    root = tmp_path / "tool_drafts"
    set_drafts_root(root)
    yield root
    reset_drafts_root_override()


def test_parse_json_content_with_prose_and_fence():
    raw = (
        "Sure, here is the payload:\n"
        "```json\n"
        '{"id": "x", "spec_md": "# T\\n", "title": "X"}\n'
        "```\n"
    )
    data = _parse_json_content(raw)
    assert data["id"] == "x"
    assert data["title"] == "X"


def test_parse_json_content_last_object_wins_for_leakage():
    raw = 'noise {"a": 1} trailing {"id": "ok", "spec_md": "s"}'
    data = _parse_json_content(raw)
    assert data["id"] == "ok"


def test_parse_json_strips_think_blocks():
    raw = '<think>plan</think>\n{"id": "t", "spec_md": "# ok"}'
    data = _parse_json_content(raw)
    assert data["id"] == "t"


def test_generate_spec_fake(drafts_root: Path):
    did = "line_count"
    create_draft(
        brief="Count lines in a file under path",
        suggested_id=did,
        slots={
            "problem_statement": "Need line counts for file evidence",
            "non_goals": "No writes",
            "io_contract": "path -> count",
            "safety_constraints": "read_only path jail",
        },
    )
    payload = {
        "id": did,
        "title": "Line count",
        "description": "Count lines in a target file",
        "spec_md": "# Tool: line_count\n## Purpose\nCount lines.\n",
        "stages": ["hunt"],
        "risk_class": "read_only",
        "prefer_extend": None,
    }
    client = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content=json.dumps(payload),
                tool_calls=[],
                raw=None,
                model_id="fake",
            )
        ]
    )
    out = generate_spec({"llm": {"fake": True}}, did, client=client)
    assert out["ok"] is True
    d = get_draft(did)
    assert "Count lines" in (d.get("spec_md") or "")
    assert (d.get("meta") or {}).get("title") == "Line count"


def test_generate_impl_fake_wireup_defaults(drafts_root: Path):
    did = "line_count"
    create_draft(brief="Count lines", suggested_id=did)
    from vulnforge.toolgen.store import update_draft

    update_draft(
        did,
        spec_md="# Tool: line_count\n## Purpose\nCount lines.\n",
        status="generated",
    )
    impl = '''\
from __future__ import annotations
from pathlib import Path
from typing import Any
from vulnforge.tools.fs_read import resolve_target_path

def line_count(ctx: dict, path: str = ".") -> dict[str, Any]:
    try:
        p = resolve_target_path(Path(ctx["target_root"]), path)
        if not p.is_file():
            return {"ok": False, "error": "not a file"}
        n = sum(1 for _ in p.open(encoding="utf-8", errors="replace"))
        return {"ok": True, "path": path, "lines": n}
    except Exception as e:
        return {"ok": False, "error": str(e)}
'''
    payload = {
        "impl_py": impl,
        "schema": {
            "tools": [
                {
                    "name": did,
                    "description": "Count lines",
                    "stages": ["hunt"],
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                        },
                        "required": [],
                    },
                }
            ]
        },
        "handler_snippet": f'if name == "{did}": ...',
        "wireup": {},
        "test_stub": f"def test_{did}():\n    assert True\n",
    }
    client = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content=json.dumps(payload),
                tool_calls=[],
                raw=None,
                model_id="fake",
            )
        ]
    )
    out = generate_impl({"llm": {"fake": True, "temperature_code": 0.1}}, did, client=client)
    assert out["ok"] is True
    d = get_draft(did, include_files=True)
    assert "def line_count" in (d.get("impl_py") or "")
    wire = d.get("wireup") or {}
    assert wire.get("impl_path") == f"vulnforge/tools/{did}.py"
    assert did in (wire.get("allowed_tools_add") or [])


def test_generate_spec_empty_raises(drafts_root: Path):
    did = "empty_tool"
    create_draft(brief="x", suggested_id=did)
    client = FakeLLMClient(
        responses=[
            LLMResult(
                ok=False,
                classification=ResponseClass.CONTEXT_LENGTH,
                content=None,
                tool_calls=[],
                raw=None,
                model_id="fake",
                error="finish_reason=length (empty content; raise llm.max_tokens for reasoning models)",
                reasoning_content="thinking...",
            )
        ]
    )
    with pytest.raises(GenerateToolError) as ei:
        generate_spec({"llm": {"fake": True}}, did, client=client)
    msg = str(ei.value).lower()
    assert "max_tokens" in msg or "reasoning" in msg or "failed" in msg
