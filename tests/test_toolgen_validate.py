"""Tests for tool draft validation and store."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnforge.toolgen.store import (
    create_draft,
    reset_drafts_root_override,
    set_drafts_root,
    update_draft,
)
from vulnforge.toolgen.validate import validate_draft, validate_draft_dir


@pytest.fixture
def drafts_root(tmp_path: Path):
    root = tmp_path / "tool_drafts"
    set_drafts_root(root)
    yield root
    reset_drafts_root_override()


GOOD_IMPL = '''\
"""toy tool"""
from __future__ import annotations
from pathlib import Path
from typing import Any
from vulnforge.tools.fs_read import resolve_target_path

def toy_count(ctx: dict, path: str = ".") -> dict[str, Any]:
    try:
        root = Path(ctx["target_root"])
        p = resolve_target_path(root, path)
        if not p.is_dir():
            return {"ok": False, "error": "not a directory"}
        n = sum(1 for _ in p.iterdir())
        return {"ok": True, "path": path, "count": n}
    except Exception as e:
        return {"ok": False, "error": str(e)}
'''

GOOD_SCHEMA = {
    "tools": [
        {
            "name": "toy_count",
            "description": "Count entries in a directory",
            "stages": ["hunt"],
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path"},
                },
                "required": [],
            },
        }
    ]
}

GOOD_WIREUP = {
    "impl_module": "vulnforge.tools.toy_count",
    "impl_path": "vulnforge/tools/toy_count.py",
    "handler_branches": ["toy_count"],
    "allowed_tools_add": ["toy_count"],
    "packet_stages": ["hunt"],
    "test_file": "tests/test_tool_toy_count.py",
}


def test_create_and_validate_pass(drafts_root: Path):
    d = create_draft(brief="Count dir entries without full inventory", suggested_id="toy_count")
    assert d["id"] == "toy_count"
    update_draft(
        "toy_count",
        spec_md="# Tool: toy_count\n## Purpose\nCount dir entries.\n",
        impl_py=GOOD_IMPL,
        schema=GOOD_SCHEMA,
        wireup=GOOD_WIREUP,
        handler_snippet='if name == "toy_count": return toy_count(ctx, **args)',
        test_stub="def test_toy_count():\n    assert True\n",
    )
    report = validate_draft("toy_count", persist=True)
    assert report["ok"], report["hard_fail"]
    assert (drafts_root / "toy_count" / "validation_report.json").is_file()


def test_forbidden_import_fails(drafts_root: Path):
    create_draft(brief="bad shell tool", suggested_id="bad_shell")
    update_draft(
        "bad_shell",
        spec_md="# bad\n## Purpose\nshell\n",
        impl_py=(
            "import subprocess\n"
            "def bad_shell(ctx, cmd=''):\n"
            "    subprocess.run(cmd, shell=True)\n"
            "    return {'ok': True}\n"
        ),
        schema={
            "tools": [
                {
                    "name": "bad_shell",
                    "description": "run shell",
                    "parameters": {"type": "object", "properties": {}, "required": []},
                }
            ]
        },
        wireup=GOOD_WIREUP,
    )
    report = validate_draft("bad_shell")
    assert not report["ok"]
    joined = " ".join(report["hard_fail"])
    assert "forbidden_imports" in joined or "code_static_safe" in joined


def test_validate_dir_cli_shape(drafts_root: Path, tmp_path: Path):
    create_draft(brief="x", suggested_id="empty_tool")
    ddir = drafts_root / "empty_tool"
    report = validate_draft_dir(ddir)
    assert not report["ok"]
    assert any(c["id"] == "spec_present" and not c["pass"] for c in report["checks"])


def test_path_param_requires_resolve(drafts_root: Path):
    create_draft(brief="path tool", suggested_id="path_open")
    update_draft(
        "path_open",
        spec_md="# path_open\n## Purpose\nopen path\n",
        impl_py=(
            "def path_open(ctx, path='.'):\n"
            "    p = ctx['target_root'] + '/' + path\n"
            "    return {'ok': True, 'path': p}\n"
        ),
        schema={
            "tools": [
                {
                    "name": "path_open",
                    "description": "open",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                    },
                }
            ]
        },
    )
    report = validate_draft("path_open")
    assert not report["ok"]
    assert any("no_path_escape" in h for h in report["hard_fail"])
