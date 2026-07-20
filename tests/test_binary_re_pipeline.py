"""Offline binary_re hunt pipeline: FakeLLM + Fake Ghidra → needs_human.

Proves: import_callers → decompile → evidence → candidate passes mech gates,
and coverage depth is not shallow when Ghidra deep tools were used.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from vulnforge.db import Database
from vulnforge.llm import LLMResult, ResponseClass
from vulnforge.stages import hunt, validate_mech
from vulnforge.stages.hunt import is_shallow
from vulnforge.util import build_single_file_manifest, write_json


def _tiny_pe(path: Path) -> Path:
    data = b"MZ" + b"\x00" * 62 + b"PE\x00\x00" + b"\x00" * 200
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _tool(name: str, arguments: dict, tid: str = "1") -> LLMResult:
    return LLMResult(
        ok=True,
        classification=ResponseClass.OK,
        content="",
        tool_calls=[{"id": tid, "name": name, "arguments": arguments}],
        raw=None,
        model_id="fake",
    )


class _FakeGhidraPipeline:
    """Minimal client: strcpy import → vulnerable_copy caller + decomp."""

    base_url = "http://fake-ghidra"

    def check_connection(self):
        return {"ok": True, "text": "Connected"}

    def get_version(self):
        return {"plugin_version": "test"}

    def get_metadata(self):
        return {"Program Name": "vuln_copy.exe"}

    def list_imports(self, *, offset: int = 0, limit: int = 200, filter_text=None):
        items = [
            {"name": "strcpy", "address": "0x140001000"},
            {"name": "memcpy", "address": "0x140001010"},
        ]
        if filter_text:
            n = str(filter_text).lower()
            items = [i for i in items if n in i["name"].lower()]
        return items[int(offset) : int(offset) + int(limit)]

    def get_function_callers(self, name_or_address: str):
        return []  # force xrefs path

    def get_xrefs_to(self, address: str):
        if address in ("0x140001000", "140001000"):
            return [{"from": "0x140002100", "to": address}]
        return []

    def get_function_by_address(self, address: str):
        if address in ("0x140002100", "140002100"):
            return {"name": "vulnerable_copy", "address": "0x140002000"}
        return {"error": f"no function at {address}"}

    def decompile_function(self, name_or_address: str):
        return {
            "code": (
                "void vulnerable_copy(char *src)\n"
                "{\n"
                "  char buf[32];\n"
                "  strcpy(buf, src); /* unbounded */\n"
                "}\n"
            )
        }

    def disassemble_function(self, name_or_address: str):
        return {"text": "vulnerable_copy: ..."}

    def list_functions(self, *, offset: int = 0, limit: int = 100, filter_text=None):
        return [{"name": "vulnerable_copy", "address": "0x140002000"}]

    def get_xrefs_from(self, address: str):
        return []

    def list_exports(self, *, offset: int = 0, limit: int = 200):
        return [{"name": "vulnerable_copy", "address": "0x140002000"}]

    def list_strings(self, *, offset: int = 0, limit: int = 100, filter_text=None):
        return []

    def search_memory_strings(self, pattern: str, *, limit: int = 50):
        return []

    def get_function_callees(self, name_or_address: str):
        return []

    def get_function_call_graph(self, name_or_address: str):
        return {}

    def search_byte_patterns(self, pattern: str, *, limit: int = 20):
        return []

    def list_segments(self):
        return []

    def get_entry_points(self):
        return [{"address": "0x140001000"}]

    def healthy(self):
        return True


def test_binary_re_hunt_to_needs_human(tmp_path: Path, monkeypatch):
    # Keep PE outside the run tree so evidence_root is not under target_root
    # (single-file binary_re uses target.parent as target_root).
    pe = _tiny_pe(tmp_path / "target" / "vuln_copy.exe")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    write_json(run_dir / "target_manifest.json", build_single_file_manifest(pe))

    db = Database.create(run_dir / "harness.db")
    db.insert_run(
        "r-bin",
        str(pe),
        "binary_re",
        "pin",
        {
            "run": {
                "profile": "binary_re",
                "binary_re_authorized": True,
                "ignore_globs": [],
            },
            "binary_re": {"i_am_authorized": True},
            "llm": {"fake": True},
            "packet": {},
            "tools": {},
            "stages": {},
        },
    )
    db.set_architecture(
        {
            "summary": "Synthetic PE with strcpy sink",
            "binary": {"name": "vuln_copy.exe"},
            "components": [{"name": "copy", "path_hints": ["vulnerable_copy"]}],
            "hunt_focus": [
                {
                    "area": "memory_safety",
                    "class": "bin-memory-safety",
                    "path_hints": ["strcpy", "vulnerable_copy"],
                }
            ],
        }
    )
    db.enqueue_task(
        "hunt",
        {
            "area": "memory_safety",
            "class": "bin-memory-safety",
            "path_hints": ["strcpy"],
        },
    )
    task = db.lease_next_task("w", 60)
    assert task is not None

    fake = _FakeGhidraPipeline()
    monkeypatch.setattr(
        "vulnforge.ghidra.runtime.ensure_ghidra_for_run",
        lambda *a, **k: {"ready": True},
    )
    monkeypatch.setattr(
        "vulnforge.ghidra.runtime.client_from_cfg",
        lambda cfg: fake,
    )

    # write_evidence defaults evidence_id to task_id when omitted; session then
    # fills submit_candidate if evidence_id is left off the candidate body.
    eid = str(task.id)
    cand = {
        "title": "Unbounded strcpy in vulnerable_copy",
        "summary": (
            "vulnerable_copy copies attacker-controlled argv into a 32-byte stack "
            "buffer via strcpy without a length check."
        ),
        "weakness_class": "bin-memory-safety",
        "threat_model": {
            "attacker": "local user controlling argv",
            "boundary": "command line → stack buffer",
            "impact": "stack buffer overflow / potential code execution",
        },
        "citations": [
            {
                "path": "vuln_copy.exe",
                "address": "0x140002000",
                "symbol": "vulnerable_copy",
            }
        ],
        "sink_address": "0x140002000",
        "sink_symbol": "vulnerable_copy",
        "sink_path": "vuln_copy.exe",
        "severity_claim": "HIGH",
        "evidence_id": eid,
    }

    responses = [
        _tool("ghidra_import_callers", {"symbol": "strcpy"}, "t1"),
        _tool("ghidra_decompile", {"name": "vulnerable_copy"}, "t2"),
        _tool(
            "write_evidence",
            {
                "evidence_id": eid,
                "relpath": "poc_notes.md",
                "content": (
                    "Attacker controls argv[1]. vulnerable_copy calls strcpy(buf, src) "
                    "into char buf[32] with no bound check. Repro: long argv string. "
                    "Static RE only — not exploit proof.\n"
                ),
            },
            "t3",
        ),
        _tool("submit_candidate", cand, "t4"),
    ]

    cfg = {
        "llm": {
            "fake": True,
            "fake_responses": responses,
            "max_tool_rounds": 8,
        },
        "run": {
            "profile": "binary_re",
            "binary_re_authorized": True,
            "ignore_globs": [],
        },
        "binary_re": {"i_am_authorized": True},
        "packet": {},
        "tools": {},
        "stages": {},
    }

    r = hunt.run(task, db, run_dir, cfg)
    assert r["status"] == "succeeded", r
    assert not r.get("none_found"), r
    assert r.get("shallow") is False, f"expected deep binary hunt, got {r}"

    findings = db.list_findings()
    assert findings, "expected a finding"
    fid = findings[0].id if hasattr(findings[0], "id") else findings[0]["id"]

    class _T:
        def __init__(self, finding_id: int):
            self.id = 99
            self.payload = {"finding_id": finding_id}

    vr = validate_mech.run(_T(fid), db, run_dir, cfg)
    assert vr.get("verdict") == "needs_human", vr
    f = db.get_finding(fid)
    assert f.state == "needs_human"

    assert (
        is_shallow(
            {"tools_used": ["ghidra_import_callers", "ghidra_decompile"]},
            profile="binary_re",
        )
        is False
    )

    db.close()


def test_binary_re_depth_not_shallow_with_import_callers_only():
    # import_callers alone is a deep tool for binary_re
    assert (
        is_shallow({"tools_used": ["ghidra_import_callers"]}, profile="binary_re")
        is False
    )
    assert is_shallow({"tools_used": ["ghidra_imports"]}, profile="binary_re") is True
