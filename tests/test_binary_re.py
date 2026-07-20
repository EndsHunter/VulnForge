"""Tests for binary_re profile, Ghidra client, and single-file init."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vulnforge.cli import EXIT_CONFIG, EXIT_PROGRESS, main
from vulnforge.db import Database
from vulnforge.findings.identity import compute_stable_key
from vulnforge.ghidra.client import GhidraClient, GhidraError
from vulnforge.packet import tool_schemas_for
from vulnforge.profiles import get_profile
from vulnforge.profiles.binary_re import BinaryReProfile, ConfigError
from vulnforge.stages.hunt import validate_candidate_shape
from vulnforge.stages.validate_mech import (
    check_binary_address_present,
    check_citations_resolve,
    check_target_unmodified,
)
from vulnforge.tools.ghidra_tools import (
    ghidra_decompile,
    ghidra_import_callers,
    ghidra_imports,
    ghidra_status,
)
from vulnforge.util import build_single_file_manifest, build_target_manifest, write_json


def _tiny_pe(path: Path) -> Path:
    """Write a minimal non-functional PE-like file (just MZ header + padding)."""
    # Not a valid PE for Ghidra; fine for init/manifest/auth tests.
    data = b"MZ" + b"\x00" * 62 + b"PE\x00\x00" + b"\x00" * 200
    path.write_bytes(data)
    return path


def test_binary_re_profile_registered():
    p = get_profile("binary_re")
    assert p.name == "binary_re"
    tools = p.allowed_tools()
    assert "ghidra_decompile" in tools
    assert "ghidra_import_callers" in tools
    assert "submit_candidate" in tools
    assert "grep" not in tools


def test_binary_re_paths_are_project_relative():
    """Defaults resolve under project root (portable ./ghidra layout)."""
    from vulnforge.ghidra.paths import project_root, resolve_path
    from vulnforge.profiles.binary_re import BinaryReProfile

    p = BinaryReProfile()
    cfg = {
        "binary_re": {
            "ghidra_install_dir": "ghidra",
            "headless_script": "scripts/start_ghidra_mcp_headless.ps1",
        }
    }
    br = p.binary_re_config(cfg)
    root = project_root()
    assert Path(br["ghidra_install_dir"]) == (root / "ghidra").resolve()
    assert resolve_path("ghidra") == (root / "ghidra").resolve()
    # Runtime command is absolute (correct) but rooted under this project
    cmd = br.get("headless_command")
    assert cmd, "expected auto headless_command"
    joined = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
    assert "start_ghidra_mcp_headless.ps1" in joined
    assert str(root) in joined


def test_authorization_gate():
    p = BinaryReProfile()
    with pytest.raises(ConfigError):
        p.require_authorization_flag({"binary_re": {"i_am_authorized": False}})
    p.require_authorization_flag({"binary_re": {"i_am_authorized": True}})
    p.require_authorization_flag({"run": {"binary_re_authorized": True}})


def test_validate_target_pe_only(tmp_path: Path):
    p = BinaryReProfile()
    pe = _tiny_pe(tmp_path / "app.exe")
    assert p.validate_target(pe, {}) is None
    bad = tmp_path / "app.elf"
    bad.write_bytes(b"\x7fELF")
    assert p.validate_target(bad, {}) is not None
    assert p.validate_target(tmp_path, {}) is not None


def test_single_file_manifest(tmp_path: Path):
    pe = _tiny_pe(tmp_path / "toy.dll")
    man = build_target_manifest(pe)
    assert man["kind"] == "single_binary"
    assert man["file_count"] == 1
    assert "toy.dll" in man["files"]
    assert man["binary"]["sha256"]


def test_tool_schemas_binary_re():
    recon = tool_schemas_for("binary_re", "recon", apply_defaults=False)
    names = {(t.get("function") or {}).get("name") for t in recon}
    assert "ghidra_imports" in names
    assert "ghidra_import_callers" in names
    assert "submit_architecture" in names
    assert "grep" not in names
    hunt = tool_schemas_for("binary_re", "hunt", apply_defaults=False)
    hnames = {(t.get("function") or {}).get("name") for t in hunt}
    assert "ghidra_decompile" in hnames
    assert "ghidra_import_callers" in hnames
    assert "submit_candidate" in hnames
    assert "request_hunt" in hnames
    # Schema nudges agents to decompile callers, not IAT stubs
    imp_schema = next(
        t
        for t in hunt
        if (t.get("function") or {}).get("name") == "ghidra_import_callers"
    )
    desc = (imp_schema.get("function") or {}).get("description") or ""
    assert "caller" in desc.lower()


def test_ghidra_client_allowlist():
    c = GhidraClient("http://127.0.0.1:9")
    with pytest.raises(GhidraError, match="allowlisted"):
        c.request("GET", "rename_function")


def test_ghidra_tools_with_mock_client():
    class Fake:
        base_url = "http://fake"

        def check_connection(self):
            return {"ok": True, "text": "Connected"}

        def get_version(self):
            return {"version": "test"}

        def decompile_function(self, name):
            return {"code": f"void {name}() {{}}"}

    ctx = {"ghidra_client": Fake(), "cfg": {"binary_re": {}}}
    st = ghidra_status(ctx)
    assert st["ok"] is True
    de = ghidra_decompile(ctx, name="FUN_401000")
    assert de["ok"] is True


class _FakeImportsClient:
    """Fake Ghidra client for imports filter + import_callers."""

    base_url = "http://fake"

    def __init__(self) -> None:
        self.imports = [
            {"name": "memcpy", "address": "0x401000"},
            {"name": "memmove", "address": "0x401010"},
            {"name": "CreateProcessW", "address": "0x401020"},
            {"name": "LoadLibraryA", "address": "0x401030"},
            {"name": "strcpy", "address": "0x401040"},
        ]
        self.xrefs = {
            "0x401000": [
                {"from": "0x402100", "to": "0x401000"},
                {"from": "0x403200", "to": "0x401000"},
            ]
        }
        self.functions_at = {
            "0x402100": {"name": "parse_packet", "address": "0x402000"},
            "0x403200": {"name": "copy_user", "address": "0x403000"},
        }

    def check_connection(self):
        return {"ok": True}

    def list_imports(self, *, offset: int = 0, limit: int = 200, filter_text=None):
        items = list(self.imports)
        # Server-side filter optional; tool still filters client-side.
        if filter_text:
            n = str(filter_text).lower()
            items = [i for i in items if n in i["name"].lower()]
        return items[int(offset) : int(offset) + int(limit)]

    def get_function_callers(self, name_or_address: str):
        # Simulate empty callers API so tool falls back to xrefs.
        return []

    def get_xrefs_to(self, address: str):
        return list(self.xrefs.get(address, []))

    def get_function_by_address(self, address: str):
        if address in self.functions_at:
            return self.functions_at[address]
        raise GhidraError(f"no function at {address}")


def test_ghidra_imports_filter_matches_names():
    ctx = {"ghidra_client": _FakeImportsClient(), "cfg": {"binary_re": {}}}
    out = ghidra_imports(ctx, filter="mem", limit=10)
    assert out["ok"] is True
    data = out["data"]
    names = {_item_name(i) for i in data["imports"]}
    assert names == {"memcpy", "memmove"}
    assert data["match_count"] == 2
    assert data["filter"] == "mem"
    # alias name_filter
    out2 = ghidra_imports(ctx, name_filter="CreateProcess", limit=5)
    assert out2["ok"] is True
    assert out2["data"]["match_count"] == 1
    assert _item_name(out2["data"]["imports"][0]) == "CreateProcessW"


def _item_name(item):
    if isinstance(item, dict):
        return item.get("name") or ""
    return str(item)


def test_ghidra_import_callers_via_xrefs():
    ctx = {"ghidra_client": _FakeImportsClient(), "cfg": {"binary_re": {}}}
    out = ghidra_import_callers(ctx, symbol="memcpy", limit=40)
    assert out["ok"] is True
    data = out["data"]
    assert data["symbol"] == "memcpy"
    assert data["import_address"] == "0x401000"
    callers = data["callers"]
    assert len(callers) == 2
    by_name = {c["name"]: c for c in callers}
    assert "parse_packet" in by_name
    assert by_name["parse_packet"]["address"] == "0x402000"
    assert by_name["parse_packet"]["xref_from"] == "0x402100"
    assert "copy_user" in by_name


def test_ghidra_import_callers_requires_symbol_or_address():
    ctx = {"ghidra_client": _FakeImportsClient(), "cfg": {"binary_re": {}}}
    out = ghidra_import_callers(ctx)
    assert out["ok"] is False
    assert "symbol or address" in out["error"].lower()


def test_ghidra_import_callers_empty_still_ok():
    fake = _FakeImportsClient()
    fake.xrefs = {}
    ctx = {"ghidra_client": fake, "cfg": {"binary_re": {}}}
    out = ghidra_import_callers(ctx, symbol="strcpy")
    assert out["ok"] is True
    assert out["data"]["callers"] == []
    assert out["data"]["notes"]


def test_validate_candidate_binary_citation():
    errs = validate_candidate_shape(
        {
            "title": "Stack overflow in parse",
            "summary": "Unbounded copy in parse_pkt",
            "weakness_class": "memory-safety",
            "threat_model": {
                "attacker": "network peer",
                "boundary": "packet parser",
                "impact": "RCE via stack smash",
            },
            "citations": [{"address": "0x401234", "symbol": "parse_pkt"}],
        }
    )
    assert errs == []


def test_stable_key_includes_address():
    body = {
        "sink_path": "app.exe",
        "sink_symbol": "parse",
        "sink_address": "0x401000",
        "weakness_class": "overflow",
        "threat_model": {"attacker": "remote"},
    }
    k1 = compute_stable_key("binary_re", body)
    body2 = dict(body)
    body2["sink_address"] = "0x402000"
    k2 = compute_stable_key("binary_re", body2)
    assert k1 != k2


def test_init_binary_re_requires_auth(tmp_path: Path):
    pe = _tiny_pe(tmp_path / "app.exe")
    runs = tmp_path / "runs"
    code = main(
        [
            "init",
            "--target",
            str(pe),
            "--profile",
            "binary_re",
            "--runs-root",
            str(runs),
            "--skip-ghidra-init",
        ]
    )
    assert code == EXIT_CONFIG


def test_init_binary_re_ok(tmp_path: Path):
    pe = _tiny_pe(tmp_path / "app.exe")
    runs = tmp_path / "runs"
    code = main(
        [
            "init",
            "--target",
            str(pe),
            "--profile",
            "binary_re",
            "--i-am-authorized-for-binary-re",
            "--runs-root",
            str(runs),
            "--skip-ghidra-init",
        ]
    )
    assert code == EXIT_PROGRESS
    targets = list(runs.iterdir())
    assert len(targets) == 1
    run_dir = next(targets[0].iterdir())
    man = json.loads((run_dir / "target_manifest.json").read_text(encoding="utf-8"))
    assert man.get("kind") == "single_binary"
    db = Database.open(run_dir / "harness.db")
    try:
        run = db.get_run()
        assert run["profile"] == "binary_re"
        cfg = json.loads(run["config_json"])
        assert cfg["run"]["binary_re_authorized"] is True
        assert set(cfg["run"]["hunt_skill_ids"]) >= {
            "bin-memory-safety",
            "bin-dangerous-apis",
        }
        tasks = db.list_tasks(limit=20)
        assert any(t.kind == "recon" for t in tasks)
    finally:
        db.close()


def test_mech_binary_citations(tmp_path: Path, toy_sqli: Path):
    pe = _tiny_pe(tmp_path / "app.exe")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    man = build_single_file_manifest(pe)
    write_json(run_dir / "target_manifest.json", man)

    db = MagicMock()
    db.get_run.return_value = {
        "target_path": str(pe),
        "profile": "binary_re",
    }

    class F:
        body = {
            "citations": [{"path": "app.exe", "address": "0x401000", "symbol": "f"}],
            "sink_address": "0x401000",
        }

    f = F()
    ok, reason = check_citations_resolve(f, run_dir, {}, db)
    assert ok, reason
    ok2, reason2 = check_target_unmodified(f, run_dir, {}, db)
    assert ok2, reason2
    ok3, reason3 = check_binary_address_present(f, run_dir, {}, db)
    assert ok3, reason3
