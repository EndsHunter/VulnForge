"""Function-level codemap symbols + area slices for hunts."""

from __future__ import annotations

import json
from pathlib import Path

from vulnforge.db import Database
from vulnforge.tools.codemap import (
    build_codemap,
    format_codemap_for_packet,
    slim_codemap_for_ui,
    slice_codemap,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
MONO_SYNTH = FIXTURES / "mono_synth"
TOY_SQLI_APP = FIXTURES / "toy_sqli" / "app.py"


def test_build_codemap_v2_has_symbols_mono_synth():
    cm = build_codemap(MONO_SYNTH, cfg={"codemap": {"symbol_backend": "heuristic"}})
    assert cm.get("version") == 2
    assert "symbols" in cm and "files" in cm
    assert isinstance(cm["symbols"], list)
    assert len(cm["symbols"]) > 0
    names = {str(s.get("name")) for s in cm["symbols"] if isinstance(s, dict)}
    # auth/session.py fixture
    assert "issue_token" in names or "verify_token" in names
    assert int((cm.get("summary") or {}).get("symbol_count") or 0) == len(cm["symbols"])
    assert (cm.get("summary") or {}).get("symbol_backend") in (
        "heuristic",
        "tree_sitter",
        "partial",
        "auto",
    )


def test_build_codemap_single_file_symbols():
    cm = build_codemap(TOY_SQLI_APP, cfg={"codemap": {"symbol_backend": "heuristic"}})
    assert cm["target_kind"] == "single_file"
    names = {str(s.get("name")) for s in (cm.get("symbols") or []) if isinstance(s, dict)}
    assert "search_users" in names
    assert any(s.get("kind") == "function" for s in cm["symbols"] if isinstance(s, dict))


def test_full_store_slice_area_only():
    cm = build_codemap(MONO_SYNTH, cfg={"codemap": {"symbol_backend": "heuristic"}})
    full_n = len(cm.get("symbols") or [])
    assert full_n > 0

    sliced = slice_codemap(
        cm,
        path_hints=["packages/auth"],
        max_modules=8,
        max_files=40,
        max_symbols=60,
        include_symbols=True,
    )
    assert sliced.get("modules")
    for m in sliced["modules"]:
        p = str(m.get("path") or "")
        assert "auth" in p.lower() or p in ("packages",)

    for s in sliced.get("symbols") or []:
        sp = str(s.get("path") or "").replace("\\", "/")
        assert "auth" in sp.lower() or sp.startswith("packages/auth")

    # Slice must not be the entire monorepo dump when other packages exist
    other = [
        s
        for s in (cm.get("symbols") or [])
        if isinstance(s, dict)
        and "auth" not in str(s.get("path") or "").lower()
    ]
    if other:
        slice_paths = {
            str(s.get("path") or "") for s in (sliced.get("symbols") or [])
        }
        for s in other:
            assert str(s.get("path") or "") not in slice_paths or "auth" in str(
                s.get("path") or ""
            ).lower()


def test_format_packet_area_includes_signatures_not_full_dump():
    cm = build_codemap(MONO_SYNTH, cfg={"codemap": {"symbol_backend": "heuristic"}})
    txt = format_codemap_for_packet(
        cm,
        max_chars=8000,
        path_hints=["packages/auth"],
        area="auth",
        sliced=True,
        cfg={"codemap": {"packet_max_symbols": 30, "symbol_backend": "heuristic"}},
        include_symbols=True,
    )
    assert txt != "(no codemap)"
    assert "issue_token" in txt or "verify_token" in txt or "symbols" in txt
    # Recon-style: no bulk symbols
    recon = format_codemap_for_packet(
        cm,
        max_chars=4000,
        sliced=False,
        include_symbols=False,
        cfg={"codemap": {"symbol_backend": "heuristic"}},
    )
    data = json.loads(recon.split("…")[0] if "…(truncated)" in recon else recon)
    assert not data.get("symbols")


def test_db_stores_full_symbols(tmp_path: Path):
    db = Database.create(tmp_path / "harness.db")
    db.insert_run(
        "run-001",
        target_path=str(tmp_path / "tgt"),
        profile="code_static",
        prompt_pin="pin",
        config={},
    )
    cm = build_codemap(MONO_SYNTH, cfg={"codemap": {"symbol_backend": "heuristic"}})
    db.set_codemap(cm, source="mechanical")
    loaded = db.get_codemap()
    assert loaded is not None
    assert len(loaded.get("symbols") or []) == len(cm.get("symbols") or [])
    assert loaded.get("version") == 2
    db.close()


def test_slim_ui_omits_symbols():
    cm = build_codemap(MONO_SYNTH, cfg={"codemap": {"symbol_backend": "heuristic"}})
    slim = slim_codemap_for_ui(cm, include_symbols=False)
    assert slim is not None
    assert slim.get("symbols_omitted") is True
    assert slim.get("symbols") == []
    assert slim.get("modules")
    with_path = slim_codemap_for_ui(
        cm, include_symbols=False, path="packages/auth", max_symbols=20
    )
    assert with_path is not None
    assert isinstance(with_path.get("symbols"), list)
    assert len(with_path["symbols"]) > 0


def test_symbols_disabled():
    cm = build_codemap(
        MONO_SYNTH,
        cfg={"codemap": {"symbols_enabled": False}},
    )
    assert cm.get("symbols") == []
    assert (cm.get("summary") or {}).get("symbol_backend") == "none"
