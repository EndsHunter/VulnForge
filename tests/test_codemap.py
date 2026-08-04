"""Tests for mechanical codemap (structure scaffold, not architecture)."""

from __future__ import annotations

from pathlib import Path

from vulnforge.db import Database
from vulnforge.stages.render import write_codemap_md
from vulnforge.tools.codemap import (
    build_codemap,
    merge_annotations_into_codemap,
    nearest_module,
    path_hints_for_area,
    slice_codemap,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
MONO_SYNTH = FIXTURES / "mono_synth"
TOY_SQLI_APP = FIXTURES / "toy_sqli" / "app.py"


def _module_paths(cm: dict) -> list[str]:
    return [
        str(m.get("path") or "")
        for m in (cm.get("modules") or [])
        if isinstance(m, dict)
    ]


def _module_labels(cm: dict) -> set[str]:
    out: set[str] = set()
    for m in cm.get("modules") or []:
        if not isinstance(m, dict):
            continue
        if m.get("label"):
            out.add(str(m["label"]).lower())
        if m.get("path"):
            out.add(str(m["path"]).replace("\\", "/").lower())
    return out


def test_build_codemap_mono_synth():
    assert MONO_SYNTH.is_dir(), f"missing fixture {MONO_SYNTH}"
    cm = build_codemap(MONO_SYNTH)
    assert cm["target_kind"] == "directory"
    assert cm.get("version") == 2
    assert "files" in cm and "symbols" in cm
    assert int((cm.get("summary") or {}).get("file_count") or 0) > 0

    labels = _module_labels(cm)
    for expected in ("packages/api", "packages/auth", "packages/ui", "packages/worker"):
        assert any(
            expected in p or expected.split("/")[-1] in labels
            for p in labels
        ), f"expected module around {expected}, got modules={_module_paths(cm)}"

    ep_paths = [
        str(e.get("path") or "")
        for e in (cm.get("entrypoints") or [])
        if isinstance(e, dict)
    ]
    assert any(
        p.endswith("pyproject.toml") or p == "pyproject.toml" for p in ep_paths
    ), f"expected pyproject.toml entrypoint, got {ep_paths}"


def test_build_codemap_single_file():
    assert TOY_SQLI_APP.is_file(), f"missing fixture {TOY_SQLI_APP}"
    cm = build_codemap(TOY_SQLI_APP)
    assert cm["target_kind"] == "single_file"
    modules = cm.get("modules") or []
    assert len(modules) == 1
    m0 = modules[0]
    assert m0.get("kind") == "file"
    assert "app.py" in str(m0.get("path") or "")
    assert int((cm.get("summary") or {}).get("file_count") or 0) == 1


def test_slice_codemap_path_hints_auth():
    cm = build_codemap(MONO_SYNTH)
    sliced = slice_codemap(cm, path_hints=["packages/auth"])
    paths = _module_paths(sliced)
    assert paths, "slice should return at least one module"
    # Must include auth; may include ancestor packages/* only as structural parent
    assert any(
        p == "packages/auth" or p.startswith("packages/auth") or p.endswith("/auth")
        for p in paths
    ), f"expected packages/auth in slice, got {paths}"
    non_auth = [
        p
        for p in paths
        if "auth" not in p.lower() and p not in ("packages", "apps", "services", "src", "libs")
    ]
    assert not non_auth, f"expected primarily auth-related modules, got {paths}"


def test_path_hints_for_area_auth():
    cm = build_codemap(MONO_SYNTH)
    hints = path_hints_for_area(cm, "auth")
    assert hints, "expected path hints for auth area"
    assert any(
        "auth" in h.lower() or h.startswith("packages/auth") for h in hints
    ), f"expected packages/auth-related hints, got {hints}"


def test_nearest_module_auth_session():
    cm = build_codemap(MONO_SYNTH)
    m = nearest_module(cm, "packages/auth/session.py")
    assert m is not None
    path = str(m.get("path") or "").replace("\\", "/")
    assert path == "packages/auth" or path.startswith("packages/auth"), path


def test_db_codemap_roundtrip(tmp_path: Path):
    db = Database.create(tmp_path / "harness.db")
    db.insert_run(
        "run-001",
        target_path=str(tmp_path / "tgt"),
        profile="code_static",
        prompt_pin="pin",
        config={},
    )
    cm = build_codemap(MONO_SYNTH)
    db.set_codemap(cm, source="mechanical")
    loaded = db.get_codemap()
    assert loaded is not None
    assert loaded.get("target_kind") == cm.get("target_kind")
    assert len(loaded.get("modules") or []) == len(cm.get("modules") or [])
    assert int((loaded.get("summary") or {}).get("file_count") or 0) > 0
    db.close()


def test_merge_annotations_into_codemap():
    cm = build_codemap(MONO_SYNTH)
    notes = [
        {
            "kind": "codemap",
            "task_id": 1,
            "payload": {
                "path": "packages/auth/session.py",
                "symbol": "create_session",
                "note": "session mint boundary",
            },
        },
        {
            "kind": "wishlist",
            "task_id": 2,
            "payload": {"text": "ignore me"},
        },
    ]
    merged = merge_annotations_into_codemap(cm, notes)
    anns = merged.get("annotations") or []
    assert anns, "expected codemap annotations"
    assert any(
        "session mint" in str(a.get("note") or "")
        and "packages/auth/session.py" in str(a.get("path") or "")
        for a in anns
        if isinstance(a, dict)
    )
    # wishlist must not become annotation
    assert not any("ignore me" in str(a.get("note") or "") for a in anns)
    assert merged.get("source") in ("merge", "mechanical")


def test_write_codemap_md_has_modules_section(tmp_path: Path):
    db = Database.create(tmp_path / "harness.db")
    db.insert_run(
        "run-001",
        target_path=str(tmp_path / "tgt"),
        profile="code_static",
        prompt_pin="pin",
        config={},
    )
    db.set_codemap(build_codemap(MONO_SYNTH), source="mechanical")
    out = tmp_path / "CODEMAP.md"
    write_codemap_md(out, db)
    text = out.read_text(encoding="utf-8")
    assert "## Modules" in text
    assert "packages/auth" in text or "auth" in text
    db.close()


def test_max_modules_cap():
    cm = build_codemap(MONO_SYNTH, cfg={"codemap": {"max_modules": 2}})
    modules = cm.get("modules") or []
    assert len(modules) <= 2
