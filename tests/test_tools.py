from __future__ import annotations

from pathlib import Path

from vulnforge.stages.hunt import prepare_candidate_submission
from vulnforge.tools import build_tool_handler
from vulnforge.tools.fs_read import resolve_target_path
from vulnforge.tools.grep_index import build_file_index
import pytest


def test_build_file_index(toy_sqli: Path):
    inv = build_file_index(toy_sqli, [])
    assert inv["file_count"] >= 1
    assert any("app.py" in p for p in inv["sample_paths"])


def test_path_escape(toy_sqli: Path):
    with pytest.raises(PermissionError):
        resolve_target_path(toy_sqli, "../outside")


def test_read_grep_evidence(toy_sqli: Path, tmp_path: Path):
    ctx = {
        "target_root": str(toy_sqli),
        "evidence_root": str(tmp_path / "evidence"),
        "task_id": 1,
        "cfg": {"tools": {}, "run": {"ignore_globs": []}},
        "session": {},
    }
    h = build_tool_handler(ctx)
    listed = h("list_dir", {"path": "."})
    assert listed["ok"]
    rd = h("read_file", {"path": "app.py"})
    assert rd["ok"]
    assert "search_users" in rd["content"]
    g = h("grep", {"pattern": "SELECT"})
    assert g["ok"]
    assert g["matches"]
    ev = h(
        "write_evidence",
        {"relpath": "note.txt", "content": "poc notes with enough bytes"},
    )
    assert ev["ok"]
    assert (tmp_path / "evidence" / "1" / "note.txt").is_file()
    # escape evidence via relpath
    bad = h(
        "write_evidence",
        {"relpath": "../x.txt", "content": "no path escape content here"},
    )
    assert not bad["ok"]


def test_file_inventory_tree_and_extension(tmp_path: Path):
    root = tmp_path / "tgt"
    (root / "pkg" / "sub").mkdir(parents=True)
    (root / "pkg" / "a.py").write_text("print(1)\n", encoding="utf-8")
    (root / "pkg" / "sub" / "b.cu").write_text("// cuda\n", encoding="utf-8")
    (root / "pkg" / "sub" / "c.go").write_text("package sub\n", encoding="utf-8")
    (root / "readme.md").write_text("# x\n", encoding="utf-8")
    ctx = {
        "target_root": str(root),
        "cfg": {"tools": {"max_inventory_entries": 500}, "run": {"ignore_globs": []}},
        "session": {},
    }
    h = build_tool_handler(ctx)
    inv = h("file_inventory", {"path": ".", "format": "both"})
    assert inv["ok"], inv
    assert inv["file_count"] >= 4
    assert "tree" in inv and "pkg/" in inv["tree"]
    assert any(p.endswith("a.py") for p in inv["files"])

    cu = h("file_inventory", {"extension": "cu", "format": "list"})
    assert cu["ok"], cu
    assert cu["file_count"] == 1
    assert cu["files"][0].endswith("b.cu")

    # Aliases from tool-gap transcripts
    alias = h("directory_tree", {"path": "pkg", "format": "tree"})
    assert alias["ok"], alias
    assert "file_inventory" in ctx["session"]["tools_used"]


def test_grep_extension_files_only_and_empty_hint(tmp_path: Path):
    root = tmp_path / "tgt"
    root.mkdir()
    (root / "a.py").write_text("SELECT 1\n", encoding="utf-8")
    (root / "b.cu").write_text("kernel\n", encoding="utf-8")
    (root / "c.cu").write_text("other\n", encoding="utf-8")
    ctx = {
        "target_root": str(root),
        "cfg": {"tools": {}, "run": {"ignore_globs": []}},
        "session": {},
    }
    h = build_tool_handler(ctx)

    # File-type filter + files_only
    g = h(
        "grep",
        {"pattern": "kernel", "extension": ".cu", "files_only": True},
    )
    assert g["ok"], g
    assert g.get("files_only")
    assert g["paths"] == ["b.cu"]

    # Empty pattern + extension → list files of that type (path discovery)
    listed = h("grep", {"pattern": "", "extension": "cu"})
    assert listed["ok"], listed
    assert set(listed.get("paths") or []) == {"b.cu", "c.cu"}

    # match_path for filename search
    by_name = h("grep", {"pattern": r"b\.cu$", "match_path": True, "files_only": True})
    assert by_name["ok"], by_name
    assert "b.cu" in (by_name.get("paths") or [])

    # Empty content search should carry a thrash-reduction hint
    miss = h("grep", {"pattern": "definitely_not_in_tree_zz"})
    assert miss["ok"]
    assert miss["matches"] == []
    assert "file_inventory" in (miss.get("hint") or "")


def test_write_evidence_rejects_path_escape_evidence_id(toy_sqli: Path, tmp_path: Path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    ctx = {
        "target_root": str(toy_sqli),
        "evidence_root": str(evidence_root),
        "task_id": 1,
        "cfg": {"tools": {}, "run": {"ignore_globs": []}},
        "session": {},
    }
    h = build_tool_handler(ctx)
    for bad_id in ("../outside", "..\\outside", "/tmp/evil", "foo/bar", "foo\\bar", ".."):
        before = list(outside.iterdir()) if outside.is_dir() else []
        r = h(
            "write_evidence",
            {
                "relpath": "pwned.txt",
                "content": "should-not-write path-escape probe content",
                "evidence_id": bad_id,
            },
        )
        assert not r["ok"], f"expected reject for evidence_id={bad_id!r}: {r}"
        assert not (outside / "pwned.txt").exists()
        assert not (tmp_path / "pwned.txt").exists()
        # nothing new under outside
        assert list(outside.iterdir()) == before
        # never create escaped paths as evidence children
        assert not any(evidence_root.glob("**/pwned.txt"))


def _candidate_body(**extra):
    body = {
        "title": "SQL injection in search_users",
        "summary": "User input is concatenated into SQL.",
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "unauthenticated user",
            "boundary": "HTTP query parameter to SQL engine",
            "impact": "read or modify arbitrary user rows",
        },
        "citations": [{"path": "app.py", "start_line": 10}],
    }
    body.update(extra)
    return body


def test_submit_candidate_requires_evidence(toy_sqli: Path, tmp_path: Path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    session: dict = {
        "candidate": None,
        "tools_used": [],
        "evidence_id": None,
        "evidence_ids_written": [],
    }

    def _submit_candidate(body: dict) -> dict:
        prepared, err = prepare_candidate_submission(body, session, evidence_root)
        if err is not None:
            return err
        session["candidate"] = prepared
        return {
            "ok": True,
            "stored": "candidate",
            "evidence_id": prepared.get("evidence_id"),
        }

    ctx = {
        "target_root": str(toy_sqli),
        "evidence_root": str(evidence_root),
        "task_id": 9,
        "cfg": {"tools": {}, "run": {"ignore_globs": []}},
        "session": session,
        "submit_candidate": _submit_candidate,
    }
    h = build_tool_handler(ctx)
    body = _candidate_body()

    # No write_evidence yet â†’ refuse
    r = h("submit_candidate", body)
    assert not r["ok"]
    assert "write_evidence" in (r.get("error") or "")
    assert session["candidate"] is None

    # After write_evidence, auto-inject evidence_id and accept
    ev = h(
        "write_evidence",
        {"relpath": "poc_notes.md", "content": "payload: ' OR 1=1 -- steps"},
    )
    assert ev["ok"]
    assert session.get("evidence_id")
    assert session.get("evidence_ids_written")
    r2 = h("submit_candidate", body)
    assert r2["ok"], r2
    assert session["candidate"]["evidence_id"] == session["evidence_id"]


def test_prepare_candidate_rejects_missing_evidence_without_session(tmp_path: Path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    session = {"tools_used": [], "evidence_id": None, "evidence_ids_written": []}
    prepared, err = prepare_candidate_submission(
        _candidate_body(), session, evidence_root
    )
    assert prepared is None
    assert err and not err["ok"]
    assert "write_evidence" in err["error"]


def test_prepare_candidate_rejects_foreign_evidence_id(tmp_path: Path):
    """M1: pre-existing pack on disk without write_evidence this session is free-ride."""
    evidence_root = tmp_path / "evidence"
    pack = evidence_root / "foreign-pack"
    pack.mkdir(parents=True)
    (pack / "note.txt").write_text("pre-existing foreign evidence pack notes\n")
    session = {"tools_used": [], "evidence_id": None, "evidence_ids_written": []}
    prepared, err = prepare_candidate_submission(
        _candidate_body(evidence_id="foreign-pack"), session, evidence_root
    )
    assert prepared is None
    assert err and not err["ok"]
    assert "foreign" in err["error"].lower() or "write_evidence" in err["error"]


def test_prepare_candidate_rejects_undersized_session_write(
    toy_sqli: Path, tmp_path: Path
):
    """M3: submit must not accept a pack that would fail mech min-byte gate."""
    from vulnforge.tools.evidence_write import MIN_EVIDENCE_FILE_BYTES

    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    # Simulate a session that claims a write without meeting min size on disk
    pack = evidence_root / "tiny"
    pack.mkdir()
    (pack / "x.txt").write_text("x")  # 1 byte < MIN
    session = {
        "tools_used": ["write_evidence"],
        "evidence_id": "tiny",
        "evidence_ids_written": ["tiny"],
    }
    prepared, err = prepare_candidate_submission(
        _candidate_body(evidence_id="tiny"), session, evidence_root
    )
    assert prepared is None
    assert err and not err["ok"]
    assert str(MIN_EVIDENCE_FILE_BYTES) in err["error"] or "non-vacuous" in err["error"]


def test_write_evidence_rejects_undersized_content(toy_sqli: Path, tmp_path: Path):
    ctx = {
        "target_root": str(toy_sqli),
        "evidence_root": str(tmp_path / "evidence"),
        "task_id": 1,
        "cfg": {"tools": {}, "run": {"ignore_globs": []}},
        "session": {},
    }
    h = build_tool_handler(ctx)
    r = h("write_evidence", {"relpath": "tiny.txt", "content": "x"})
    assert not r["ok"]
    assert "small" in (r.get("error") or "").lower()


def test_prepare_candidate_enforces_poc_relpath(tmp_path: Path):
    """M2/M3: when poc_relpath set, that file must exist and meet min size."""
    evidence_root = tmp_path / "evidence"
    pack = evidence_root / "e1"
    pack.mkdir(parents=True)
    (pack / "other.txt").write_text("other file with enough content bytes here\n")
    session = {
        "tools_used": ["write_evidence"],
        "evidence_id": "e1",
        "evidence_ids_written": ["e1"],
    }
    prepared, err = prepare_candidate_submission(
        _candidate_body(evidence_id="e1", poc_relpath="poc.md"),
        session,
        evidence_root,
    )
    assert prepared is None
    assert err and not err["ok"]
    assert "poc" in err["error"].lower()

    (pack / "poc.md").write_text("actual poc steps with enough content bytes\n")
    prepared2, err2 = prepare_candidate_submission(
        _candidate_body(evidence_id="e1", poc_relpath="poc.md"),
        session,
        evidence_root,
    )
    assert err2 is None, err2
    assert prepared2 is not None
    assert prepared2["evidence_id"] == "e1"


def _hash_tree(root: Path) -> dict[str, str]:
    from vulnforge.util import hash_file, normalize_relpath

    out: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            rel = normalize_relpath(str(p.relative_to(root)))
            out[rel] = hash_file(p)
    return out


def test_agent_tools_do_not_mutate_target(tmp_path: Path):
    """Built-in tools leave the audit target tree byte-identical."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n# SELECT users\n", encoding="utf-8")
    (target / "sub").mkdir()
    (target / "sub" / "b.py").write_text("print(2)\n", encoding="utf-8")
    evidence = tmp_path / "evidence"
    before = _hash_tree(target)
    ctx = {
        "target_root": str(target),
        "evidence_root": str(evidence),
        "task_id": 42,
        "cfg": {"tools": {}, "run": {"ignore_globs": []}},
        "session": {},
    }
    h = build_tool_handler(ctx)
    assert h("list_dir", {"path": "."})["ok"]
    assert h("file_inventory", {"path": ".", "format": "list"})["ok"]
    assert h("read_file", {"path": "app.py"})["ok"]
    assert h("grep", {"pattern": "SELECT"})["ok"]
    assert h(
        "write_evidence",
        {"relpath": "note.txt", "content": "poc notes with enough bytes for gate"},
    )["ok"]
    assert h("note", {"kind": "wishlist", "payload": {"msg": "x"}})["ok"]
    after = _hash_tree(target)
    assert after == before
    assert (evidence / "42" / "note.txt").is_file()


def test_write_evidence_rejects_evidence_under_target(tmp_path: Path):
    """Mis-set evidence_root inside target must not write into the audit tree."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("ok\n", encoding="utf-8")
    nested = target / "evidence_oops"
    nested.mkdir()
    before = _hash_tree(target)
    ctx = {
        "target_root": str(target),
        "evidence_root": str(nested),
        "task_id": 1,
        "cfg": {"tools": {}},
        "session": {},
    }
    h = build_tool_handler(ctx)
    r = h(
        "write_evidence",
        {"relpath": "evil.txt", "content": "should not land under target tree xx"},
    )
    assert not r["ok"]
    assert "target" in (r.get("error") or "").lower() or "evidence_root" in (
        r.get("error") or ""
    ).lower()
    assert _hash_tree(target) == before
