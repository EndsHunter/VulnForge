"""Tool schema clarity: agents get when-to-use and param semantics in-schema."""

from __future__ import annotations

from vulnforge.packet import tool_schemas_for


def _by_name(stage: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for t in tool_schemas_for("code_static", stage, apply_defaults=False):
        fn = t.get("function") or {}
        name = fn.get("name")
        if name:
            out[str(name)] = fn
    return out


def test_read_file_documents_line_indexing_and_paths():
    fn = _by_name("recon")["read_file"]
    desc = (fn.get("description") or "").lower()
    assert "1-based" in desc or "1-based" in str(fn.get("parameters")).lower()
    props = (fn.get("parameters") or {}).get("properties") or {}
    assert "path" in props
    assert "start_line" in props and "end_line" in props
    assert props["path"].get("description")
    assert "1-based" in (props["start_line"].get("description") or "").lower()


def test_grep_documents_narrowing_and_empty_pattern_mode():
    fn = _by_name("recon")["grep"]
    desc = fn.get("description") or ""
    assert "extension" in desc.lower() or "glob" in desc.lower()
    assert "empty" in desc.lower()
    props = (fn.get("parameters") or {}).get("properties") or {}
    for key in (
        "pattern",
        "glob",
        "extension",
        "files_only",
        "match_path",
        "max_matches",
        "path",
        "context",
        "case_insensitive",
        "literal",
    ):
        assert key in props
        assert props[key].get("description"), f"{key} needs description"


def test_read_file_documents_around_line_and_batch():
    fn = _by_name("hunt")["read_file"]
    props = (fn.get("parameters") or {}).get("properties") or {}
    assert "around_line" in props
    assert "radius" in props
    assert "paths" in props


def test_query_and_preflight_schemas_present():
    hunt = _by_name("hunt")
    assert "query_sinks" in hunt
    assert "query_codemap" in hunt
    assert "find_symbol" in hunt
    assert "preflight_candidate" in hunt
    assert "get_architecture" in hunt
    assert "list_evidence" in hunt
    assert "read_evidence" in hunt


def test_submit_architecture_finish_contract():
    fn = _by_name("recon")["submit_architecture"]
    desc = (fn.get("description") or "").lower()
    assert "finish" in desc or "done" in desc
    assert "summary" in desc
    assert "submit_candidate" in desc  # forbid in recon
    props = (fn.get("parameters") or {}).get("properties") or {}
    assert props["summary"].get("description")
    assert "hunt_focus" in props


def test_submit_candidate_and_none_finish_contracts():
    tools = _by_name("hunt")
    cand = tools["submit_candidate"]
    none = tools["submit_none"]
    assert "citation" in (cand.get("description") or "").lower()
    assert "threat_model" in (cand.get("parameters") or {}).get("properties", {})
    tm = cand["parameters"]["properties"]["threat_model"]
    assert set(tm.get("required") or []) >= {"attacker", "boundary", "impact"}
    reason = none["parameters"]["properties"]["reason"]
    assert reason.get("description")
    assert "check" in (none.get("description") or "").lower() or "search" in (
        none.get("description") or ""
    ).lower()


def test_list_dir_points_to_file_inventory():
    fn = _by_name("hunt")["list_dir"]
    desc = (fn.get("description") or "").lower()
    assert "file_inventory" in desc
    assert "one" in desc or "single" in desc or "not recursive" in desc


def test_note_payload_documented():
    fn = _by_name("recon")["note"]
    payload = (fn.get("parameters") or {}).get("properties", {}).get("payload") or {}
    assert payload.get("description")
    assert "codemap" in (payload.get("description") or "").lower()


def test_write_evidence_develop_poc_has_evidence_id_and_poc_wording():
    hunt = _by_name("hunt")["write_evidence"]
    poc = _by_name("develop_poc")["write_evidence"]
    h_props = (hunt.get("parameters") or {}).get("properties") or {}
    p_props = (poc.get("parameters") or {}).get("properties") or {}
    assert "evidence_id" not in h_props
    assert "evidence_id" in p_props
    assert "poc" in (poc.get("description") or "").lower()
