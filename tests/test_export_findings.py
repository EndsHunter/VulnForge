"""Unit tests for findings export (no optional binary deps required)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnforge.db import Database
from vulnforge.export_findings import (
    DISCLAIMER,
    ExportOptions,
    ROW_COLUMNS,
    export_bundle,
    export_csv,
    export_html,
    export_json,
    export_markdown,
    export_bytes,
    findings_to_rows,
)


SAMPLE_BODY = {
    "title": "SQL Injection in search_users",
    "summary": "Untrusted q is interpolated into SQL via f-string.",
    "weakness_class": "injection",
    "threat_model": {
        "attacker": "Any caller controlling q",
        "boundary": "Function parameter boundary",
        "impact": "Data exfiltration",
    },
    "citations": [
        {
            "path": "app.py",
            "start_line": 9,
            "end_line": 12,
            "symbol": "search_users",
        }
    ],
    "evidence_id": "3",
    "severity_claim": "HIGH",
    "sink_path": "app.py",
    "sink_symbol": "search_users",
    "human_review_latest": {
        "action": "confirm",
        "notes": "Looks real after manual check",
        "from_state": "needs_human",
        "to_state": "confirmed",
    },
    "human_review": [
        {
            "action": "confirm",
            "notes": "Looks real after manual check",
            "from_state": "needs_human",
            "to_state": "confirmed",
        }
    ],
}


@pytest.fixture
def db_with_finding(tmp_path: Path):
    db = Database.create(tmp_path / "harness.db")
    db.insert_run(
        "run-001",
        target_path=str(tmp_path / "toy"),
        profile="code_static",
        prompt_pin="pin",
        config={},
    )
    db.insert_finding(SAMPLE_BODY, state="confirmed", evidence_id="3")
    db.insert_finding(
        {
            "title": "Candidate only",
            "summary": "Needs work",
            "weakness_class": "access-control",
            "threat_model": {"attacker": "auth user", "boundary": "API", "impact": "idor"},
            "citations": [{"path": "routes.py", "start_line": 1, "end_line": 2}],
            "severity_claim": "medium",
        },
        state="candidate",
    )
    db.insert_finding(
        {
            "title": "Mech-passed XSS",
            "summary": "Reflected XSS candidate awaiting human",
            "weakness_class": "xss",
            "threat_model": {
                "attacker": "remote user",
                "boundary": "query param",
                "impact": "session theft",
            },
            "citations": [{"path": "views.py", "start_line": 10, "end_line": 14}],
            "severity_claim": "high",
            "evidence_id": "ev-xss",
            "needs_human": True,
        },
        state="needs_human",
        evidence_id="ev-xss",
    )
    db.insert_finding(
        {
            "title": "Rejected by mech",
            "summary": "Missing citations",
            "weakness_class": "injection",
            "threat_model": {"attacker": "a", "boundary": "b", "impact": "c"},
            "citations": [],
            "severity_claim": "low",
            "validation_reasons": ["missing_citations", "threat_model_vacuous"],
        },
        state="rejected_mech",
    )
    yield db, tmp_path
    db.close()


def test_disclaimer_language():
    assert "needs_human" in DISCLAIMER
    assert "mechanical gates" in DISCLAIMER
    assert "human accepted" in DISCLAIMER
    assert "exploit" in DISCLAIMER.lower()
    # Must not claim confirmed = mechanical only
    assert "confirmed = mechanical" not in DISCLAIMER.lower()
    assert "confirmed means" not in DISCLAIMER.lower() or "human" in DISCLAIMER.lower()


def test_findings_to_rows_flat(db_with_finding):
    db, _ = db_with_finding
    rows = findings_to_rows(db)
    assert len(rows) == 4
    conf = next(r for r in rows if r["state"] == "confirmed")
    assert conf["title"] == "SQL Injection in search_users"
    assert conf["weakness_class"] == "injection"
    assert conf["severity"].upper() == "HIGH"
    assert conf["path"] == "app.py"
    assert conf["evidence_id"] == "3"
    assert conf["attacker"]
    assert "app.py" in conf["citations"] or conf["path"] == "app.py"
    assert conf["human_review_action"] == "confirm"
    assert "manual check" in conf["human_review_notes"]
    rej = next(r for r in rows if r["state"] == "rejected_mech")
    assert "missing_citations" in rej["validation_reasons"]
    for col in ROW_COLUMNS:
        assert col in conf


def test_summary_counts_include_needs_human(db_with_finding):
    db, run_dir = db_with_finding
    data = json.loads(export_json(run_dir, db))
    assert data["counts"]["needs_human"] == 1
    assert data["counts"]["confirmed"] == 1
    assert data["counts"]["candidate"] == 1
    assert data["counts"]["rejected"] == 1
    assert data["counts"]["total"] == 4


def test_export_json_contains_disclaimer_and_findings(db_with_finding):
    db, run_dir = db_with_finding
    text = export_json(run_dir, db)
    data = json.loads(text)
    assert DISCLAIMER == data["disclaimer"]
    assert "mechanical gates" in data["disclaimer"]
    assert "human accepted" in data["disclaimer"]
    assert data["counts"]["confirmed"] == 1
    assert data["counts"]["candidate"] == 1
    assert data["counts"]["needs_human"] == 1
    assert data["counts"]["rejected"] == 1
    assert len(data["findings"]) == 4
    assert len(data["rows"]) == 4
    assert data["run_id"] == "run-001"
    # Flat rows carry human review + validation fields
    conf_row = next(r for r in data["rows"] if r["state"] == "confirmed")
    assert conf_row["human_review_action"] == "confirm"
    rej_row = next(r for r in data["rows"] if r["state"] == "rejected_mech")
    assert "missing_citations" in rej_row["validation_reasons"]


def test_export_markdown(db_with_finding):
    db, run_dir = db_with_finding
    md = export_markdown(run_dir, db)
    assert md.startswith("# VulnForge audit report")
    assert "mechanical gates" in md
    assert "human accepted" in md
    assert "SQL Injection" in md
    assert "Needs human:" in md
    assert "Confirmed (human):" in md
    assert "## Findings" in md
    assert "Needs human review (mech-passed)" in md
    assert "Confirmed findings (human-accepted)" in md
    assert "Rejected" in md
    assert "Candidates" in md
    assert "injection" in md
    assert "app.py" in md
    assert "Mech-passed XSS" in md
    assert "missing_citations" in md
    assert "human_review" in md


def test_export_csv(db_with_finding):
    db, run_dir = db_with_finding
    csv_text = export_csv(run_dir, db)
    assert "mechanical gates" in csv_text
    assert "human accepted" in csv_text
    lines = [ln for ln in csv_text.splitlines() if not ln.startswith("#")]
    assert lines[0].startswith("id,")
    assert "confirmed" in csv_text
    assert "needs_human" in csv_text
    assert "SQL Injection" in csv_text
    header = lines[0].split(",")
    for col in (
        "id",
        "state",
        "severity",
        "title",
        "stable_key",
        "human_review_action",
        "human_review_notes",
        "validation_reasons",
    ):
        assert col in header


def test_export_html_self_contained(db_with_finding):
    db, run_dir = db_with_finding
    html_doc = export_html(run_dir, db)
    assert html_doc.lstrip().startswith("<!DOCTYPE html>")
    assert "<style>" in html_doc
    assert "mechanical gates" in html_doc
    assert "human accepted" in html_doc
    assert "SQL Injection" in html_doc
    assert "<details" in html_doc
    assert 'id="f-1"' in html_doc or "f-1" in html_doc
    assert "Needs human" in html_doc
    assert "Confirmed (human)" in html_doc
    assert "state-needs-human" in html_doc
    assert "http://cdn" not in html_doc.lower()
    assert "https://fonts" not in html_doc.lower()


def test_export_bytes_dispatch(db_with_finding):
    db, run_dir = db_with_finding
    payload, ext, media = export_bytes("md", run_dir, db)
    assert ext == "md"
    assert b"VulnForge" in payload
    assert "markdown" in media or "text" in media

    payload, ext, media = export_bytes("html", run_dir, db)
    assert ext == "html"
    assert payload.startswith(b"<!DOCTYPE") or b"html" in payload[:200].lower()


def test_export_include_poc_embeds_evidence(tmp_path: Path, toy_sqli: Path):
    """When include_poc=True, evidence pack file text is embedded."""
    from vulnforge.util import build_target_manifest, write_json

    run_dir = tmp_path / "run-001"
    run_dir.mkdir()
    (run_dir / "evidence" / "3").mkdir(parents=True)
    poc_text = "PoC: inject ' OR 1=1 -- into search_users via q param\n"
    (run_dir / "evidence" / "3" / "poc.md").write_text(poc_text, encoding="utf-8")
    write_json(run_dir / "target_manifest.json", build_target_manifest(toy_sqli, []))
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", str(toy_sqli), "code_static", "pin", {})
    body = dict(SAMPLE_BODY)
    body["poc_relpath"] = "poc.md"
    db.insert_finding(body, state="confirmed", evidence_id="3")

    # Without flag — no pack body
    md0 = export_markdown(run_dir, db, include_poc=False)
    assert "Include PoC: `no`" in md0
    assert "inject ' OR 1=1" not in md0

    md1 = export_markdown(run_dir, db, include_poc=True)
    assert "Include PoC: `yes`" in md1
    assert "PoC / evidence pack" in md1
    assert "inject ' OR 1=1" in md1
    assert "poc.md" in md1

    data = json.loads(export_json(run_dir, db, include_poc=True))
    assert data["include_poc"] is True
    conf = next(f for f in data["findings"] if f["state"] == "confirmed")
    assert "poc" in conf
    files = conf["poc"]["files"]
    assert any(f.get("relpath") == "poc.md" for f in files)
    assert any("OR 1=1" in (f.get("content") or "") for f in files)
    row = next(r for r in data["rows"] if r["state"] == "confirmed")
    assert row["poc_relpath"] == "poc.md"
    assert "poc.md" in row["poc_files"]
    assert "OR 1=1" in row["poc_excerpt"]

    payload, ext, _ = export_bytes("md", run_dir, db, include_poc=True)
    assert ext == "md"
    assert b"OR 1=1" in payload
    db.close()


def test_export_bytes_unknown_format(db_with_finding):
    db, run_dir = db_with_finding
    with pytest.raises(ValueError, match="unknown export format"):
        export_bytes("pdf", run_dir, db)


def test_export_xlsx_import_error_message(db_with_finding, monkeypatch):
    db, run_dir = db_with_finding
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "openpyxl" or name.startswith("openpyxl."):
            raise ImportError("No module named openpyxl")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    from vulnforge.export_findings import export_xlsx

    with pytest.raises(ImportError, match="openpyxl"):
        export_xlsx(run_dir, db)


def test_export_docx_import_error_message(db_with_finding, monkeypatch):
    db, run_dir = db_with_finding
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "docx" or name.startswith("docx."):
            raise ImportError("No module named docx")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    from vulnforge.export_findings import export_docx

    with pytest.raises(ImportError, match="python-docx"):
        export_docx(run_dir, db)


def test_empty_findings(tmp_path: Path):
    db = Database.create(tmp_path / "harness.db")
    db.insert_run("run-001", str(tmp_path), "code_static", "pin", {})
    try:
        rows = findings_to_rows(db)
        assert rows == []
        md = export_markdown(tmp_path, db)
        assert "No findings" in md
        html_doc = export_html(tmp_path, db)
        assert "No findings" in html_doc
        data = json.loads(export_json(tmp_path, db))
        assert data["counts"]["total"] == 0
        assert data["counts"]["needs_human"] == 0
    finally:
        db.close()


def test_export_includes_architecture_and_hunts(db_with_finding):
    db, run_dir = db_with_finding
    db.set_architecture(
        {
            "summary": "Toy web app with search API",
            "components": [
                {
                    "name": "api",
                    "role": "http",
                    "path_hints": ["app.py"],
                }
            ],
            "trust_boundaries": ["public/private"],
            "hunt_focus": [{"area": "api", "why": "user input to SQL"}],
        },
        source="test",
    )
    db.enqueue_task(
        "hunt",
        {"area": "api", "class": "injection", "path_hints": ["app.py"]},
        priority=50,
    )
    opts = ExportOptions(
        include_findings=True,
        include_architecture=True,
        include_hunts=True,
        include_summary=True,
        include_poc=False,
        include_codemap=False,
    )
    md = export_markdown(run_dir, db, options=opts)
    assert "## Architecture" in md
    assert "Toy web app" in md
    assert "**api**" in md
    assert "public/private" in md
    assert "## Hunts & coverage" in md
    assert "Hunt tasks" in md
    assert "injection" in md
    assert "## Campaign summary" in md

    data = json.loads(export_json(run_dir, db, options=opts))
    assert data["architecture"]["summary"] == "Toy web app with search API"
    assert data["architecture"]["components"][0]["name"] == "api"
    assert isinstance(data["hunt_tasks"], list)
    assert any(h.get("class") == "injection" for h in data["hunt_tasks"])
    assert data["sections"]["include_architecture"] is True

    html_doc = export_html(run_dir, db, options=opts)
    assert "Architecture" in html_doc
    assert "Toy web app" in html_doc
    assert "Hunts" in html_doc or "coverage" in html_doc.lower()


def test_export_bundle_multi_format_zip(db_with_finding):
    db, run_dir = db_with_finding
    payload, ext, media = export_bundle(
        "md,json",
        run_dir,
        db,
        options=ExportOptions(include_findings=True),
    )
    assert ext == "zip"
    assert "zip" in media
    assert payload[:2] == b"PK"
    import zipfile
    import io

    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        names = zf.namelist()
        assert any(n.endswith(".md") for n in names)
        assert any(n.endswith(".json") for n in names)


def test_export_without_findings_still_has_architecture(db_with_finding):
    db, run_dir = db_with_finding
    db.set_architecture(
        {"summary": "Map only", "components": [{"name": "core"}]},
        source="test",
    )
    opts = ExportOptions(
        include_findings=False,
        include_architecture=True,
        include_hunts=False,
        include_summary=False,
    )
    md = export_markdown(run_dir, db, options=opts)
    assert "## Architecture" in md
    assert "Map only" in md
    assert "## Findings" not in md
    data = json.loads(export_json(run_dir, db, options=opts))
    assert data["findings"] == []
    assert data["architecture"]["summary"] == "Map only"
