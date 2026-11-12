"""SARIF 2.1.0 findings export (issue #187). Offline: schema is vendored."""

from __future__ import annotations

import io
import json
import re
import zipfile
from pathlib import Path, PurePosixPath

import pytest
from fastapi.testclient import TestClient

jsonschema = pytest.importorskip("jsonschema")

from vulnforge.cli import main as vf_main
from vulnforge.control import campaign as campaign_ctl
from vulnforge.db import Database
from vulnforge.export_findings import (
    EXPORT_FORMATS,
    ExportOptions,
    export_bundle,
    export_bytes,
    export_json,
    export_sarif,
    sarif_document,
)
from vulnforge.sarif_export import artifact_uri, rule_id_for_class, selected_states
from vulnforge.ui import store
from vulnforge.ui.app import create_app

SCHEMA_PATH = Path(__file__).parent / "fixtures" / "sarif" / "sarif-schema-2.1.0.json"
ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


@pytest.fixture(scope="module")
def validator():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft4Validator.check_schema(schema)
    return jsonschema.Draft4Validator(schema)


def _assert_valid(validator, doc: dict) -> None:
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors[:10])
    inv = doc["runs"][0]["invocations"][0]
    if "endTimeUtc" in inv:
        assert ISO_UTC.match(inv["endTimeUtc"])


def _body(title, cls, citations, *, severity=None, sink=None, symbol=None):
    body = {
        "title": title,
        "summary": f"{title} summary",
        "weakness_class": cls,
        "threat_model": {"attacker": "remote", "boundary": "http", "impact": "x"},
        "citations": citations,
    }
    if severity:
        body["severity_claim"] = severity
    if sink:
        body["sink_path"] = sink
    if symbol:
        body["sink_symbol"] = symbol
    return body


def _make_run(tmp_path: Path) -> tuple[store.RunRef, Path, dict[str, int]]:
    runs = tmp_path / "runs"
    run_dir = runs / "toy" / "run-001"
    run_dir.mkdir(parents=True)
    target = tmp_path / "target"
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", str(target), "code_static", "pin", {})
    ids = {}
    ids["sqli"] = db.insert_finding(
        _body(
            "SQL injection in search_users",
            "injection",
            [
                {"path": "lib/util.py", "start_line": 3, "end_line": 4, "symbol": "helper"},
                {"path": "app.py", "start_line": 9, "end_line": 12, "symbol": "search_users"},
                {"path": str(target / "db" / "query.py"), "start_line": 20},
            ],
            severity="HIGH",
            sink="app.py",
            symbol="search_users",
        ),
        state="confirmed",
        evidence_id="3",
    )
    xss_body = _body("Reflected XSS", "XSS", [{"path": "views/a b.py", "start_line": 10}], severity="medium")
    xss_body["severity_rubric"] = {"action": "capped", "rule_id": "sev-2"}
    ids["xss"] = db.insert_finding(xss_body, state="needs_human")
    ids["cmd"] = db.insert_finding(
        _body("Shell exec", "injection", [{"path": "./run.sh", "start_line": 2}], severity="LOW"),
        state="needs_human",
    )
    ids["cand"] = db.insert_finding(
        _body("Candidate idor", "access-control", [{"path": "routes.py", "start_line": 1}]),
        state="candidate",
    )
    ids["rej"] = db.insert_finding(
        _body("Rejected", "injection", [{"path": "old.py", "start_line": 5}]),
        state="rejected_mech",
    )
    ids["llm"] = db.insert_finding(
        _body("Disproved", "ssrf", [{"path": "net.py", "start_line": 7}]),
        state="rejected_llm",
    )
    ids["sup"] = db.insert_finding(
        _body("Merged dup", "injection", [{"path": "app.py", "start_line": 9}]),
        state="superseded",
    )
    ids["noloc"] = db.insert_finding(
        _body("No lines", "secrets", [{"path": "conf.py"}]),
        state="confirmed",
    )
    ids["outside"] = db.insert_finding(
        _body("Outside target", "secrets", [{"path": "/etc/passwd", "start_line": 1}]),
        state="confirmed",
    )
    db.close()
    return store.resolve_run(runs, "toy", "run-001"), run_dir, ids


@pytest.fixture
def run(tmp_path: Path):
    return _make_run(tmp_path)


def _doc(run_dir: Path, **opts) -> dict:
    db = Database.open(run_dir / "harness.db")
    try:
        return json.loads(export_sarif(run_dir, db, options=ExportOptions(**opts)))
    finally:
        db.close()


def _results_by_id(doc: dict) -> dict[int, dict]:
    return {r["properties"]["vulnforge/finding_id"]: r for r in doc["runs"][0]["results"]}


def test_registry_entry():
    assert EXPORT_FORMATS["sarif"] == (
        "export_sarif",
        "sarif",
        "application/sarif+json",
        False,
    )


def test_default_export_is_confirmed_only_and_schema_valid(run, validator):
    _ref, run_dir, ids = run
    doc = _doc(run_dir)
    _assert_valid(validator, doc)
    assert doc["version"] == "2.1.0"
    by_id = _results_by_id(doc)
    assert set(by_id) == {ids["sqli"]}
    props = doc["runs"][0]["properties"]
    assert props["vulnforge/states_included"] == ["confirmed"]
    assert props["vulnforge/run_id"] == "run-001"
    assert "not exploit proven" in props["vulnforge/disclaimer"]


def test_include_flags_widen_filter(run, validator):
    _ref, run_dir, ids = run
    nh = _doc(run_dir, sarif_include_needs_human=True)
    _assert_valid(validator, nh)
    assert set(_results_by_id(nh)) == {ids["sqli"], ids["xss"], ids["cmd"]}

    rej = _doc(run_dir, sarif_include_rejected=True)
    _assert_valid(validator, rej)
    assert set(_results_by_id(rej)) == {ids["sqli"], ids["rej"], ids["llm"], ids["sup"]}

    explicit = _doc(run_dir, sarif_states=("candidate",), sarif_include_needs_human=True)
    _assert_valid(validator, explicit)
    assert set(_results_by_id(explicit)) == {ids["cand"]}


def test_one_rule_per_weakness_class(run):
    _ref, run_dir, _ids = run
    doc = _doc(run_dir, sarif_states=("confirmed", "needs_human", "rejected_mech", "candidate"))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert ids == sorted(ids)
    # Static hunt-skill aliases apply: "XSS" → client-side.
    assert ids == ["access-control", "client-side", "injection"]
    by_rule = {r["id"]: r for r in rules}
    # Raw class "XSS" maps to the canonical rule; prose uses the canonical slug.
    assert by_rule["client-side"]["shortDescription"]["text"] == "VulnForge client-side finding"
    for r in rules:
        assert "security" in r["properties"]["tags"]
        assert r["help"]["text"]
        assert "security-severity" not in r["properties"]
    for res in doc["runs"][0]["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]


def test_result_shape_fingerprints_and_properties(run):
    ref, run_dir, ids = run
    doc = _doc(run_dir, sarif_include_needs_human=True)
    by_id = _results_by_id(doc)

    db = Database.open(run_dir / "harness.db")
    stable = {f.id: f.stable_key for f in db.list_findings()}
    db.close()

    sqli = by_id[ids["sqli"]]
    assert sqli["level"] == "error"
    assert sqli["partialFingerprints"] == {
        "primaryLocationLineHash": stable[ids["sqli"]],
        "vulnforge/stableKey/v1": stable[ids["sqli"]],
    }
    p = sqli["properties"]
    assert p["vulnforge/state"] == "confirmed"
    assert p["vulnforge/confirmed"] is True
    assert p["vulnforge/stable_key"] == stable[ids["sqli"]]
    assert p["vulnforge/evidence_id"] == "3"
    assert p["vulnforge/severity_claim"] == "HIGH"
    # Primary location prefers the sink_path citation over the first one.
    loc = sqli["locations"][0]
    assert loc["physicalLocation"] == {
        "artifactLocation": {"uri": "app.py"},
        "region": {"startLine": 9, "endLine": 12},
    }
    assert "uriBaseId" not in loc["physicalLocation"]["artifactLocation"]
    assert loc["logicalLocations"] == [{"name": "search_users"}]
    related = [r["physicalLocation"]["artifactLocation"]["uri"] for r in sqli["relatedLocations"]]
    # Absolute path under the target root becomes target-relative.
    assert related == ["lib/util.py", "db/query.py"]
    assert sqli["message"]["text"].startswith("SQL injection in search_users. Human accepted")
    # Related locations are linked from the message so code scanning shows them.
    assert sqli["message"]["text"].endswith(
        "Related locations: [lib/util.py:3](1), [db/query.py:20](2)."
    )

    xss = by_id[ids["xss"]]
    assert xss["level"] == "warning"
    assert xss["ruleId"] == "client-side"
    assert xss["properties"]["vulnforge/confirmed"] is False
    assert xss["properties"]["vulnforge/policy_rule"] == "capped:sev-2"
    assert "vulnforge/policy_rule" not in sqli["properties"]
    assert xss["message"]["text"].startswith(
        "needs_human: Reflected XSS. Mechanical gates passed; not a confirmed vulnerability."
    )
    assert xss["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "views/a%20b.py"
    assert xss["locations"][0]["physicalLocation"]["region"] == {"startLine": 10}

    cmd = by_id[ids["cmd"]]
    assert cmd["level"] == "note"
    assert cmd["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "run.sh"


def test_no_location_findings_become_notifications(run, tmp_path):
    _ref, run_dir, ids = run
    doc = _doc(run_dir)
    text = json.dumps(doc)
    # Absolute paths never leak into the log.
    assert "/etc/passwd" not in text
    assert str(tmp_path) not in text
    inv = doc["runs"][0]["invocations"][0]
    notes = inv["toolExecutionNotifications"]
    assert {n["properties"]["vulnforge/finding_id"] for n in notes} == {ids["noloc"], ids["outside"]}
    assert all(n["descriptor"]["id"] == "vulnforge/no-location" for n in notes)
    assert doc["runs"][0]["properties"]["vulnforge/skipped_no_location"] == 2
    driver_notes = doc["runs"][0]["tool"]["driver"]["notifications"]
    assert driver_notes[0]["id"] == "vulnforge/no-location"


def test_empty_run_is_valid(tmp_path, validator):
    db = Database.create(tmp_path / "harness.db")
    db.insert_run("run-001", str(tmp_path / "t"), "code_static", "pin", {})
    try:
        doc = json.loads(export_sarif(tmp_path, db))
    finally:
        db.close()
    _assert_valid(validator, doc)
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_export_does_not_change_state(run):
    _ref, run_dir, _ids = run
    db = Database.open(run_dir / "harness.db")
    try:
        before = {f.id: f.state for f in db.list_findings()}
        export_sarif(run_dir, db, options=ExportOptions(sarif_include_rejected=True))
        after = {f.id: f.state for f in db.list_findings()}
    finally:
        db.close()
    assert before == after


def test_dispatch_and_bundle(run, validator):
    _ref, run_dir, _ids = run
    db = Database.open(run_dir / "harness.db")
    try:
        payload, ext, media = export_bytes("sarif", run_dir, db)
        assert (ext, media) == ("sarif", "application/sarif+json")
        _assert_valid(validator, json.loads(payload))
        zipped, zext, _ = export_bundle("json,sarif", run_dir, db)
    finally:
        db.close()
    assert zext == "zip"
    with zipfile.ZipFile(io.BytesIO(zipped)) as zf:
        assert "vulnforge-report.sarif" in zf.namelist()
        _assert_valid(validator, json.loads(zf.read("vulnforge-report.sarif")))


def test_json_sections_unchanged_by_sarif_options(run):
    _ref, run_dir, _ids = run
    opts = ExportOptions(sarif_include_rejected=True, sarif_states=("candidate",))
    assert set(opts.as_dict()) == {
        "include_findings",
        "include_architecture",
        "include_hunts",
        "include_summary",
        "include_poc",
        "include_codemap",
    }
    db = Database.open(run_dir / "harness.db")
    try:
        payload = json.loads(export_json(run_dir, db, options=opts))
    finally:
        db.close()
    assert set(payload["sections"]) == set(opts.as_dict())


def test_from_kwargs_threads_sarif_flags():
    opts = ExportOptions.from_kwargs(
        sarif_include_needs_human=True, sarif_states=["needs_human"]
    )
    assert opts.sarif_include_needs_human is True
    assert opts.sarif_states == ("needs_human",)


def test_helpers():
    assert rule_id_for_class("Access Control / IDOR") == "access-control-idor"
    assert rule_id_for_class("") == "unclassified"
    assert rule_id_for_class("SQLi") == "injection"
    assert rule_id_for_class("business_logic") == "business-logic"
    root = PurePosixPath("/srv/target")
    assert artifact_uri("/srv/target/a/b.py", root) == "a/b.py"
    assert artifact_uri("/srv/other/b.py", root) is None
    assert artifact_uri("../escape.py", root) is None
    assert artifact_uri("a/../b.py", root) == "b.py"
    assert artifact_uri("src\\win.py", root) == "src/win.py"
    assert artifact_uri("C:/x/y.py", None) is None
    assert artifact_uri("https://example.com/x", root) is None
    assert selected_states() == ("confirmed",)
    assert selected_states(include_needs_human=True, states=["candidate"]) == ("candidate",)


def test_cli_export_sarif(run, tmp_path, validator, capsys):
    _ref, run_dir, ids = run
    out = tmp_path / "out" / "findings.sarif"
    rc = vf_main(
        [
            "export",
            "--run-dir",
            str(run_dir),
            "--format",
            "sarif",
            "--include-needs-human",
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    _assert_valid(validator, doc)
    assert set(_results_by_id(doc)) == {ids["sqli"], ids["xss"], ids["cmd"]}

    rc = vf_main(["export", "--run-dir", str(run_dir), "--format", "sarif", "--state", "rejected_llm"])
    assert rc == 0
    written = list((run_dir / "exports").glob("*.sarif"))
    assert len(written) == 1
    assert set(_results_by_id(json.loads(written[0].read_text()))) == {ids["llm"]}

    capsys.readouterr()
    rc = vf_main(["export", "--run-dir", str(run_dir), "--format", "sarif", "--out", "-"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["version"] == "2.1.0"

    assert vf_main(["export", "--run-dir", str(run_dir), "--format", "pdf"]) == 30


def test_campaign_findings_sarif(run, validator):
    ref, run_dir, ids = run
    res = campaign_ctl.apply(ref, "findings", {"format": "sarif"})
    assert res["ok"] is True and res["verb"] == "findings"
    assert res["format"] == "sarif"
    assert res["count"] == 1
    assert res["skipped_no_location"] == 2
    _assert_valid(validator, res["sarif"])

    widened = campaign_ctl.apply(
        ref, "findings", {"format": "sarif", "include_needs_human": True, "class": "injection"}
    )
    assert set(_results_by_id(widened["sarif"])) == {ids["sqli"], ids["cmd"]}

    by_state = campaign_ctl.apply(ref, "findings", {"format": "sarif", "state": "candidate"})
    assert set(_results_by_id(by_state["sarif"])) == {ids["cand"]}

    bad = campaign_ctl.apply(ref, "findings", {"format": "xml"})
    assert bad["ok"] is False and bad["http"] == 400

    # Default rows format unchanged.
    rows = campaign_ctl.apply(ref, "findings", {})
    assert "findings" in rows and "sarif" not in rows


def test_http_export_and_campaign_routes(run, validator):
    ref, run_dir, ids = run
    app = create_app(runs_root=ref.path.parents[1])
    base = f"/api/runs/{ref.target_id}/{ref.run_id}"
    with TestClient(app) as client:
        r = client.get(f"{base}/export", params={"format": "sarif"})
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/sarif+json")
        assert r.headers["content-disposition"].endswith('.sarif"')
        doc = r.json()
        _assert_valid(validator, doc)
        assert set(_results_by_id(doc)) == {ids["sqli"]}

        r = client.get(
            f"{base}/export",
            params={"format": "sarif", "sarif_include_needs_human": "true", "sarif_include_rejected": "true"},
        )
        assert set(_results_by_id(r.json())) == {
            ids["sqli"], ids["xss"], ids["cmd"], ids["rej"], ids["llm"], ids["sup"]
        }

        r = client.get(f"{base}/campaign/findings", params={"format": "sarif", "include_needs_human": "true"})
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 3
        _assert_valid(validator, body["sarif"])

        r = client.post(
            f"{base}/campaign/findings",
            json={"format": "sarif", "include_rejected": True, "class": "ssrf"},
        )
        assert r.status_code == 200
        assert set(_results_by_id(r.json()["sarif"])) == {ids["llm"]}

        r = client.get(f"{base}/campaign/findings", params={"format": "xml"})
        assert r.status_code == 400


def test_sarif_document_is_deterministic_apart_from_timestamp(run):
    _ref, run_dir, _ids = run
    db = Database.open(run_dir / "harness.db")
    try:
        a = sarif_document(run_dir, db, options=ExportOptions(sarif_include_needs_human=True))
        b = sarif_document(run_dir, db, options=ExportOptions(sarif_include_needs_human=True))
    finally:
        db.close()
    for d in (a, b):
        d["runs"][0]["invocations"][0].pop("endTimeUtc", None)
    assert a == b


def test_primary_prefers_sink_symbol_in_same_file_and_tags_are_unique(tmp_path, validator):
    db = Database.create(tmp_path / "harness.db")
    db.insert_run("run-001", str(tmp_path / "t"), "code_static", "pin", {})
    fid = db.insert_finding(
        _body(
            "Command injection via os.system [see](1)",
            "security",
            [
                {"path": "app.py", "start_line": 10, "symbol": "parse_query"},
                {"path": "app.py", "start_line": 40, "symbol": "search_users"},
            ],
            sink="app.py",
            symbol="search_users",
        ),
        state="confirmed",
    )
    try:
        doc = sarif_document(tmp_path, db)
    finally:
        db.close()
    _assert_valid(validator, doc)
    res = _results_by_id(doc)[fid]
    assert res["locations"][0]["physicalLocation"]["region"] == {"startLine": 40}
    assert res["locations"][0]["logicalLocations"] == [{"name": "search_users"}]
    assert [r["message"]["text"] for r in res["relatedLocations"]] == ["parse_query"]
    # Title text that would read as an embedded link is escaped.
    assert res["message"]["text"].startswith("Command injection via os.system \\[see\\](1).")
    assert res["message"]["text"].endswith("Related locations: [app.py:10](1).")
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "security"
    assert rule["properties"]["tags"] == ["security", "vulnforge"]


def test_campaign_class_filter_uses_aliases(run):
    ref, _run_dir, ids = run
    res = campaign_ctl.apply(
        ref, "findings", {"format": "sarif", "include_needs_human": True, "class": "sqli"}
    )
    assert set(_results_by_id(res["sarif"])) == {ids["sqli"], ids["cmd"]}
    res = campaign_ctl.apply(
        ref, "findings", {"format": "sarif", "include_needs_human": True, "class": "client-side"}
    )
    assert set(_results_by_id(res["sarif"])) == {ids["xss"]}
