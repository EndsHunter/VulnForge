"""Operator security policy (#183): schema, storage, packets, disprove, report, API, CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vulnforge.db import SECURITY_POLICY_REVISION_CAP, Database
from vulnforge.security_policy import (
    POLICY_SCHEMA,
    PolicyError,
    apply_severity_rubric,
    draft_from_security_md,
    format_policy_for_packet,
    match_exclusion,
    normalize_policy,
    parse_policy_citations,
    path_matches,
)

POLICY = {
    "notes": "Public API only faces the internet.",
    "trust_boundaries": [
        {"id": "tb-api", "name": "internet → api", "paths": ["src/api/**"]},
        {"id": "tb-cli", "name": "local cli", "paths": ["tools/cli/**"]},
    ],
    "attacker_controlled": [{"id": "src-1", "description": "HTTP params", "paths": []}],
    "out_of_scope": [{"id": "oos-tests", "paths": ["tests/"], "reason": "fixtures"}],
    "exclusions": [
        {"id": "ex-vendor", "paths": ["vendor/**"], "weakness_class": "*", "reason": "vendored"}
    ],
    "severity_rubric": [
        {"id": "sev-admin", "max_severity": "MEDIUM", "paths": ["src/admin/**"],
         "criteria": "admin-only"},
    ],
}


def _body(*paths: str, cls: str = "injection", sev: str | None = None) -> dict:
    b = {"weakness_class": cls, "citations": [{"path": p, "start_line": 1} for p in paths]}
    if sev:
        b["severity_claim"] = sev
    return b


def _db(tmp_path: Path, target: Path | None = None) -> Database:
    db = Database.create(tmp_path / "harness.db")
    db.insert_run("run-001", str(target or tmp_path / "tgt"), "code_static", "pin", {})
    return db


# --- schema -----------------------------------------------------------------


def test_normalize_valid_policy_fills_defaults():
    pol, errs = normalize_policy(POLICY)
    assert errs == []
    assert pol["schema"] == POLICY_SCHEMA
    assert pol["exclusions"][0]["weakness_class"] == "*"
    assert pol["in_scope"] == [] and pol["trusted_inputs"] == []


@pytest.mark.parametrize(
    "raw,needle",
    [
        ({"exclusion": []}, "unknown top-level key"),
        ({"severity_rubric": [{"max_sevrity": "LOW"}]}, "unknown key 'max_sevrity'"),
        ({"exclusions": [{"paths": [], "reason": "r"}]}, "at least one glob"),
        ({"exclusions": [{"paths": ["a/**"]}]}, "reason is required"),
        ({"out_of_scope": [{"paths": ["../x"], "reason": "r"}]}, "'..'"),
        ({"out_of_scope": [{"paths": ["/etc/**"], "reason": "r"}]}, "relative"),
        ({"severity_rubric": [{"max_severity": "SEVERE"}]}, "max_severity must be"),
        (
            {"exclusions": [{"id": "x", "paths": ["a"], "reason": "r"}],
             "out_of_scope": [{"id": "x", "paths": ["b"], "reason": "r"}]},
            "duplicate id",
        ),
        ({"schema": "other@2"}, "unsupported schema"),
        ([], "JSON object"),
    ],
)
def test_normalize_rejects_bad_policies(raw, needle):
    _pol, errs = normalize_policy(raw)
    assert any(needle in e for e in errs), errs


def test_auto_ids_do_not_collide_with_explicit():
    pol, errs = normalize_policy(
        {"exclusions": [{"paths": ["a"], "reason": "r"}, {"id": "ex-1", "paths": ["b"], "reason": "r"}]}
    )
    assert errs == []
    assert [r["id"] for r in pol["exclusions"]] == ["ex-2", "ex-1"]


# --- globs + matching ---------------------------------------------------------


@pytest.mark.parametrize(
    "glob,path,ok",
    [
        ("vendor/**", "vendor/x.py", True),
        ("vendor/**", "vendor/a/b/c.py", True),
        ("vendor/**", "notvendor/x.py", False),
        ("vendor", "vendor/x.py", True),
        ("vendor", "vendored/x.py", False),
        ("tests/", "tests/unit/t.py", True),
        ("src/*.py", "src/a.py", True),
        ("src/*.py", "src/a/b.py", False),
        ("**/test_*.py", "test_a.py", True),
        ("**/test_*.py", "pkg/sub/test_a.py", True),
        ("a.b", "aXb", False),
        ("Src/**", "src/a.py", False),
        ("app/[id]", "app/[id]/page.tsx", True),
        ("app/[id]", "app/x/page.tsx", False),
    ],
)
def test_path_matches(glob, path, ok):
    assert path_matches(glob, path) is ok


def test_match_exclusion_requires_every_cited_path():
    pol, _ = normalize_policy(POLICY)
    assert match_exclusion(pol, _body("vendor/lib.py"))["rule_id"] == "ex-vendor"
    assert match_exclusion(pol, _body("vendor/lib.py", "src/app.py")) is None
    oos = match_exclusion(pol, _body("tests/t.py", "./tests/u.py"), revision=7)
    assert oos["kind"] == "out_of_scope" and oos["policy_revision"] == 7
    assert match_exclusion(pol, {"citations": []}) is None
    assert match_exclusion(pol, {"citations": "garbage"}) is None


def test_match_exclusion_resolves_dotdot_like_citation_gate():
    pol, _ = normalize_policy(POLICY)
    assert match_exclusion(pol, _body("lib/../vendor/a.py"))["matched_paths"] == ["vendor/a.py"]
    assert match_exclusion(pol, _body("vendor/../src/app.py")) is None
    assert match_exclusion(pol, _body("../vendor/a.py")) is None


def test_in_scope_is_not_a_gate():
    pol, _ = normalize_policy({"in_scope": [{"paths": ["src/**"]}]})
    assert match_exclusion(pol, _body("other/x.py")) is None


def test_rubric_picks_tightest_cap_and_never_raises():
    pol, _ = normalize_policy(
        {
            "severity_rubric": [
                {"id": "loose", "max_severity": "HIGH"},
                {"id": "tight", "max_severity": "LOW", "weakness_class": "injection"},
                {"id": "prose", "criteria": "explain only"},
            ]
        }
    )
    out, rec = apply_severity_rubric(pol, _body("a.py", sev="CRITICAL"))
    assert out["severity_claim"] == "LOW" and out["severity_claim_original"] == "CRITICAL"
    assert rec["rule_id"] == "tight" and rec["action"] == "capped"
    # HIGH vs LOW must compare by rank, not string order.
    out2, rec2 = apply_severity_rubric(pol, _body("a.py", cls="xss", sev="MEDIUM"))
    assert out2["severity_claim"] == "MEDIUM" and rec2["action"] == "within"
    # No claim → no record.
    out3, rec3 = apply_severity_rubric(pol, _body("a.py"))
    assert rec3 is None and "severity_rubric" not in out3
    # Existing cap is kept.
    _o, rec4 = apply_severity_rubric(pol, out)
    assert rec4 is None


# --- packets -----------------------------------------------------------------


def test_hunt_slice_keeps_overlapping_rules_and_rubric():
    pol, _ = normalize_policy(POLICY)
    txt = format_policy_for_packet(pol, stage="hunt", revision=3, path_hints=["src/api/users.py"])
    assert "rev 3" in txt and "area slice" in txt
    assert "tb-api" in txt
    assert "tb-cli" not in txt  # outside the hunt area
    assert "src-1" in txt  # no paths → always kept
    assert "sev-admin" in txt  # rubric always kept
    assert "do not skip submit_candidate" in txt
    full = format_policy_for_packet(pol, stage="hunt")
    assert "tb-cli" in full
    assert format_policy_for_packet(None) == ""


def test_policy_block_is_capped():
    pol, _ = normalize_policy(
        {"exclusions": [{"paths": [f"d{i}/**"], "reason": "x" * 200} for i in range(50)]}
    )
    txt = format_policy_for_packet(pol, max_chars=1800)
    assert len(txt) <= 1800
    assert "policy truncated" in txt


def test_pack_hunt_includes_policy_slice():
    from vulnforge.packet import pack_hunt
    from vulnforge.paths import system_prompts_root

    pol, _ = normalize_policy(POLICY)
    pkt = pack_hunt(
        {"llm": {"context_tokens": 32768, "max_context_fraction": 0.5}},
        system_prompts_root(),
        {"area": "api", "class": "injection", "path_hints": ["src/api/"]},
        "arch",
        [],
        [],
        security_policy={"revision": 2, "policy": pol},
    )
    assert "Operator security policy (hunt rev 2, area slice)" in pkt.user
    assert "tb-api" in pkt.user and "tb-cli" not in pkt.user
    plain = pack_hunt({}, system_prompts_root(), {"area": "api", "class": "injection"}, "a", [], [])
    assert "Operator security policy" not in plain.user


def test_pack_recon_and_disprove_include_policy():
    from vulnforge.packet import pack_disprove, pack_recon_agent
    from vulnforge.paths import system_prompts_root

    pol, _ = normalize_policy(POLICY)
    rec = {"revision": 4, "policy": pol}
    rp = pack_recon_agent({}, system_prompts_root(), "body", {}, security_policy=rec)
    assert "Operator security policy (recon rev 4)" in rp.user
    assert "ground truth" in rp.user
    dp = pack_disprove({}, system_prompts_root(), {"title": "t"}, [], security_policy=rec)
    assert "POLICY_RULE=<id>" in dp.user
    assert "ex-vendor" in dp.user


def test_parse_policy_citations_filters_unknown_ids():
    pol, _ = normalize_policy(POLICY)
    out = parse_policy_citations(
        "VERDICT=reject\nPOLICY_RULE=ex-vendor\nPOLICY_RULE = nope\nPOLICY_RULE=ex-vendor.", pol
    )
    assert out == ["ex-vendor"]
    assert parse_policy_citations("POLICY_RULE=ex-vendor", None) == []


# --- storage -----------------------------------------------------------------


def test_db_revisions_restore_and_validation(tmp_path: Path):
    db = _db(tmp_path)
    assert db.get_security_policy() is None
    r1 = db.set_security_policy(POLICY, source="cli", note="first")
    r2 = db.set_security_policy({"notes": "second"})
    cur = db.get_security_policy()
    assert cur["revision"] == r2 and cur["policy"]["notes"] == "second"
    with pytest.raises(PolicyError):
        db.set_security_policy({"bogus": 1})
    assert db.get_security_policy()["revision"] == r2  # nothing appended
    hist = db.list_security_policy_revisions()
    assert [h["revision"] for h in hist] == [r2, r1]
    assert hist[1]["note"] == "first"
    r3 = db.restore_security_policy_revision(r1)
    cur = db.get_security_policy()
    assert cur["revision"] == r3 and cur["source"] == "restore"
    assert cur["policy"]["exclusions"][0]["id"] == "ex-vendor"
    assert db.restore_security_policy_revision(9999) is None
    db.close()


def test_db_revision_cap_keeps_newest(tmp_path: Path):
    db = _db(tmp_path)
    last = None
    for i in range(SECURITY_POLICY_REVISION_CAP + 3):
        last = db.set_security_policy({"notes": f"n{i}"})
    revs = db.list_security_policy_revisions(limit=SECURITY_POLICY_REVISION_CAP)
    assert len(revs) == SECURITY_POLICY_REVISION_CAP
    assert revs[0]["revision"] == last
    db.close()


def test_table_created_on_open_of_older_db(tmp_path: Path):
    db = _db(tmp_path)
    db.conn.execute("DROP TABLE security_policy_revisions")
    db.conn.commit()
    db.close()
    db2 = Database.open(tmp_path / "harness.db")
    assert db2.get_security_policy() is None
    db2.close()


def test_draft_from_security_md(tmp_path: Path):
    tgt = tmp_path / "tgt"
    (tgt / ".github").mkdir(parents=True)
    assert draft_from_security_md(tgt) is None
    (tgt / ".github" / "SECURITY.md").write_text("# Security\nReport to x.\n", encoding="utf-8")
    d = draft_from_security_md(tgt)
    assert d["source_path"] == ".github/SECURITY.md"
    assert "Report to x." in d["policy"]["notes"]
    assert d["policy"]["exclusions"] == []  # no invented rules
    assert normalize_policy(d["policy"])[1] == []


# --- recon + validate_llm wiring ---------------------------------------------


def test_store_merged_architecture_stamps_policy_revision(tmp_path: Path):
    from vulnforge.stages.recon import store_merged_architecture

    db = _db(tmp_path)
    rev = db.set_security_policy(POLICY)
    arch = store_merged_architecture(
        db, part={"summary": "s", "components": []}, agents_run=[], inventory={}, seed_sinks=[]
    )
    assert arch["security_policy_revision"] == rev
    db.close()


def test_validate_llm_passes_policy_and_records_citations(
    tmp_path: Path, toy_sqli: Path, monkeypatch
):
    from tests.test_validate_llm_safety import (
        T,
        _fake_cfg,
        _good_body,
        _setup_run,
        _stamp_mech_pass,
        _write_evidence,
    )
    from vulnforge.stages import validate_llm

    run_dir, db = _setup_run(tmp_path, toy_sqli)
    db.set_security_policy(
        {"exclusions": [{"id": "ex-app", "paths": ["app.py"], "reason": "accepted risk"}]}
    )
    seen: list = []
    real = validate_llm.pack_disprove

    def spy(*a, **kw):
        seen.append(kw.get("security_policy"))
        return real(*a, **kw)

    monkeypatch.setattr(validate_llm, "pack_disprove", spy)
    body = _stamp_mech_pass(_good_body(toy_sqli))
    _write_evidence(run_dir)
    fid = db.insert_finding(body, state="needs_human")
    stand_cite = "VERDICT=stand\nPOLICY_RULE=ex-app\nPOLICY_RULE=made-up"
    r = validate_llm.run(T(fid), db, run_dir, _fake_cfg(stand_cite, stand_cite))
    assert r["status"] == "succeeded"
    assert seen and all(s and s["policy"]["exclusions"][0]["id"] == "ex-app" for s in seen)
    f = db.get_finding(fid)
    # Citing a rule never changes verdict aggregation: stand stays needs_human.
    assert f.state == "needs_human"
    vl = f.body["validation_llm"]
    assert vl["policy_rules_cited"] == ["ex-app"]
    assert all(v["policy_rules_cited"] == ["ex-app"] for v in vl["verifiers"])
    db.close()


# --- report / export / API / CLI ---------------------------------------------


def _excluded_db(tmp_path: Path) -> tuple[Database, int]:
    db = _db(tmp_path)
    body = {
        "title": "SQLi in vendored lib",
        "weakness_class": "injection",
        "severity_claim": "LOW",
        "severity_claim_original": "HIGH",
        "severity_rubric": {"rule_id": "sev-admin", "action": "capped", "from": "HIGH", "to": "LOW"},
        "validation_reasons": ["policy_excluded:ex-vendor"],
        "policy_match": {
            "kind": "excluded",
            "rule_id": "ex-vendor",
            "reason": "vendored | upstream",
            "matched_paths": ["vendor/lib.py"],
            "policy_revision": 1,
        },
        "citations": [{"path": "vendor/lib.py", "start_line": 1}],
    }
    fid = db.insert_finding(body, state="rejected_mech", stable_key="pol-1")
    return db, fid


def test_report_md_lists_policy_excluded(tmp_path: Path):
    from vulnforge.stages.render import write_report_md

    db, fid = _excluded_db(tmp_path)
    out = tmp_path / "REPORT.md"
    write_report_md(out, db)
    text = out.read_text(encoding="utf-8")
    assert "## Excluded by security policy" in text
    sec = text.split("## Excluded by security policy", 1)[1].split("\n## ", 1)[0]
    assert f"| {fid} | SQLi in vendored lib |" in sec
    assert "`ex-vendor`" in sec and "vendor/lib.py" in sec
    assert "vendored \\| upstream" in sec
    db.close()


def test_report_md_keeps_policy_match_after_human_reopen(tmp_path: Path):
    from vulnforge.stages.render import write_report_md

    db, fid = _excluded_db(tmp_path)
    db.conn.execute("UPDATE findings SET state='needs_human' WHERE id=?", (fid,))
    db.conn.commit()
    out = tmp_path / "REPORT.md"
    write_report_md(out, db)
    text = out.read_text(encoding="utf-8")
    assert "security policy:** excluded by rule `ex-vendor`" in text
    assert "hunter claimed HIGH; capped by policy rule `sev-admin`" in text
    db.close()


def test_report_md_survives_malformed_policy_match(tmp_path: Path):
    from vulnforge.stages.render import write_report_md

    db, fid = _excluded_db(tmp_path)
    f = db.get_finding(fid)
    body = dict(f.body)
    body["policy_match"] = {"kind": "excluded", "rule_id": "ex-1", "matched_paths": 5}
    db.conn.execute("UPDATE findings SET body_json=? WHERE id=?", (json.dumps(body), fid))
    db.conn.commit()
    out = tmp_path / "REPORT.md"
    write_report_md(out, db)
    assert "`ex-1`" in out.read_text(encoding="utf-8")
    db.close()


def test_export_rows_carry_policy_rule(tmp_path: Path):
    from vulnforge.export_findings import ROW_COLUMNS, findings_to_rows

    db, fid = _excluded_db(tmp_path)
    assert "policy_rule" in ROW_COLUMNS
    rows = findings_to_rows(db)
    row = next(r for r in rows if r["id"] == fid)
    assert row["policy_rule"] == "excluded:ex-vendor; capped:sev-admin"
    assert row["severity_claim_original"] == "HIGH"
    db.close()


def _api(tmp_path: Path, target: Path):
    from vulnforge.ui.app import create_app

    runs_root = tmp_path / "runs"
    run = runs_root / "toy" / "run-001"
    run.mkdir(parents=True)
    (run / "evidence").mkdir()
    (run / "project").mkdir()
    db = Database.create(run / "harness.db")
    db.insert_run("run-001", str(target.resolve()), "code_static", "pin", {})
    db.close()
    return TestClient(create_app(runs_root=runs_root)), "/api/runs/toy/run-001/security-policy"


def test_api_policy_round_trip(tmp_path: Path, toy_sqli: Path):
    client, base = _api(tmp_path, toy_sqli)
    r = client.get(base)
    assert r.status_code == 200 and r.json()["revision"] is None
    bad = client.put(base, json={"policy": {"exclusions": [{"paths": []}]}})
    assert bad.status_code == 400
    assert bad.json()["detail"]["errors"]
    assert client.get(f"{base}/history").json()["count"] == 0
    ok = client.put(base, json={"policy": POLICY, "note": "v1"})
    assert ok.status_code == 200, ok.text
    rev1 = ok.json()["revision"]
    client.put(base, json={"policy": {"notes": "v2"}})
    hist = client.get(f"{base}/history").json()["revisions"]
    assert [h["revision"] for h in hist][1] == rev1
    one = client.get(f"{base}/history/{rev1}").json()
    assert one["policy"]["exclusions"][0]["id"] == "ex-vendor"
    assert client.get(f"{base}/history/9999").status_code == 404
    rest = client.post(f"{base}/restore/{rev1}", json={"note": "back"})
    assert rest.status_code == 200
    cur = client.get(base).json()
    assert cur["source"] == "restore" and cur["policy"]["exclusions"][0]["id"] == "ex-vendor"


def test_api_draft_security_md_is_not_saved(tmp_path: Path, toy_sqli: Path):
    client, base = _api(tmp_path, toy_sqli)
    assert client.get(f"{base}/draft/security-md").json()["found"] is False
    (toy_sqli / "SECURITY.md").write_text("Only /api is public.\n", encoding="utf-8")
    d = client.get(f"{base}/draft/security-md").json()
    assert d["found"] is True and d["saved"] is False
    assert "Only /api is public." in d["policy"]["notes"]
    assert client.get(base).json()["revision"] is None


def test_cli_policy_set_show_history_restore(tmp_path: Path, toy_sqli: Path, capsys):
    from vulnforge.cli import EXIT_CONFIG, EXIT_PROGRESS, main

    run_dir = tmp_path / "run-001"
    run_dir.mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", str(toy_sqli), "code_static", "pin", {})
    db.close()
    f = tmp_path / "p.json"
    f.write_text(json.dumps(POLICY), encoding="utf-8")
    rd = ["--run-dir", str(run_dir)]
    assert main(["policy", "set", "--file", str(f), "--note", "n", *rd]) == EXIT_PROGRESS
    rev1 = json.loads(capsys.readouterr().out)["revision"]
    f.write_text(json.dumps({"bogus": True}), encoding="utf-8")
    assert main(["policy", "set", "--file", str(f), *rd]) == EXIT_CONFIG
    capsys.readouterr()
    assert main(["policy", "show", *rd]) == EXIT_PROGRESS
    assert json.loads(capsys.readouterr().out)["revision"] == rev1
    assert main(["policy", "history", *rd]) == EXIT_PROGRESS
    assert len(json.loads(capsys.readouterr().out)["revisions"]) == 1
    assert main(["policy", "restore", "--revision", str(rev1), *rd]) == EXIT_PROGRESS
    capsys.readouterr()
    assert main(["policy", "draft-security-md", *rd]) == EXIT_CONFIG
    capsys.readouterr()
    (toy_sqli / "SECURITY.md").write_text("Report privately.\n", encoding="utf-8")
    assert main(["policy", "draft-security-md", *rd]) == EXIT_PROGRESS
    assert json.loads(capsys.readouterr().out)["saved"] is False
    assert main(["policy", "draft-security-md", "--save", *rd]) == EXIT_PROGRESS
    out = json.loads(capsys.readouterr().out)
    assert out["saved"] is True
    db = Database.open(run_dir / "harness.db")
    cur = db.get_security_policy()
    assert cur["source"] == "security_md" and "Report privately." in cur["policy"]["notes"]
    db.close()
