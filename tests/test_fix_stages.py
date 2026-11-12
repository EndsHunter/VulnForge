"""develop_fix + verify_fix stages, offline with FakeLLMClient (#186).

Invariants under test: target tree never mutated, finding state never changed,
verifier never sees the fix author's notes, ``inconclusive`` always lists what
would resolve it, PoC re-runs are forced to mount the patched tree.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnforge.control import fix_ops
from vulnforge.db import Database
from vulnforge.llm import LLMResult, ResponseClass
from vulnforge.stages import develop_fix, verify_fix
from vulnforge.util import build_target_manifest, write_json

from tests.test_fix_patch import SQLI_FIX, _snapshot

NOTES_MARKER = "AUTHOR-RATIONALE-7f3a9c-do-not-leak"


def _setup(tmp_path: Path, target: Path):
    run_dir = tmp_path / "run-001"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    write_json(run_dir / "target_manifest.json", build_target_manifest(target, []))
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", str(target), "code_static", "pin", {})
    return run_dir, db


def _body(eid: str = "e-fix") -> dict:
    return {
        "title": "SQL injection in search_users",
        "summary": "User input is concatenated into SQL.",
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "unauthenticated user",
            "boundary": "HTTP query parameter to SQL engine",
            "impact": "read arbitrary rows",
        },
        "citations": [{"path": "app.py", "start_line": 11, "symbol": "search_users"}],
        "severity_claim": "HIGH",
        "evidence_id": eid,
    }


def _tool(i: int, name: str, **args) -> LLMResult:
    return LLMResult(
        ok=True,
        classification=ResponseClass.OK,
        content="",
        tool_calls=[{"id": str(i), "name": name, "arguments": args}],
        raw=None,
        model_id="fake",
    )


def _final(text: str) -> LLMResult:
    return LLMResult(
        ok=True, classification=ResponseClass.OK, content=text, tool_calls=[], raw=None, model_id="fake"
    )


def _cfg(responses: list, **extra) -> dict:
    cfg = {
        "llm": {"fake": True, "fake_responses": responses, "max_tool_rounds": 6},
        "run": {"ignore_globs": [], "max_tasks": 10},
        "packet": {},
        "tools": {},
    }
    cfg.update(extra)
    return cfg


def _lease(db: Database, kind: str, payload: dict):
    tid = db.enqueue_task(kind, payload)
    task = db.lease_next_task("w", 60)
    assert task and task.id == tid
    return task


def _verdict(v: str, conf: str = "high", hint: str = "") -> LLMResult:
    text = f"VERDICT={v}\nCONFIDENCE={conf}\nREASONING=read app.py search_users\n"
    if hint:
        text += f"WOULD_RESOLVE={hint}\n"
    return _final(text)


def _all_text_outside_evidence(run_dir: Path) -> str:
    out = []
    for p in run_dir.rglob("*"):
        if (
            p.is_file()
            and "evidence" not in p.relative_to(run_dir).parts
            and not p.name.startswith("harness.db")  # the finding row itself holds the notes
        ):
            out.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(out)


# --------------------------------------------------------------------------- develop_fix


def test_develop_fix_writes_patch_never_target(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = db.insert_finding(_body(), state="confirmed", evidence_id="e-fix")
    before = _snapshot(toy_sqli)
    task = _lease(db, "develop_fix", {"finding_id": fid, "operator_notes": "use params"})
    cfg = _cfg(
        [
            _tool(1, "write_evidence", relpath="poc.py", content="print('not allowed here')\n"),
            _tool(2, "write_evidence", relpath="fix.patch", content=SQLI_FIX),
            _tool(3, "write_evidence", relpath="fix_notes.md", content="Root cause: f-string SQL. Use params.\n"),
            _final("Wrote fix.patch"),
        ]
    )
    r = develop_fix.run(task, db, run_dir, cfg)
    assert r["status"] == "succeeded", r
    assert r["applies"] is True
    assert r["patch_files"] == ["app.py"]
    assert r["finding_state"] == "confirmed"
    pack = run_dir / "evidence" / "e-fix"
    assert (pack / "fix.patch").read_text() == SQLI_FIX
    assert not (pack / "poc.py").exists()  # relpath allowlist held
    check = json.loads((pack / "fix_check.json").read_text())
    assert check["applies"] is True and check["parse_ok"] is True
    f = db.get_finding(fid)
    assert f.state == "confirmed"
    assert f.body["fix_relpath"] == "fix.patch"
    assert f.body["fix_development_latest"]["applies"] is True
    assert _snapshot(toy_sqli) == before
    db.close()


def test_develop_fix_records_non_applying_patch(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = db.insert_finding(_body(), state="needs_human", evidence_id="e-fix")
    task = _lease(db, "develop_fix", {"finding_id": fid})
    bad = SQLI_FIX.replace("INTENTIONALLY VULNERABLE", "NOT IN FILE")
    cfg = _cfg([_tool(1, "write_evidence", relpath="fix.patch", content=bad), _final("done")])
    r = develop_fix.run(task, db, run_dir, cfg)
    assert r["status"] == "succeeded"
    assert r["applies"] is False
    assert any("context_mismatch" in e for e in r["patch_errors"])
    assert db.get_finding(fid).state == "needs_human"
    db.close()


def test_develop_fix_requires_a_patch(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = db.insert_finding(_body(), state="confirmed", evidence_id="e-fix")
    task = _lease(db, "develop_fix", {"finding_id": fid})
    r = develop_fix.run(task, db, run_dir, _cfg([_final("I could not find a fix.")]))
    assert r["status"] == "failed_task"
    assert r["error"] == "no_fix_patch_written"
    db.close()


def test_develop_fix_invalid_patch_fails(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = db.insert_finding(_body(), state="confirmed", evidence_id="e-fix")
    task = _lease(db, "develop_fix", {"finding_id": fid})
    cfg = _cfg(
        [
            _tool(1, "write_evidence", relpath="fix.patch", content="--- ../x\n+++ ../x\n@@ -1 +1 @@\n-a\n+b\n"),
            _final("done"),
        ]
    )
    r = develop_fix.run(task, db, run_dir, cfg)
    assert r["status"] == "failed_task"
    assert r["error"] == "invalid_fix_patch"
    db.close()


def test_develop_fix_state_gate_and_force(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = db.insert_finding(_body(), state="rejected_mech", evidence_id="e-fix")
    task = _lease(db, "develop_fix", {"finding_id": fid})
    r = develop_fix.run(task, db, run_dir, _cfg([]))
    assert r["status"] == "failed_task"
    assert r["error"].startswith("finding_state_not_eligible")
    db.close()
    assert fix_ops.enqueue_develop_fix(run_dir, fid)["ok"] is False
    r2 = fix_ops.enqueue_develop_fix(run_dir, fid, force=True, operator_notes="try")
    assert r2["ok"] is True and r2["kind"] == "develop_fix"
    db = Database.open(run_dir / "harness.db")
    row = db.conn.execute("SELECT payload_json, priority FROM tasks WHERE id=?", (r2["task_id"],)).fetchone()
    payload = json.loads(row["payload_json"])
    assert payload["force"] is True and payload["operator_notes"] == "try"
    assert row["priority"] == 30
    assert db.get_finding(fid).state == "rejected_mech"
    db.close()


def test_cli_dispatch_develop_fix(tmp_path: Path, toy_sqli: Path):
    from vulnforge.cli import dispatch_task

    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = db.insert_finding(_body(), state="confirmed", evidence_id="e-fix")
    task = _lease(db, "develop_fix", {"finding_id": fid})
    cfg = _cfg([_tool(1, "write_evidence", relpath="fix.patch", content=SQLI_FIX), _final("ok")])
    assert dispatch_task(task, db, run_dir, cfg)["status"] == "succeeded"
    db.close()


# --------------------------------------------------------------------------- verify_fix


def _with_fix_patch(run_dir: Path, db: Database, *, state: str = "confirmed") -> int:
    pack = run_dir / "evidence" / "e-fix"
    pack.mkdir(parents=True, exist_ok=True)
    (pack / "fix.patch").write_text(SQLI_FIX, encoding="utf-8")
    (pack / "fix_notes.md").write_text(f"{NOTES_MARKER}: trust me, it is fixed.\n", encoding="utf-8")
    body = _body()
    body["fix_relpath"] = "fix.patch"
    body["fix_development_latest"] = {"notes": NOTES_MARKER}
    body["remediation"] = f"{NOTES_MARKER} use parameters"
    return db.insert_finding(body, state=state, evidence_id="e-fix")


def test_verify_fix_static_only_fixed_and_independent(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _with_fix_patch(run_dir, db)
    before = _snapshot(toy_sqli)
    task = _lease(db, "verify_fix", {"finding_id": fid, "use_fix_patch": True})
    cfg = _cfg(
        [
            _tool(1, "read_file", path="app.py"),
            _tool(2, "write_evidence", relpath="fix_notes.md", content="overwrite attempt by verifier"),
            _tool(3, "read_evidence", relpath="fix_notes.md"),
            _verdict("fixed", "high"),
        ]
    )
    r = verify_fix.run(task, db, run_dir, cfg)
    assert r["status"] == "succeeded", r
    assert r["verdict"] == "fixed"
    assert r["basis"] == "static_only"
    assert r["confidence"] == "medium"  # static-only is capped
    assert r["poc_evidence"] == "no_poc"
    assert r["finding_state"] == "confirmed"

    pack = run_dir / "evidence" / "e-fix"
    rec = json.loads((pack / "verify_fix.json").read_text())
    assert rec["verdict"] == "fixed"
    assert rec["source"]["source"] == "fix_patch"
    assert rec["cited_diff"]["any_region_changed"] is True
    # Verifier had no write and no pack-read tools; notes untouched and never shown.
    assert NOTES_MARKER in (pack / "fix_notes.md").read_text()
    text = _all_text_outside_evidence(run_dir)
    assert "tool_not_allowed_in_stage" in text
    assert NOTES_MARKER not in text
    # Verifier read the PATCHED tree.
    assert "execute(sql, (q,))" in text
    # Scratch tree cleaned up; target untouched; state untouched.
    scratch = run_dir / "scratch" / "verify_fix"
    assert not scratch.exists() or not any(scratch.iterdir())
    assert _snapshot(toy_sqli) == before
    f = db.get_finding(fid)
    assert f.state == "confirmed"
    assert f.body["fix_verification_latest"]["verdict"] == "fixed"
    db.close()


def test_verify_fix_unchanged_tree_is_inconclusive(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = db.insert_finding(_body(), state="needs_human", evidence_id="e-fix")
    patched = tmp_path / "patched_copy"
    shutil.copytree(toy_sqli, patched)  # identical: nothing was fixed
    task = _lease(db, "verify_fix", {"finding_id": fid, "patched_path": str(patched)})
    r = verify_fix.run(task, db, run_dir, _cfg([_verdict("fixed", "high")]))
    assert r["status"] == "succeeded"
    assert r["verdict"] == "inconclusive"
    assert r["would_resolve"], "inconclusive must list what would resolve it"
    assert patched.is_dir() and (patched / "app.py").is_file()  # operator tree kept
    rec = json.loads((run_dir / "evidence" / "e-fix" / "verify_fix.json").read_text())
    assert rec["cited_diff"]["cited_code_unchanged"] is True
    assert db.get_finding(fid).state == "needs_human"
    db.close()


def test_verify_fix_still_vulnerable(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _with_fix_patch(run_dir, db)
    task = _lease(db, "verify_fix", {"finding_id": fid, "use_fix_patch": True})
    r = verify_fix.run(
        task, db, run_dir, _cfg([_verdict("still_vulnerable", "high", "test the admin endpoint")])
    )
    assert r["verdict"] == "still_vulnerable"
    assert r["confidence"] == "medium"
    assert db.get_finding(fid).state == "confirmed"
    db.close()


def test_verify_fix_unparseable_is_inconclusive(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _with_fix_patch(run_dir, db)
    task = _lease(db, "verify_fix", {"finding_id": fid, "use_fix_patch": True})
    r = verify_fix.run(task, db, run_dir, _cfg([_final("Looks good to me!")]))
    assert r["verdict"] == "inconclusive"
    assert any("VERDICT" in h for h in r["would_resolve"])
    db.close()


def test_verify_fix_source_validation(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = db.insert_finding(_body(), state="confirmed", evidence_id="e-fix")
    for payload, err in (
        ({"finding_id": fid}, "need_exactly_one_source"),
        ({"finding_id": fid, "use_fix_patch": True, "git_rev": "HEAD"}, "need_exactly_one_source"),
        ({"finding_id": fid, "use_fix_patch": True}, "fix_patch_missing"),
        ({"finding_id": fid, "patched_path": str(tmp_path / "nope")}, "patched_path_not_dir"),
        ({"finding_id": fid, "git_rev": "--upload-pack=x"}, "invalid_git_rev"),
    ):
        task = SimpleNamespace(id=0, kind="verify_fix", payload=payload)
        r = verify_fix.run(task, db, run_dir, _cfg([]))
        assert r["status"] == "failed_task" and err in r["error"], (payload, r)
    db.close()
    assert fix_ops.enqueue_verify_fix(run_dir, fid)["ok"] is False
    assert "fix_patch_missing" in fix_ops.enqueue_verify_fix(run_dir, fid, use_fix_patch=True)["error"]
    ok = fix_ops.enqueue_verify_fix(run_dir, fid, patched_path=str(toy_sqli), baseline=False)
    assert ok["ok"] and ok["kind"] == "verify_fix"


def test_verify_fix_patch_that_does_not_apply(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _with_fix_patch(run_dir, db)
    (run_dir / "evidence" / "e-fix" / "fix.patch").write_text(
        SQLI_FIX.replace("INTENTIONALLY", "NOPE"), encoding="utf-8"
    )
    task = _lease(db, "verify_fix", {"finding_id": fid, "use_fix_patch": True})
    r = verify_fix.run(task, db, run_dir, _cfg([]))
    assert r["status"] == "failed_task"
    assert "fix_patch_does_not_apply" in r["error"]
    db.close()


# --------------------------------------------------------------------------- PoC re-run


def _add_poc(run_dir: Path, *, target_bound: bool = True) -> None:
    pack = run_dir / "evidence" / "e-fix"
    pack.mkdir(parents=True, exist_ok=True)
    src = "import sys\nsys.path.insert(0, '/target')\n" if target_bound else ""
    (pack / "poc.py").write_text(src + "import app\nprint('ASSERT_OK')\n", encoding="utf-8")


def _fake_exec(observed_on: set[str], *, mount: bool = True, calls: list | None = None):
    def fake(pack_dir, *, cfg=None, target_path=None, **kw):
        if calls is not None:
            calls.append({"cfg": cfg, "target_path": target_path})
        assert (cfg or {}).get("poc_harness", {}).get("mount_target_ro") is True
        resolved = str(Path(target_path).resolve())
        hit = any(resolved == str(Path(p).resolve()) for p in observed_on)
        argv = ["docker", "run", "-v", f"{resolved}:/target:ro"] if mount else None
        return {
            "verdict": "signal_observed" if hit else "signal_absent",
            "signal_matched": hit,
            "exit_code": 0,
            "ran": True,
            "timed_out": False,
            "argv": argv,
            "isolation": "gvisor",
        }

    return fake


def test_verify_fix_poc_supports_fixed(tmp_path: Path, toy_sqli: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _with_fix_patch(run_dir, db)
    _add_poc(run_dir)
    calls: list = []
    monkeypatch.setattr(pr, "execute_poc_for_pack", _fake_exec({str(toy_sqli)}, calls=calls))
    task = _lease(db, "verify_fix", {"finding_id": fid, "use_fix_patch": True})
    r = verify_fix.run(task, db, run_dir, _cfg([_verdict("fixed", "high")]))
    assert r["verdict"] == "fixed", r
    assert r["basis"] == "poc+static"
    assert r["confidence"] == "high"
    assert r["poc_evidence"] == "supports_fixed"
    # One patched run (scratch tree) + one same-task baseline (original target).
    paths = [str(Path(c["target_path"]).resolve()) for c in calls]
    assert str(toy_sqli.resolve()) in paths
    assert any("scratch/verify_fix" in p for p in paths)
    assert db.get_finding(fid).state == "confirmed"
    db.close()


def test_verify_fix_poc_reproduces_overrides_llm(tmp_path: Path, toy_sqli: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = db.insert_finding(_body(), state="confirmed", evidence_id="e-fix")
    _add_poc(run_dir)
    patched = tmp_path / "patched"
    shutil.copytree(toy_sqli, patched)
    (patched / "app.py").write_text(
        (patched / "app.py").read_text().replace("execute(sql)", "execute(sql)  # 'fixed'"),
        encoding="utf-8",
    )
    monkeypatch.setattr(pr, "execute_poc_for_pack", _fake_exec({str(toy_sqli), str(patched)}))
    task = _lease(db, "verify_fix", {"finding_id": fid, "patched_path": str(patched)})
    r = verify_fix.run(task, db, run_dir, _cfg([_verdict("fixed", "high")]))
    assert r["verdict"] == "still_vulnerable"
    assert r["basis"] == "poc"
    assert db.get_finding(fid).state == "confirmed"
    db.close()


def test_verify_fix_poc_unmounted_is_inconclusive(tmp_path: Path, toy_sqli: Path, monkeypatch):
    """A PoC that ran without the patched tree mounted says nothing about the fix."""
    import vulnforge.poc_runner as pr

    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _with_fix_patch(run_dir, db)
    _add_poc(run_dir)
    monkeypatch.setattr(pr, "execute_poc_for_pack", _fake_exec({str(toy_sqli)}, mount=False))
    task = _lease(db, "verify_fix", {"finding_id": fid, "use_fix_patch": True})
    r = verify_fix.run(task, db, run_dir, _cfg([_verdict("fixed", "high")]))
    assert r["verdict"] == "inconclusive"
    assert any("/target" in h for h in r["would_resolve"])
    db.close()


def test_verify_fix_poc_not_target_bound(tmp_path: Path, toy_sqli: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _with_fix_patch(run_dir, db)
    _add_poc(run_dir, target_bound=False)
    monkeypatch.setattr(pr, "execute_poc_for_pack", _fake_exec({str(toy_sqli)}))
    task = _lease(db, "verify_fix", {"finding_id": fid, "use_fix_patch": True})
    r = verify_fix.run(task, db, run_dir, _cfg([_verdict("fixed", "high")]))
    assert r["verdict"] == "inconclusive"
    assert r["poc_evidence"] == "no_signal"
    db.close()


def test_verify_fix_harness_disabled_poc_present(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _with_fix_patch(run_dir, db)
    _add_poc(run_dir)
    task = _lease(db, "verify_fix", {"finding_id": fid, "use_fix_patch": True})
    cfg = _cfg([_verdict("fixed", "high")], poc_harness={"enabled": False})
    r = verify_fix.run(task, db, run_dir, cfg)
    # A PoC exists but could not run: static-only fixed is not allowed.
    assert r["verdict"] == "inconclusive"
    assert r["poc_evidence"] == "not_run"
    assert any("poc_harness" in h for h in r["would_resolve"])
    db.close()


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_verify_fix_git_rev_source(tmp_path: Path, toy_sqli: Path):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e"}

    def git(*a):
        subprocess.run(["git", "-C", str(toy_sqli), *a], check=True, env=env, capture_output=True)

    git("init", "-q")
    git("add", ".")
    git("commit", "-q", "-m", "vuln")
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = db.insert_finding(_body(), state="confirmed", evidence_id="e-fix")
    # The "fix" lives on a commit; the working tree (the target) stays vulnerable.
    git("checkout", "-q", "-b", "fix")
    subprocess.run(["git", "-C", str(toy_sqli), "apply", "-"], input=SQLI_FIX.encode(), check=True)
    git("commit", "-q", "-am", "fix")
    git("checkout", "-q", "-")
    before = _snapshot(toy_sqli)
    task = _lease(db, "verify_fix", {"finding_id": fid, "git_rev": "fix"})
    r = verify_fix.run(task, db, run_dir, _cfg([_verdict("fixed", "medium")]))
    assert r["status"] == "succeeded", r
    assert r["verdict"] == "fixed"
    rec = json.loads((run_dir / "evidence" / "e-fix" / "verify_fix.json").read_text())
    assert rec["source"]["source"] == "git_rev" and len(rec["source"]["commit"]) >= 40
    assert _snapshot(toy_sqli) == before
    db.close()


# --------------------------------------------------------------------------- combiner


@pytest.mark.parametrize(
    "llm,poc,region,want",
    [
        ("fixed", "supports_fixed", True, "fixed"),
        ("fixed", "supports_fixed", False, "fixed"),  # fix may live upstream
        ("fixed", "no_poc", True, "fixed"),
        ("fixed", "no_poc", False, "inconclusive"),
        ("fixed", "no_signal", True, "inconclusive"),
        ("fixed", "not_run", True, "inconclusive"),
        ("fixed", "reproduces_on_patched", True, "still_vulnerable"),
        ("still_vulnerable", "no_poc", True, "still_vulnerable"),
        ("still_vulnerable", "supports_fixed", True, "inconclusive"),
        ("inconclusive", "supports_fixed", True, "inconclusive"),
        ("inconclusive", "no_poc", True, "inconclusive"),
    ],
)
def test_combiner_table(llm: str, poc: str, region: bool, want: str):
    out = verify_fix.combine_verdict(
        llm={"verdict": llm, "confidence": "high"},
        poc={"evidence": poc, "present": poc != "no_poc"},
        diff={"any_region_changed": region},
    )
    assert out["verdict"] == want
    if want == "inconclusive":
        assert out["would_resolve"]


def test_parse_verify_output():
    p = verify_fix.parse_verify_output(
        "**VERDICT=still_vulnerable**\nCONFIDENCE=medium\nREASONING=x\n"
        "WOULD_RESOLVE=run poc\nWOULD_RESOLVE=read admin.py\n"
    )
    assert p["verdict"] == "still_vulnerable" and p["confidence"] == "medium"
    assert p["would_resolve"] == ["run poc", "read admin.py"]
    assert verify_fix.parse_verify_output("VERDICT=confirmed")["verdict"] == "inconclusive"


def test_lease_kinds_registered():
    from vulnforge.llm_models import lease_pair

    cfg = {"llm": {"model": "base", "model_develop_poc": "dev-m", "model_validate": "val-m"}}
    assert lease_pair(cfg, "develop_fix")[1] == "dev-m"
    assert lease_pair(cfg, "verify_fix")[1] == "val-m"


def test_fix_api_routes(tmp_path: Path, toy_sqli: Path):
    from fastapi.testclient import TestClient

    from vulnforge.ui.app import create_app

    runs_root = tmp_path / "runs"
    tgt_dir = runs_root / "toy-1"
    tgt_dir.mkdir(parents=True)
    run_dir, db = _setup(tgt_dir, toy_sqli)
    fid = _with_fix_patch(run_dir, db)
    db.close()
    client = TestClient(create_app(runs_root=runs_root))
    base = f"/api/runs/toy-1/run-001/findings/{fid}"
    g = client.get(f"{base}/fix")
    assert g.status_code == 200, g.text
    assert g.json()["fix_patch"] == SQLI_FIX
    d = client.post(f"{base}/develop-fix", json={"operator_notes": "x"})
    assert d.status_code == 200 and d.json()["kind"] == "develop_fix"
    v = client.post(f"{base}/verify-fix", json={"use_fix_patch": True})
    assert v.status_code == 200 and v.json()["kind"] == "verify_fix"
    bad = client.post(f"{base}/verify-fix", json={})
    assert bad.status_code == 400


# --------------------------------------------------------------------------- review regressions


def test_verify_fix_symlinked_poc_blocks_static_fixed(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _with_fix_patch(run_dir, db)
    real = tmp_path / "real_poc.py"
    real.write_text("import sys\nsys.path.insert(0, '/target')\n", encoding="utf-8")
    os.symlink(real, run_dir / "evidence" / "e-fix" / "poc.py")
    task = _lease(db, "verify_fix", {"finding_id": fid, "use_fix_patch": True})
    r = verify_fix.run(task, db, run_dir, _cfg([_verdict("fixed", "high")]))
    assert r["verdict"] == "inconclusive"
    assert r["poc_evidence"] == "not_run"
    db.close()


def test_verifier_never_sees_poc_stdout(tmp_path: Path, toy_sqli: Path, monkeypatch):
    """The PoC can read /work/fix_notes.md; its output must not reach the verifier."""
    import vulnforge.poc_runner as pr

    run_dir, db = _setup(tmp_path, toy_sqli)
    fid = _with_fix_patch(run_dir, db)
    _add_poc(run_dir)
    base = _fake_exec({str(toy_sqli)})

    def leaky(pack_dir, **kw):
        out = base(pack_dir, **kw)
        out["stdout_excerpt"] = f"cat /work/fix_notes.md -> {NOTES_MARKER}"
        return out

    monkeypatch.setattr(pr, "execute_poc_for_pack", leaky)
    task = _lease(db, "verify_fix", {"finding_id": fid, "use_fix_patch": True})
    r = verify_fix.run(task, db, run_dir, _cfg([_verdict("fixed", "high")]))
    assert r["verdict"] == "fixed"
    assert NOTES_MARKER not in _all_text_outside_evidence(run_dir)
    db.close()


def test_verify_fix_run_dir_inside_target_refused(tmp_path: Path, toy_sqli: Path):
    inner = toy_sqli / "runs"
    inner.mkdir()
    run_dir, db = _setup(inner, toy_sqli)
    fid = _with_fix_patch(run_dir, db)
    task = SimpleNamespace(id=0, kind="verify_fix", payload={"finding_id": fid, "use_fix_patch": True})
    r = verify_fix.run(task, db, run_dir, _cfg([]))
    assert r["status"] == "failed_task"
    assert "scratch_inside_source" in r["error"]
    assert not (run_dir / "scratch").exists()
    db.close()
