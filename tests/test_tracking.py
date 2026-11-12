"""Track findings in GitHub Issues (#189). Offline: fake transport only."""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
from io import BytesIO
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import vulnforge.tracking.github as gh
from vulnforge.db import Database
from vulnforge.ui.app import create_app  # noqa: I001 — import before operator_chat (cycle)
from vulnforge.operator_chat import tools_home, tools_run
from vulnforge.operator_chat.tools_common import MUTATE_TOOLS, mutation_summary
from vulnforge.tracking import TrackingError, preview_track, publish_with_token, track_findings
from vulnforge.tracking.base import body_has_marker, build_sink, marker_line
from vulnforge.tracking.render import NOT_PROOF_LINE, evidence_excerpt, render_issue
from vulnforge.ui.store import RunRef, run_snapshot

REPO = "acme/widgets"
CFG = {"tracking": {"sink": "github", "github": {"repo": REPO, "labels": ["security"]}}}


class FakeGitHub:
    """In-memory GitHub Issues API. Records every call."""

    def __init__(self, repo: str = REPO):
        self.repo = repo
        self.issues: dict[int, dict] = {}
        self.calls: list[tuple[str, str, dict | None]] = []
        self.fail_create = False

    def add_issue(self, body: str, labels=("vulnforge",)) -> int:
        n = len(self.issues) + 1
        self.issues[n] = {
            "number": n,
            "title": "pre-existing",
            "body": body,
            "state": "open",
            "labels": [{"name": l} for l in labels],
            "html_url": f"https://github.com/{self.repo}/issues/{n}",
        }
        return n

    def methods(self, method: str) -> list:
        return [c for c in self.calls if c[0] == method]

    def __call__(self, method: str, path: str, body=None):
        self.calls.append((method, path, body))
        base = f"repos/{self.repo}/issues"
        if method == "POST" and path == base:
            if self.fail_create:
                raise TrackingError("boom")
            n = self.add_issue(body["body"], labels=body.get("labels") or ())
            self.issues[n]["title"] = body["title"]
            return self.issues[n]
        if method == "GET" and path.startswith(base + "?"):
            page = int(re.search(r"[?&]page=(\d+)", path).group(1))
            rows = [
                i for i in self.issues.values()
                if any(l["name"] == "vulnforge" for l in i["labels"])
            ]
            return rows[(page - 1) * 100 : page * 100]
        m = re.fullmatch(re.escape(base) + r"/(\d+)", path)
        if m:
            n = int(m.group(1))
            if method == "GET":
                return self.issues[n]
            if method == "PATCH":
                self.issues[n].update(title=body["title"], body=body["body"])
                return self.issues[n]
        raise AssertionError(f"unexpected call {method} {path}")


def _body(title="SQL injection in search_users", path="app.py", eid="e1") -> dict:
    return {
        "title": title,
        "summary": "User input reaches SQL. ping @security-team",
        "weakness_class": "injection",
        "threat_model": {"attacker": "anon", "boundary": "HTTP", "impact": "read rows"},
        "citations": [{"path": path, "start_line": 10, "symbol": "search_users"}],
        "evidence_id": eid,
        "severity_claim": "HIGH",
    }


def _run(tmp_path: Path, target_id="toy", run_id="run-001") -> Path:
    run_dir = tmp_path / "runs" / target_id / run_id
    (run_dir / "evidence").mkdir(parents=True)
    db = Database.create(run_dir / "harness.db")
    db.insert_run(run_id, str(tmp_path), "code_static", "pin", {})
    db.close()
    return run_dir


def _add(run_dir: Path, state="confirmed", **kw) -> int:
    db = Database.open(run_dir / "harness.db")
    try:
        return db.insert_finding(_body(**kw), state=state)
    finally:
        db.close()


def _set_state(run_dir: Path, fid: int, state: str) -> None:
    db = Database.open(run_dir / "harness.db")
    try:
        db.update_finding_state(fid, state)
    finally:
        db.close()


def _key(run_dir: Path, fid: int) -> str:
    db = Database.open(run_dir / "harness.db")
    try:
        return db.get_finding(fid).stable_key
    finally:
        db.close()


# ---------------------------------------------------------------- dedupe


def test_create_then_retrack_updates_same_issue(tmp_path):
    run_dir = _run(tmp_path)
    fid = _add(run_dir)
    fake = FakeGitHub()
    r1 = track_findings(run_dir, [fid], transport=fake, cfg=CFG)
    assert r1["ok"], r1
    assert r1["results"][0]["action"] == "created"
    url = r1["results"][0]["url"]
    assert url == f"https://github.com/{REPO}/issues/1"
    post = fake.methods("POST")[0][2]
    assert post["labels"] == ["vulnforge", "security"]

    r2 = track_findings(run_dir, [fid], transport=fake, cfg=CFG)
    assert r2["ok"], r2
    assert r2["results"][0]["action"] == "updated"
    assert len(fake.methods("POST")) == 1
    assert len(fake.methods("PATCH")) == 1
    assert len(fake.issues) == 1

    db = Database.open(run_dir / "harness.db")
    row = db.get_tracking(_key(run_dir, fid), "github", REPO)
    db.close()
    assert row["status"] == "linked" and row["url"] == url and row["external_id"] == "1"

    snap = run_snapshot(RunRef("toy", "run-001", run_dir))
    f = next(x for x in snap["findings"] if x["id"] == fid)
    assert f["tracking"][0]["url"] == url
    events = (run_dir / "events.jsonl").read_text().splitlines()
    tracked = [json.loads(l) for l in events if "finding_tracked" in l]
    assert [e["action"] for e in tracked] == ["created", "updated"]
    assert "body" not in tracked[0]


def test_new_run_finds_existing_issue_by_marker(tmp_path):
    run_a = _run(tmp_path, run_id="run-001")
    run_b = _run(tmp_path, run_id="run-002")
    fa = _add(run_a)
    fb = _add(run_b)
    assert _key(run_a, fa) == _key(run_b, fb)
    fake = FakeGitHub()
    track_findings(run_a, [fa], transport=fake, cfg=CFG)
    r = track_findings(run_b, [fb], transport=fake, cfg=CFG)
    assert r["results"][0]["action"] == "updated"
    assert len(fake.methods("POST")) == 1
    assert len(fake.issues) == 1


def test_loose_marker_match_does_not_patch(tmp_path):
    run_dir = _run(tmp_path)
    fid = _add(run_dir)
    key = _key(run_dir, fid)
    fake = FakeGitHub()
    # Key mentioned inline / with a suffix, but not the exact marker line.
    fake.add_issue(f"see {marker_line(key)} here")
    fake.add_issue(marker_line(key) + "ff")
    fake.add_issue(f"<!-- {marker_line(key)} -->")
    r = track_findings(run_dir, [fid], transport=fake, cfg=CFG)
    assert r["results"][0]["action"] == "created"
    assert not fake.methods("PATCH")
    assert len(fake.issues) == 4


def test_linked_issue_without_marker_is_not_overwritten(tmp_path):
    run_dir = _run(tmp_path)
    fid = _add(run_dir)
    fake = FakeGitHub()
    track_findings(run_dir, [fid], transport=fake, cfg=CFG)
    fake.issues[1]["body"] = "someone rewrote this issue"
    r = track_findings(run_dir, [fid], transport=fake, cfg=CFG)
    res = r["results"][0]
    assert not res["ok"] and res["action"] == "error"
    assert "refusing" in res["reason"]
    assert not fake.methods("PATCH")


def test_pending_claim_blocks_second_creator(tmp_path):
    run_dir = _run(tmp_path)
    fid = _add(run_dir)
    key = _key(run_dir, fid)
    db = Database.open(run_dir / "harness.db")
    claimed, _ = db.claim_tracking(key, "github", REPO, finding_id=fid)
    db.close()
    assert claimed
    fake = FakeGitHub()
    r = track_findings(run_dir, [fid], transport=fake, cfg=CFG)
    assert "in progress" in r["results"][0]["reason"]
    assert not fake.methods("POST")


def test_stale_pending_claim_rescans_and_links(tmp_path):
    """Crash after POST but before record: the retry finds the issue, no duplicate."""
    run_dir = _run(tmp_path)
    fid = _add(run_dir)
    key = _key(run_dir, fid)
    fake = FakeGitHub()
    payload_issue = render_issue(
        Database.open(run_dir / "harness.db").get_finding(fid), run_dir=run_dir
    )
    fake.add_issue(payload_issue.body_md)
    db = Database.open(run_dir / "harness.db")
    db.claim_tracking(key, "github", REPO, finding_id=fid)
    db.conn.execute("UPDATE finding_tracking SET updated_at='2000-01-01T00:00:00Z'")
    db.conn.commit()
    db.close()
    r = track_findings(run_dir, [fid], transport=fake, cfg=CFG)
    assert r["results"][0]["action"] == "updated"
    assert not fake.methods("POST")


def test_failed_create_releases_claim(tmp_path):
    run_dir = _run(tmp_path)
    fid = _add(run_dir)
    fake = FakeGitHub()
    fake.fail_create = True
    r = track_findings(run_dir, [fid], transport=fake, cfg=CFG)
    assert r["results"][0]["action"] == "error"
    fake.fail_create = False
    r = track_findings(run_dir, [fid], transport=fake, cfg=CFG)
    assert r["results"][0]["action"] == "created"


# ---------------------------------------------------------------- eligibility


def test_default_is_confirmed_only(tmp_path):
    run_dir = _run(tmp_path)
    c = _add(run_dir, "confirmed", path="a.py")
    n = _add(run_dir, "needs_human", path="b.py")
    cand = _add(run_dir, "candidate", path="c.py")
    rej = _add(run_dir, "rejected_human", path="d.py")
    fake = FakeGitHub()
    cfg = {"tracking": {**CFG["tracking"], "include_needs_human": True}}  # ignored
    r = track_findings(run_dir, [c, n, cand, rej], transport=fake, cfg=cfg)
    by = {x["finding_id"]: x for x in r["results"]}
    assert by[c]["ok"]
    assert not by[n]["ok"] and "opt in" in by[n]["reason"]
    assert not by[cand]["ok"] and not by[rej]["ok"]
    assert len(fake.methods("POST")) == 1
    assert r["partial"] and not r["ok"]


def test_needs_human_opt_in_says_not_confirmed(tmp_path):
    run_dir = _run(tmp_path)
    n = _add(run_dir, "needs_human")
    fake = FakeGitHub()
    r = track_findings(run_dir, [n], include_needs_human=True, transport=fake, cfg=CFG)
    assert r["ok"]
    body = fake.issues[1]["body"]
    assert "NOT confirmed" in body and NOT_PROOF_LINE in body
    db = Database.open(run_dir / "harness.db")
    assert db.get_finding(n).state == "needs_human"  # never changes state
    db.close()


def test_cap_per_publish(tmp_path):
    run_dir = _run(tmp_path)
    r = track_findings(run_dir, list(range(1, 30)), transport=FakeGitHub(), cfg=CFG)
    assert not r["ok"] and "at most" in r["error"]


def test_missing_repo_is_an_error(tmp_path):
    run_dir = _run(tmp_path)
    fid = _add(run_dir)
    r = track_findings(run_dir, [fid], transport=FakeGitHub(), cfg={"tracking": {}})
    assert not r["ok"] and "destination" in r["error"]
    with pytest.raises(TrackingError):
        build_sink("github", {}, "../../etc", transport=FakeGitHub())
    with pytest.raises(TrackingError, match="not implemented"):
        build_sink("jira", {}, "X", transport=FakeGitHub())


# ---------------------------------------------------------------- body


def test_issue_body_contents(tmp_path):
    run_dir = _run(tmp_path)
    pack = run_dir / "evidence" / "e1"
    pack.mkdir()
    (pack / "notes.md").write_text("trace: request -> query ``` @attacker", encoding="utf-8")
    (pack / "poc.py").write_text("SECRET_POC_CODE", encoding="utf-8")
    (pack / "poc_run.json").write_text('{"signal": true}', encoding="utf-8")
    fid = _add(run_dir, title="SQLi\nin search @org/team")
    db = Database.open(run_dir / "harness.db")
    f = db.get_finding(fid)
    db.close()
    p = render_issue(f, run_dir=run_dir, run_id="run-001")
    assert "\n" not in p.title and p.title.startswith("[VulnForge] HIGH injection:")
    assert "@org" not in p.title and "@​org" in p.title
    assert NOT_PROOF_LINE in p.body_md  # even with poc_run.json on disk
    assert "accepted by human review" in p.body_md
    assert "`app.py:10` · `search_users`" in p.body_md
    assert "Excerpt from `notes.md`" in p.body_md
    assert "````" in p.body_md  # fence longer than content's backticks
    assert "SECRET_POC_CODE" not in p.body_md
    assert "@security-team" not in p.body_md and "@attacker" not in p.body_md
    assert body_has_marker(p.body_md, f.stable_key)
    assert str(tmp_path) not in p.body_md  # no local target path


def test_excerpt_jail(tmp_path):
    run_dir = _run(tmp_path)
    outside = tmp_path / "outside.md"
    outside.write_text("OUTSIDE", encoding="utf-8")
    assert evidence_excerpt(run_dir, "../x") == (None, None)
    assert evidence_excerpt(run_dir, "../../etc") == (None, None)
    pack = run_dir / "evidence" / "p1"
    pack.mkdir()
    (pack / "notes.md").symlink_to(outside)
    assert evidence_excerpt(run_dir, "p1") == (None, None)
    (run_dir / "evidence" / "link").symlink_to(tmp_path, target_is_directory=True)
    assert evidence_excerpt(run_dir, "link") == (None, None)
    (pack / "evidence.md").write_text("inside", encoding="utf-8")
    assert evidence_excerpt(run_dir, "p1") == ("evidence.md", "inside")


# ---------------------------------------------------------------- dashboard


def test_api_preview_then_publish(tmp_path, monkeypatch):
    run_dir = _run(tmp_path)
    fid = _add(run_dir)
    fake = FakeGitHub()
    monkeypatch.setattr(gh, "resolve_transport", lambda *_a, **_k: fake)
    monkeypatch.setattr(
        "vulnforge.tracking.service.tracking_config", lambda cfg=None: dict(CFG["tracking"])
    )
    client = TestClient(create_app(runs_root=tmp_path / "runs"))
    base = "/api/runs/toy/run-001/findings/track"

    assert client.get("/api/tracking/config").json()["destination"] == REPO

    no_tok = client.post(base, json={"finding_ids": [fid], "confirm": True})
    assert no_tok.status_code == 422  # token is required
    bad = client.post(base, json={"token": "nope"})
    assert bad.status_code == 400

    pv = client.post(base + "/preview", json={"finding_ids": [fid]})
    assert pv.status_code == 200, pv.text
    pj = pv.json()
    assert fake.calls == []  # preview never touches the sink
    assert pj["destination"] == REPO and pj["token"]
    assert NOT_PROOF_LINE in pj["items"][0]["issue_body"]

    pub = client.post(base, json={"token": pj["token"]})
    assert pub.status_code == 200, pub.text
    assert pub.json()["results"][0]["action"] == "created"
    again = client.post(base, json={"token": pj["token"]})
    assert again.status_code == 400  # one-shot


def test_publish_rechecks_state_and_body(tmp_path):
    run_dir = _run(tmp_path)
    a = _add(run_dir, path="a.py")
    b = _add(run_dir, path="b.py")
    fake = FakeGitHub()
    pv = preview_track(run_dir, [a, b], cfg=CFG)
    assert pv["eligible_count"] == 2
    _set_state(run_dir, a, "rejected_human")
    db = Database.open(run_dir / "harness.db")
    f = db.get_finding(b)
    body = dict(f.body, summary="edited after preview")
    db.conn.execute("UPDATE findings SET body_json=? WHERE id=?", (json.dumps(body), b))
    db.conn.commit()
    db.close()
    r = publish_with_token(run_dir, pv["token"], transport=fake, cfg=CFG)
    by = {x["finding_id"]: x for x in r["results"]}
    assert "not eligible" in by[a]["reason"]
    assert "changed since preview" in by[b]["reason"]
    assert fake.calls == []


def test_preview_token_bound_to_run(tmp_path):
    run_a = _run(tmp_path, run_id="run-001")
    run_b = _run(tmp_path, run_id="run-002")
    fid = _add(run_a)
    pv = preview_track(run_a, [fid], cfg=CFG)
    r = publish_with_token(run_b, pv["token"], transport=FakeGitHub(), cfg=CFG)
    assert not r["ok"] and "another run" in r["error"]


def test_preview_without_eligible_has_no_token(tmp_path):
    run_dir = _run(tmp_path)
    fid = _add(run_dir, "needs_human")
    pv = preview_track(run_dir, [fid], cfg=CFG)
    assert pv["ok"] and pv["token"] is None and pv["eligible_count"] == 0


# ---------------------------------------------------------------- operator chat


def test_chat_tool_is_confirm_gated_mutator(tmp_path, monkeypatch):
    run_dir = _run(tmp_path)
    fid = _add(run_dir)
    fake = FakeGitHub()
    monkeypatch.setattr(gh, "resolve_transport", lambda *_a, **_k: fake)
    monkeypatch.setattr(
        "vulnforge.tracking.service.tracking_config", lambda cfg=None: dict(CFG["tracking"])
    )
    assert "track_findings" in MUTATE_TOOLS
    run_names = {s["function"]["name"] for s in tools_run.schemas()}
    home_names = {s["function"]["name"] for s in tools_home.schemas()}
    assert "track_findings" in run_names and "track_findings" not in home_names

    run = RunRef("toy", "run-001", run_dir)
    pending = tools_run.dispatch("track_findings", {"finding_ids": [fid]}, run=run)
    assert pending["pending_confirm"] is True
    assert fake.calls == []

    summary = mutation_summary("track_findings", {"finding_ids": [fid]})
    assert REPO in summary and "PUBLISH OUTSIDE" in summary
    assert "Only confirmed" in summary
    nh = mutation_summary(
        "track_findings", {"finding_ids": [fid], "include_needs_human": True}
    )
    assert "NOT confirmed" in nh

    done = tools_run.dispatch(
        "track_findings", {"finding_ids": [fid]}, run=run, execute_mutations=True
    )
    assert done["ok"] and done["results"][0]["action"] == "created"


def test_ralph_and_stages_never_import_tracking():
    root = Path(__file__).resolve().parents[1]
    paths = [root / "scripts" / "ralph.py", root / "vulnforge" / "ui" / "runner.py"]
    paths += list((root / "vulnforge" / "stages").rglob("*.py"))
    paths += list((root / "vulnforge" / "agent_runtime").rglob("*.py"))
    for p in paths:
        if p.is_file():
            assert "vulnforge.tracking" not in p.read_text(encoding="utf-8"), p


# ---------------------------------------------------------------- transports


def test_gh_transport_argv_and_redaction(monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        seen["kw"] = kw
        return subprocess.CompletedProcess(cmd, 1, "", "HTTP 401 token ghp_" + "a" * 36)

    monkeypatch.setattr(gh, "_run", fake_run)
    t = gh.GhCliTransport(gh_path="gh")
    with pytest.raises(TrackingError) as ei:
        t("POST", f"repos/{REPO}/issues", {"title": "x", "body": "y"})
    assert "ghp_" not in str(ei.value) and "[redacted]" in str(ei.value)
    assert seen["cmd"][:4] == ["gh", "api", "-X", "POST"]
    assert seen["cmd"][-2:] == ["--input", "-"]
    assert "shell" not in seen["kw"]
    assert json.loads(seen["kw"]["input"]) == {"title": "x", "body": "y"}


def test_token_transport_keeps_token_out_of_errors(monkeypatch):
    secret = "ghp_" + "Z" * 36
    monkeypatch.setenv("VF_GITHUB_TOKEN", secret)
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"] = req.full_url
        seen["auth"] = req.get_header("Authorization")
        raise urllib.error.HTTPError(
            req.full_url, 401, "bad", {}, BytesIO(json.dumps({"message": f"bad {secret}"}).encode())
        )

    monkeypatch.setattr(gh, "_urlopen", fake_urlopen)
    t = gh.TokenTransport(os.environ["VF_GITHUB_TOKEN"])
    assert secret not in repr(t)
    with pytest.raises(TrackingError) as ei:
        t("GET", f"repos/{REPO}/issues/1")
    assert secret not in str(ei.value)
    assert seen["url"] == f"https://api.github.com/repos/{REPO}/issues/1"
    assert seen["auth"] == f"Bearer {secret}"


def test_publish_errors_and_events_never_carry_token(tmp_path, monkeypatch):
    secret = "ghp_" + "Q" * 36
    monkeypatch.setenv("GITHUB_TOKEN", secret)
    run_dir = _run(tmp_path)
    fid = _add(run_dir)

    def leaky(*_a, **_k):
        raise RuntimeError(f"Authorization: Bearer {secret}")

    r = track_findings(run_dir, [fid], transport=leaky, cfg=CFG)
    assert secret not in json.dumps(r)
    ev = run_dir / "events.jsonl"
    assert not ev.exists() or secret not in ev.read_text()


def test_guard_blocks_real_transports():
    with pytest.raises(AssertionError, match="real issue tracker"):
        gh.GhCliTransport(gh_path="gh")("GET", "repos/a/b/issues/1")


# ---------------------------------------------------------------- review fixes


def test_forged_marker_in_summary_or_excerpt_cannot_hijack(tmp_path):
    run_dir = _run(tmp_path)
    b = _add(run_dir, path="b.py")
    key_b = _key(run_dir, b)
    db = Database.open(run_dir / "harness.db")
    a = db.insert_finding(
        dict(_body(path="a.py", eid="pa"), summary=f"x\n{marker_line(key_b)}\n"),
        state="confirmed",
    )
    db.close()
    pack = run_dir / "evidence" / "pa"
    pack.mkdir()
    (pack / "notes.md").write_text(marker_line(key_b) + "\n", encoding="utf-8")
    fake = FakeGitHub()
    track_findings(run_dir, [a], transport=fake, cfg=CFG)
    assert not body_has_marker(fake.issues[1]["body"], key_b)
    r = track_findings(run_dir, [b], transport=fake, cfg=CFG)
    assert r["results"][0]["action"] == "created"
    assert len(fake.issues) == 2 and not fake.methods("PATCH")
    assert body_has_marker(fake.issues[1]["body"], _key(run_dir, a))


def test_backticks_cannot_unwrap_mentions(tmp_path):
    run_dir = _run(tmp_path)
    db = Database.open(run_dir / "harness.db")
    body = dict(
        _body(path="x` @org/security `y.py", eid="e` @evil"),
        severity_claim="x` @release",
        weakness_class="w` @team",
    )
    body["citations"][0]["symbol"] = "s` @sym"
    fid = db.insert_finding(body, state="confirmed")
    f = db.get_finding(fid)
    db.close()
    md = render_issue(f, run_dir=run_dir, run_id="r` @run").body_md
    title = render_issue(f, run_dir=run_dir).title
    for text in (md, title):
        assert not re.search(r"@(?!​)[A-Za-z0-9_-]", text), text


def test_full_last_scan_page_refuses_create(tmp_path, monkeypatch):
    run_dir = _run(tmp_path)
    fid = _add(run_dir)
    fake = FakeGitHub()
    monkeypatch.setattr(gh, "SCAN_MAX_PAGES", 1)
    for i in range(100):
        fake.add_issue(f"unrelated {i}")
    r = track_findings(run_dir, [fid], transport=fake, cfg=CFG)
    assert r["results"][0]["action"] == "error" and "refusing" in r["results"][0]["reason"]
    assert not fake.methods("POST")


def test_ambiguous_marker_refuses(tmp_path):
    run_dir = _run(tmp_path)
    fid = _add(run_dir)
    key = _key(run_dir, fid)
    fake = FakeGitHub()
    fake.add_issue("a\n" + marker_line(key))
    fake.add_issue("b\n" + marker_line(key))
    r = track_findings(run_dir, [fid], transport=fake, cfg=CFG)
    assert "several issues" in r["results"][0]["reason"]
    assert not fake.methods("PATCH") and not fake.methods("POST")


def test_claim_tokens_protect_other_publishers(tmp_path):
    run_dir = _run(tmp_path)
    fid = _add(run_dir)
    key = _key(run_dir, fid)
    db = Database.open(run_dir / "harness.db")
    try:
        t1, _ = db.claim_tracking(key, "github", REPO, finding_id=fid)
        db.conn.execute("UPDATE finding_tracking SET updated_at='2000-01-01T00:00:00Z'")
        db.conn.commit()
        t2, _ = db.claim_tracking(key, "github", REPO, finding_id=fid)  # stale takeover
        assert t1 and t2 and t1 != t2
        assert not db.refresh_tracking_claim(key, "github", REPO, t1)
        db.release_tracking_claim(key, "github", REPO, t1)  # must not drop t2's claim
        row = db.get_tracking(key, "github", REPO)
        assert row["status"] == "pending" and row["claim_token"] == t2
        assert db.refresh_tracking_claim(key, "github", REPO, t2)
    finally:
        db.close()


def test_takeover_during_scan_aborts_create(tmp_path):
    run_dir = _run(tmp_path)
    fid = _add(run_dir)
    key = _key(run_dir, fid)
    fake = FakeGitHub()
    real = fake.__call__

    def stealing(method, path, body=None):
        out = real(method, path, body)
        if method == "GET" and "?" in path:
            db = Database.open(run_dir / "harness.db")
            db.conn.execute("UPDATE finding_tracking SET claim_token='other'")
            db.conn.commit()
            db.close()
        return out

    r = track_findings(run_dir, [fid], transport=stealing, cfg=CFG)
    assert "taken over" in r["results"][0]["reason"]
    assert not fake.methods("POST")
    db = Database.open(run_dir / "harness.db")
    assert db.get_tracking(key, "github", REPO)["claim_token"] == "other"
    db.close()


def test_label_change_after_preview_is_skipped(tmp_path):
    run_dir = _run(tmp_path)
    fid = _add(run_dir)
    pv = preview_track(run_dir, [fid], cfg=CFG)
    assert pv["items"][0]["issue_labels"] == ["vulnforge", "security"]
    cfg2 = {"tracking": {"sink": "github", "github": {"repo": REPO, "labels": ["p0"]}}}
    fake = FakeGitHub()
    r = publish_with_token(run_dir, pv["token"], transport=fake, cfg=cfg2)
    assert "changed since preview" in r["results"][0]["reason"]
    assert fake.calls == []
