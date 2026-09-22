"""Campaign control grammar: one verb set over Ralph + harness.db."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vulnforge.control import campaign as campaign_ctl
from vulnforge.db import Database
from vulnforge.hitl import SCHEMA_ID, emit_packet, list_inbox
from vulnforge.operator_chat.tools_common import get_status_impl, list_findings_impl
from vulnforge.ui.app import create_app
from vulnforge.ui import store


def _make_run(tmp_path: Path) -> store.RunRef:
    runs = tmp_path / "runs"
    run_dir = runs / "toy" / "run-001"
    run_dir.mkdir(parents=True)
    (run_dir / "evidence").mkdir()
    (run_dir / "project").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", str(tmp_path / "target"), "code_static", "pin", {})
    db.enqueue_task("recon", {"agent_ids": ["surface-mapper"]}, priority=5)
    db.close()
    return store.resolve_run(runs, "toy", "run-001")


def _client(ref: store.RunRef) -> TestClient:
    app = create_app(runs_root=ref.path.parents[1])
    return TestClient(app)


def _url(ref: store.RunRef, suffix: str) -> str:
    return f"/api/runs/{ref.target_id}/{ref.run_id}{suffix}"


def test_grammar_lists_seven_verbs_on_ralph():
    doc = campaign_ctl.describe_grammar()
    assert doc["schema"] == "vulnforge.campaign@1"
    assert doc["engine"] == "ralph"
    assert doc["parallel_runner"] is False
    verbs = [row["verb"] for row in doc["verbs"]]
    assert verbs == ["start", "stop", "pause", "resume", "status", "findings", "gate"]
    wires = {row["verb"]: row["wires"] for row in doc["verbs"]}
    assert wires == {
        "start": "vulnforge.ui.runner.start_run",
        "stop": "vulnforge.ui.runner.stop_run_hard",
        "pause": "vulnforge.ui.runner.pause_run",
        "resume": "vulnforge.ui.runner.resume_run",
        "status": "vulnforge.operator_chat.tools_common.get_status_impl",
        "findings": "vulnforge.operator_chat.tools_common.list_findings_impl",
        "gate": "vulnforge.hitl.list_inbox",
    }
    src = Path("vulnforge/control/campaign.py").read_text(encoding="utf-8")
    assert "subprocess" not in src
    assert "Popen" not in src


def test_docs_name_the_grammar_contract():
    grammar = campaign_ctl.describe_grammar()
    campaign_doc = Path("docs/harness/CAMPAIGN.md").read_text(encoding="utf-8")
    protocol = Path("PROTOCOL.md").read_text(encoding="utf-8")
    agents = Path("AGENTS.md").read_text(encoding="utf-8")
    assert "/api/campaign/grammar" in protocol
    assert "docs/harness/CAMPAIGN.md" in protocol
    for row in grammar["verbs"]:
        assert f"`{row['verb']}`" in protocol
        assert f"`{row['verb']}`" in agents
        assert f"`{row['verb']}`" in campaign_doc
        symbol = row["wires"].rsplit(".", 1)[-1]
        assert symbol in campaign_doc


def test_grammar_endpoint_and_bound_home(tmp_path: Path):
    ref = _make_run(tmp_path)
    with _client(ref) as client:
        static = client.get("/api/campaign/grammar")
        assert static.status_code == 200
        body = static.json()
        assert body["parallel_runner"] is False
        assert [row["verb"] for row in body["verbs"]] == list(campaign_ctl.VERBS)

        home = client.get(_url(ref, "/campaign"))
        assert home.status_code == 200
        payload = home.json()
        assert payload["verbs"] == list(campaign_ctl.VERBS)
        assert payload["status"]["verb"] == "status"
        assert payload["status"]["harness"]["has_work"] is True
        assert payload["engine"] == "ralph"


def test_pause_stop_status_use_runner_and_harness(tmp_path: Path):
    ref = _make_run(tmp_path)
    with _client(ref) as client:
        direct = get_status_impl(ref, {})
        status = client.get(_url(ref, "/campaign/status"))
        assert status.status_code == 200
        body = status.json()
        assert body["ok"] is True
        assert body["verb"] == "status"
        assert body["engine"] == "ralph"
        assert body["parallel_runner"] is False
        assert body["card"] == direct["card"]
        assert body["harness"]["db"] == "harness.db"
        assert body["harness"]["leased"] == 0
        assert body["harness"]["tasks"].get("queued", 0) >= 1
        assert body["harness"]["has_work"] is True
        assert body["runner"]["alive"] is False

        denied = client.get(_url(ref, "/campaign/pause"))
        assert denied.status_code == 405
        assert "POST" in denied.headers.get("allow", "")

        missing = client.post(_url(ref, "/campaign/launch"))
        assert missing.status_code == 404

        paused = client.post(_url(ref, "/campaign/pause"))
        assert paused.status_code == 200
        assert paused.json()["verb"] == "pause"
        assert (ref.path / "STOP").is_file()
        events = (ref.path / "events.jsonl").read_text(encoding="utf-8")
        assert "campaign_pause" in events
        assert "runner_pause" in events

        legacy = client.post(_url(ref, "/pause"))
        assert legacy.status_code == 200
        assert (ref.path / "STOP").is_file()

        stopped = client.post(_url(ref, "/campaign/stop"))
        assert stopped.status_code == 200
        assert stopped.json()["verb"] == "stop"
        events = (ref.path / "events.jsonl").read_text(encoding="utf-8")
        assert "campaign_stop" in events
        assert "runner_stop_hard" in events
        follow = client.get(_url(ref, "/campaign/status"))
        assert follow.json()["runner"]["state"] == "paused"
        assert follow.json()["runner"]["stop"] is True


def test_start_and_resume_delegate_to_ralph(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    ref = _make_run(tmp_path)
    calls: list[dict] = []

    def fake_start(path, **kwargs):
        calls.append({"path": Path(path), "kwargs": kwargs})
        return {"ok": True, "pid": 42, "status": {"state": "running", "alive": True}}

    monkeypatch.setattr("vulnforge.ui.runner.start_run", fake_start)
    monkeypatch.setattr(
        "vulnforge.ui.app.load_ui_settings",
        lambda: {"max_concurrent_agents": 4, "max_tasks": 99},
    )
    (ref.path / "STOP").write_text("paused_at=test\n", encoding="utf-8")
    with _client(ref) as client:
        resumed = client.post(
            _url(ref, "/campaign/resume"),
            json={"workers": 2, "max_tasks": 3},
        )
        assert resumed.status_code == 200
        assert resumed.json()["verb"] == "resume"
        assert not (ref.path / "STOP").is_file()
        assert len(calls) == 1
        assert calls[0]["path"] == ref.path
        assert calls[0]["kwargs"]["workers"] == 2
        assert calls[0]["kwargs"]["max_tasks"] == 3

        started = client.post(_url(ref, "/campaign/start"), json={})
        assert started.status_code == 200
        assert started.json()["verb"] == "start"
        assert calls[1]["kwargs"]["max_tasks"] is None
        assert calls[1]["kwargs"]["workers"] == 4
        events = (ref.path / "events.jsonl").read_text(encoding="utf-8")
        assert "campaign_resume" in events
        assert "campaign_start" in events


def test_start_conflict_does_not_clear_stop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    ref = _make_run(tmp_path)
    (ref.path / "STOP").write_text("hold\n", encoding="utf-8")

    def alive(_path):
        return {
            "alive": True,
            "state": "running",
            "pid": 123,
            "stop": False,
            "locked": False,
            "pids": [123],
            "workers": 1,
            "workers_alive": 1,
            "meta": {},
        }

    monkeypatch.setattr("vulnforge.ui.runner.runner_status", alive)
    with _client(ref) as client:
        resp = client.post(_url(ref, "/campaign/start"), json={})
        assert resp.status_code == 409
        assert "already running" in resp.json()["detail"]
    assert (ref.path / "STOP").is_file()


def test_unknown_loop_profile_does_not_spawn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    ref = _make_run(tmp_path)

    def explode(*_a, **_k):
        raise AssertionError("start_run should not be called")

    monkeypatch.setattr("vulnforge.ui.runner.start_run", explode)
    with _client(ref) as client:
        resp = client.post(
            _url(ref, "/campaign/start"),
            json={"loop_profile_id": "no-such-profile"},
        )
        assert resp.status_code == 400


def test_findings_match_chat_list_and_do_not_mutate(tmp_path: Path):
    ref = _make_run(tmp_path)
    db = Database.open(ref.path / "harness.db")
    sql_id = db.insert_finding(
        {
            "title": "SQL injection in search_users",
            "summary": "query string concatenated into SQL",
            "weakness_class": "injection",
            "threat_model": {"attacker": "remote"},
            "citations": [{"path": "app.py", "symbol": "search_users"}],
        },
        state="needs_human",
    )
    other_id = db.insert_finding(
        {
            "title": "reflected markup",
            "summary": "template echo",
            "weakness_class": "xss",
            "threat_model": {"attacker": "remote"},
            "citations": [{"path": "view.js", "symbol": "render"}],
        },
        state="candidate",
    )
    db.close()
    with _client(ref) as client:
        listed = client.get(
            _url(ref, "/campaign/findings"),
            params={"state": "needs_human", "class": "injection", "q": "search"},
        )
        assert listed.status_code == 200
        body = listed.json()
        direct = list_findings_impl(
            ref,
            {"state": "needs_human", "class": "injection", "q": "search", "limit": 40},
        )
        assert body["count"] == 1
        assert body["verb"] == "findings"
        assert body["findings"] == direct["findings"]
        assert body["findings"][0]["finding_id"] == sql_id

        posted = client.post(
            _url(ref, "/campaign/findings"),
            json={"class": "xss", "limit": 5},
        )
        assert posted.status_code == 200
        assert posted.json()["count"] == 1
        assert posted.json()["findings"][0]["finding_id"] == other_id

    db = Database.open(ref.path / "harness.db")
    try:
        assert db.get_finding(sql_id).state == "needs_human"
        assert db.get_finding(other_id).state == "candidate"
    finally:
        db.close()


def test_gate_reads_inbox_and_never_confirms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    ref = _make_run(tmp_path)

    def explode(*_a, **_k):
        raise AssertionError("gate must not review findings")

    monkeypatch.setattr("vulnforge.control.ops.review_finding", explode)
    db = Database.open(ref.path / "harness.db")
    fid = db.insert_finding(
        {
            "title": "SQL injection in search_users",
            "summary": "concatenated SQL",
            "weakness_class": "injection",
            "threat_model": {"attacker": "remote", "boundary": "query", "impact": "rows"},
            "citations": [{"path": "app.py", "symbol": "search_users"}],
        },
        state="needs_human",
    )
    emitted = emit_packet(
        db,
        ref.path,
        {
            "schema": SCHEMA_ID,
            "id": "gate-export",
            "title": "Export gate",
            "status": "awaiting-review",
            "blocks": [
                {
                    "type": "approval",
                    "id": "gate-export-ok",
                    "prompt": "Sign off on the export gate?",
                }
            ],
        },
    )
    assert emitted["ok"] is True
    inbox = list_inbox(db, ref.path)
    db.close()

    with _client(ref) as client:
        empty_style = client.post(_url(ref, "/campaign/gate"), json={})
        assert empty_style.status_code == 200
        body = empty_style.json()
        assert body["verb"] == "gate"
        assert body["confirms"] is False
        assert body["open"] is True
        assert body["needs_human"] == 1
        assert body["inbox"]["count"] == inbox["count"]
        ids = {item["id"] for item in body["inbox"]["items"]}
        assert "gate-export" in ids
        assert f"finding-{fid}" in ids
        assert body["findings_by_state"].get("confirmed", 0) == 0

    db = Database.open(ref.path / "harness.db")
    try:
        assert db.get_finding(fid).state == "needs_human"
    finally:
        db.close()
