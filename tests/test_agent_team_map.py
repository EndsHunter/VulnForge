"""Agent-team map: lease holders on Tasks, existing steer, not Mission lanes."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vulnforge.db import Database
from vulnforge.paths import PROJECT_ROOT
from vulnforge.ui.app import create_app

HELPERS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "agent_team_map.js"
TEST_JS = PROJECT_ROOT / "tests" / "js" / "agent_team_map.test.js"
RUN_HTML = PROJECT_ROOT / "vulnforge" / "ui" / "templates" / "run.html"
APP_JS = PROJECT_ROOT / "vulnforge" / "ui" / "static" / "app.js"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_agent_team_map_js():
    assert HELPERS.is_file(), f"missing {HELPERS}"
    assert TEST_JS.is_file(), f"missing {TEST_JS}"
    proc = subprocess.run(
        ["node", "--test", str(TEST_JS)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, (
        f"node --test failed (rc={proc.returncode})\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )


def test_run_html_puts_agent_team_on_tasks_not_mission():
    html = RUN_HTML.read_text(encoding="utf-8")
    tasks = html.split('id="panel-tasks"', 1)[1].split('id="panel-timeline"', 1)[0]
    mission = html.split('data-mode-panel="mission"', 1)[1].split(
        'data-mode-panel="explorer"', 1
    )[0]
    assert 'id="agent-team"' in tasks
    assert 'id="agent-team-body"' in tasks
    assert 'id="agent-team-enqueue"' in tasks
    assert 'id="agent-team-enqueue-btn"' in tasks
    assert 'data-confirm="1"' in tasks
    assert "hunts/from-selection" not in tasks  # enqueue stays a client call to the existing route
    assert 'id="agent-team"' not in mission
    assert "arch-campaign" not in tasks
    assert 'id="btn-start"' in html
    assert 'id="btn-pause"' in html
    assert html.index("agent_team_map.js") < html.index("/static/app.js")
    # Mission lanes stay on the architecture strip; Ralph stays on the run bar.
    assert 'class="arch-campaign-lanes"' not in tasks
    assert 'id="btn-start"' not in tasks


def test_app_js_reuses_existing_steer():
    js = APP_JS.read_text(encoding="utf-8")
    assert "function renderAgentTeam(" in js
    assert "function submitAgentTeamEnqueue(" in js
    assert "function sendAgentTeamNote(" in js
    assert "/hunts/from-selection" in js
    assert "/steer/note" in js
    assert "pauseTask(id)" in js
    assert "haltTask(id)" in js
    assert "resumePausedTask(id)" in js
    assert "openLiveTask(id)" in js
    assert "Enqueue a ${cls} hunt" in js
    assert "does not confirm a finding" in js
    assert "Send this note into task" in js
    assert "renderAgentTeam(snap)" in js


def test_snapshot_exposes_max_leases_parallel(tmp_path: Path):
    run = tmp_path / "runs" / "toy" / "run-001"
    run.mkdir(parents=True)
    (run / "evidence").mkdir()
    db = Database.create(run / "harness.db")
    db.insert_run(
        "run-001",
        str(tmp_path),
        "code_static",
        "pin",
        {"run": {"profile": "code_static", "max_leases_parallel": 2, "max_tasks": 50}},
    )
    db.enqueue_task("hunt", {"area": "api", "class": "injection"}, priority=40)
    db.conn.execute(
        """
        UPDATE tasks
        SET state='leased', lease_owner='vf-4242-a1b2c3d4',
            lease_until='2099-01-01T00:00:00Z', attempt=1
        WHERE id=1
        """
    )
    db.conn.commit()
    db.close()

    app = create_app(runs_root=tmp_path / "runs")
    client = TestClient(app)
    res = client.get("/api/runs/toy/run-001")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["run"]["max_leases_parallel"] == 2
    leased = [t for t in body["tasks"] if t["state"] == "leased"]
    assert leased and leased[0]["lease_owner"] == "vf-4242-a1b2c3d4"
