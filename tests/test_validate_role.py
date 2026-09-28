"""Dedicated validate / PoC referee role (issue #128).

Blank role follows hunt. A non-empty validate_models list is the full slot set.
"""

from __future__ import annotations

import json
from pathlib import Path

from vulnforge.cli import cmd_init, cmd_status
from vulnforge.control.exit_codes import EXIT_CONFIG, EXIT_PROGRESS
from vulnforge.db import Database
from vulnforge.llm_models import (
    lease_pair,
    resolve_stage_model,
    resolve_validate_models,
    resolve_validate_targets,
    status_model_summary,
    validate_same_as_hunt,
)
from vulnforge.settings import apply_ui_settings_to_cfg, load_ui_settings, save_ui_settings
from vulnforge.settings.load import load_config


def _isolate(tmp_path: Path, monkeypatch) -> None:
    p = tmp_path / "ui_settings.json"
    monkeypatch.setattr("vulnforge.settings.ui.UI_SETTINGS_PATH", p)
    monkeypatch.setattr("vulnforge.settings.UI_SETTINGS_PATH", p)


def test_blank_validate_role_follows_hunt_then_default():
    hunt_set = {
        "llm": {
            "model": "default-m",
            "model_hunt": "hunt-m",
            "model_validate": "",
            "validate_models": [],
        }
    }
    assert resolve_validate_models(hunt_set) == ["hunt-m"]
    assert resolve_stage_model(hunt_set, "validate_llm") == "hunt-m"
    assert resolve_stage_model(hunt_set, "poc_referee") == "hunt-m"
    assert validate_same_as_hunt(hunt_set) is True
    assert status_model_summary(hunt_set) == "hunt=hunt-m validate=hunt-m"

    both_blank = {"llm": {"model": "only", "model_hunt": "", "model_validate": None}}
    assert resolve_validate_models(both_blank) == ["only"]
    assert validate_same_as_hunt(both_blank) is True


def test_explicit_validate_role_splits_from_hunt_and_list_wins():
    split = {
        "llm": {
            "model": "default-m",
            "model_hunt": {"host_id": "lab", "model_id": "hunt-m"},
            "model_validate": {"host_id": "other", "model_id": "referee-m"},
            "validate_models": [],
        }
    }
    assert resolve_validate_targets(split) == [
        {"host_id": "other", "model_id": "referee-m"}
    ]
    assert lease_pair(split, "validate_llm") == ("other", "referee-m")
    assert lease_pair(split, "poc_referee") == ("other", "referee-m")
    assert lease_pair(split, "hunt") == ("lab", "hunt-m")
    assert validate_same_as_hunt(split) is False
    assert status_model_summary(split) == "hunt=lab/hunt-m validate=other/referee-m"

    listed = {
        "llm": {
            "model": "default-m",
            "model_hunt": "hunt-m",
            "model_validate": "referee-m",
            "validate_models": [
                {"host_id": "lab", "model_id": "v1"},
                {"host_id": "lab", "model_id": "v2"},
            ],
        }
    }
    assert resolve_validate_targets(listed) == [
        {"host_id": "lab", "model_id": "v1"},
        {"host_id": "lab", "model_id": "v2"},
    ]
    assert resolve_validate_models(listed) == ["v1", "v2"]
    assert "referee-m" not in resolve_validate_models(listed)


def test_settings_roundtrip_dedicated_validate_role(tmp_path: Path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    lab = {
        "id": "lab",
        "base_url": "http://127.0.0.1:9/v1",
        "api_mode": "chat_completions",
        "api_key": "",
    }
    save_ui_settings({"hosts": [lab]})
    save_ui_settings(
        {
            "available": [
                {"host_id": "lab", "model_id": "hunter", "verified_at": "t"},
                {"host_id": "lab", "model_id": "referee", "verified_at": "t"},
            ]
        }
    )
    save_ui_settings(
        {
            "hosts": [lab],
            "model": {"host_id": "lab", "model_id": "hunter"},
            "model_hunt": {"host_id": "lab", "model_id": "hunter"},
            "model_validate": {"host_id": "lab", "model_id": "referee"},
        }
    )
    ui = load_ui_settings()
    assert ui["model_validate"] == {"host_id": "lab", "model_id": "referee"}
    cfg = apply_ui_settings_to_cfg({"llm": {"model": "yaml-default"}, "stages": {}, "run": {}}, ui)
    assert resolve_validate_targets(cfg) == [{"host_id": "lab", "model_id": "referee"}]
    assert validate_same_as_hunt(cfg) is False

    save_ui_settings({"model_validate": None, "validate_models": []})
    cleared = apply_ui_settings_to_cfg(
        {"llm": {"model": "yaml-default"}, "stages": {}, "run": {}}, load_ui_settings()
    )
    assert resolve_validate_models(cleared) == ["hunter"]

    save_ui_settings(
        {
            "validate_models": [
                {"host_id": "lab", "model_id": "hunter"},
                {"host_id": "lab", "model_id": "referee"},
            ]
        }
    )
    listed = apply_ui_settings_to_cfg(
        {"llm": {}, "stages": {}, "run": {}}, load_ui_settings()
    )
    assert resolve_validate_models(listed) == ["hunter", "referee"]


def test_settings_api_shows_which_model_validates(tmp_path: Path, monkeypatch):
    from fastapi.testclient import TestClient

    from vulnforge.ui.app import create_app

    _isolate(tmp_path, monkeypatch)
    app = create_app(runs_root=tmp_path / "runs")
    with TestClient(app) as client:
        page = client.get("/settings")
        assert page.status_code == 200
        assert 'id="set-model-validate"' in page.text
        assert "(same as hunt)" in page.text
        lab = {
            "id": "lab",
            "base_url": "http://127.0.0.1:9/v1",
            "api_mode": "chat_completions",
            "api_key": "",
        }
        hosts = client.put("/api/settings", json={"hosts": [lab]})
        assert hosts.status_code == 200
        listed = client.put(
            "/api/settings",
            json={
                "available": [
                    {"host_id": "lab", "model_id": "hunter", "verified_at": "t"},
                    {"host_id": "lab", "model_id": "referee", "verified_at": "t"},
                ]
            },
        )
        assert listed.status_code == 200
        put = client.put(
            "/api/settings",
            json={
                "hosts": [lab],
                "model": {"host_id": "lab", "model_id": "hunter"},
                "model_hunt": {"host_id": "lab", "model_id": "hunter"},
                "model_validate": {"host_id": "lab", "model_id": "referee"},
                "validate_models": [],
            },
        )
        assert put.status_code == 200
        body = client.get("/api/settings").json()
        assert body["settings"]["model_validate"]["model_id"] == "referee"
        assert body["effective"]["validate_targets"] == [
            {"host_id": "lab", "model_id": "referee"}
        ]
        assert body["effective"]["validate_models"] == ["referee"]
        assert body["effective"]["hunt_model"] == {"host_id": "lab", "model_id": "hunter"}
        assert "confirmed" not in json.dumps(body["effective"].get("validate_targets"))


def test_status_names_validate_and_hunt(tmp_path: Path, capsys):
    run = tmp_path / "run-001"
    run.mkdir()
    db = Database.create(run / "harness.db")
    db.insert_run("run-001", str(tmp_path), "code_static", "pin", {})
    db.close()

    class Args:
        run_dir = run

    split = {
        "llm": {
            "model": "default-m",
            "model_hunt": "hunt-m",
            "model_validate": "referee-m",
        },
        "stages": {"validate_llm": True},
    }
    assert cmd_status(Args(), split) == EXIT_PROGRESS
    first = capsys.readouterr()
    assert "models:  hunt=hunt-m validate=referee-m" in first.out
    assert "never auto-confirm" in first.err
    assert "weak signal" not in first.err

    same = {
        "llm": {"model": "hunt-m", "model_hunt": "hunt-m", "model_validate": ""},
        "stages": {"validate_llm": True},
    }
    assert cmd_status(Args(), same) == EXIT_PROGRESS
    second = capsys.readouterr()
    assert "hunt=hunt-m validate=hunt-m" in second.out
    assert "validate matches hunt (weak signal)" in second.err
    assert "never auto-confirm" in second.err


def test_init_flag_sets_validate_role(tmp_path: Path, monkeypatch, toy_sqli: Path):
    _isolate(tmp_path, monkeypatch)
    runs = tmp_path / "runs"

    class Args:
        target = toy_sqli
        profile = None
        runs_root = runs
        strategy = "discovery"
        docs_path = None
        agent_ids = None
        operator_notes = ""
        dynamic_skills = False
        dynamic_skill_count = 3
        hunt_skill_mode = "all_active"
        hunt_skill_ids = None
        sandbox_poc_validate = False
        enqueue_hunts = False
        model_validate = "referee-x"
        job_id = None

    args = Args()
    args.progress = lambda _evt: None
    cfg = load_config()
    assert cmd_init(args, cfg) == EXIT_PROGRESS
    ui = load_ui_settings()
    assert ui["model_validate"] == "referee-x"
    run_dirs = list(runs.glob("*/*"))
    assert len(run_dirs) == 1
    db = Database.open(run_dirs[0] / "harness.db")
    stored = json.loads(db.get_run()["config_json"])
    db.close()
    assert stored["llm"]["model_validate"] == "referee-x"
    assert resolve_validate_models(stored) == ["referee-x"]

    # Hosts saved: a bare id must not bind across hosts, and must not create a run.
    save_ui_settings(
        {
            "hosts": [
                {
                    "id": "lab",
                    "base_url": "http://127.0.0.1:9/v1",
                    "api_mode": "chat_completions",
                    "api_key": "",
                }
            ],
            "model": None,
            "model_validate": None,
        }
    )
    save_ui_settings(
        {
            "available": [
                {"host_id": "lab", "model_id": "referee", "verified_at": "t"},
            ],
            "model": {"host_id": "lab", "model_id": "referee"},
        }
    )
    before = list(runs.glob("*/*"))

    bare = Args()
    bare.progress = lambda _evt: None
    bare.model_validate = "bare-id"
    code = cmd_init(bare, load_config())
    assert code == EXIT_CONFIG
    assert list(runs.glob("*/*")) == before

    good = Args()
    good.progress = lambda _evt: None
    good.model_validate = "lab/referee"
    assert cmd_init(good, load_config()) == EXIT_PROGRESS
    assert load_ui_settings()["model_validate"] == {"host_id": "lab", "model_id": "referee"}
