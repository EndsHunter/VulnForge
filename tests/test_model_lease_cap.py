"""Per-model concurrent lease cap. The key is model id, not host + model."""

from __future__ import annotations

import json
from pathlib import Path

from vulnforge.cli import lease_one_for_run
from vulnforge.control.exit_codes import EXIT_BUSY
from vulnforge.db import Database
from vulnforge.llm_models import lease_model_id
from vulnforge.settings import apply_ui_settings_to_cfg, load_ui_settings, save_ui_settings
from vulnforge.settings.catalog import (
    cfg_lease_ceiling,
    effective_model_cap,
    ui_lease_ceiling,
)
from vulnforge.util import build_target_manifest, write_json


def _isolate(tmp_path: Path, monkeypatch) -> None:
    p = tmp_path / "ui_settings.json"
    monkeypatch.setattr("vulnforge.settings.ui.UI_SETTINGS_PATH", p)
    monkeypatch.setattr("vulnforge.settings.UI_SETTINGS_PATH", p)


def _db(tmp_path: Path, toy_sqli: Path) -> Database:
    run = tmp_path / "run-001"
    run.mkdir()
    (run / "evidence").mkdir()
    write_json(run / "target_manifest.json", build_target_manifest(toy_sqli, []))
    db = Database.create(run / "harness.db")
    db.insert_run("run-001", str(toy_sqli), "code_static", "pin", {})
    return db


def _cfg() -> dict:
    """Hunt uses alpha. Recon uses beta. Same ids can be served by two hosts."""
    return {
        "llm": {
            "model": "beta",
            "model_hunt": {"host_id": "large", "model_id": "alpha"},
            "model_recon": {"host_id": "small", "model_id": "alpha"},
            "model_develop_poc": {"host_id": "small", "model_id": "beta"},
            "hosts": [
                {"id": "small", "base_url": "http://small/v1"},
                {"id": "large", "base_url": "http://large/v1"},
            ],
        },
        "run": {
            "max_leases_parallel": 2,
            "lease_ttl_seconds": 60,
            "model_concurrent_caps": {"alpha": 1},
        },
    }


def test_effective_cap_ignores_host_and_falls_back():
    caps = {"alpha": 1}
    assert effective_model_cap(caps, "alpha", 4) == 1
    assert effective_model_cap(caps, "beta", 4) == 4
    # A host-shaped nest is not a cap for that model.
    assert effective_model_cap({"small": {"alpha": 9}}, "alpha", 2) == 2


def test_override_caps_leasing_and_missing_override_uses_global(tmp_path: Path, toy_sqli: Path):
    db = _db(tmp_path, toy_sqli)
    cfg = _cfg()
    # alpha override 1, beta has no override so the global cap (2) applies.
    db.enqueue_task("hunt", {"area": "a", "class": "injection"}, priority=10)
    db.enqueue_task("hunt", {"area": "b", "class": "injection"}, priority=20)
    db.enqueue_task("develop_poc", {"finding_id": 1}, priority=30)
    db.enqueue_task("develop_poc", {"finding_id": 2}, priority=40)
    db.enqueue_task("develop_poc", {"finding_id": 3}, priority=50)

    first = lease_one_for_run(db, cfg, "w1")
    assert first is not None and first.kind == "hunt"
    assert first.lease_model_id == "alpha"
    # Next hunt is the same model id (other host in the role map) and must wait.
    # develop_poc is beta, under the global cap, so it leases instead.
    second = lease_one_for_run(db, cfg, "w2")
    assert second is not None and second.kind == "develop_poc"
    assert second.lease_model_id == "beta"
    third = lease_one_for_run(db, cfg, "w3")
    assert third is not None and third.lease_model_id == "beta"
    fourth = lease_one_for_run(db, cfg, "w4")
    assert fourth is None  # beta global cap is 2; alpha still held at 1
    assert db.count_leased_tasks() == 3

    db.complete_task(first.id, {"status": "succeeded"})
    nxt = lease_one_for_run(db, cfg, "w5")
    assert nxt is not None and nxt.kind == "hunt" and nxt.lease_model_id == "alpha"
    db.close()


def test_same_model_id_on_two_hosts_is_one_cap(tmp_path: Path, toy_sqli: Path):
    """Recon (host small) and hunt (host large) both resolve to alpha."""
    db = _db(tmp_path, toy_sqli)
    cfg = _cfg()
    assert lease_model_id(cfg, "recon", {"host_id": "small"}) == "alpha"
    assert lease_model_id(cfg, "hunt", {"host_id": "large"}) == "alpha"
    assert lease_model_id(cfg, "recon", {}) == lease_model_id(cfg, "hunt", {})

    db.enqueue_task("recon", {"agent_ids": ["default-map"]}, priority=10)
    db.enqueue_task("hunt", {"area": "a", "class": "injection"}, priority=20)
    a = lease_one_for_run(db, cfg, "w1")
    b = lease_one_for_run(db, cfg, "w2")
    assert a is not None and a.lease_model_id == "alpha"
    assert b is None
    db.close()


def test_override_may_exceed_global(tmp_path: Path, toy_sqli: Path):
    db = _db(tmp_path, toy_sqli)
    cfg = _cfg()
    cfg["run"]["max_leases_parallel"] = 1
    cfg["run"]["model_concurrent_caps"] = {"alpha": 3}
    cfg["llm"]["model_hunt"] = "alpha"
    cfg["llm"]["model"] = "beta"
    for i in range(4):
        db.enqueue_task("hunt", {"area": f"a{i}", "class": "injection"}, priority=10 + i)
    db.enqueue_task("develop_poc", {"finding_id": 1}, priority=50)
    db.enqueue_task("develop_poc", {"finding_id": 2}, priority=60)
    leased = [lease_one_for_run(db, cfg, f"w{i}") for i in range(6)]
    kinds = [t.kind for t in leased if t is not None]
    assert kinds.count("hunt") == 3
    assert kinds.count("develop_poc") == 1  # beta has no override; global is 1
    assert leased[4] is None or leased[5] is None
    assert db.count_leased_tasks() == 4
    db.close()


def test_run_once_busy_when_model_cap_is_full(tmp_path: Path, toy_sqli: Path):
    from vulnforge.cli import cmd_run_once

    run = tmp_path / "runs" / "cap" / "run-001"
    run.mkdir(parents=True)
    (run / "evidence").mkdir()
    db = Database.create(run / "harness.db")
    db.insert_run("run-001", str(toy_sqli), "code_static", "pin", {})
    db.enqueue_task("hunt", {"area": "a", "class": "injection"}, priority=10)
    db.enqueue_task("hunt", {"area": "b", "class": "injection"}, priority=20)
    cfg = {
        "llm": {"model": "alpha", "model_hunt": "alpha"},
        "run": {
            "max_leases_parallel": 4,
            "lease_ttl_seconds": 60,
            "model_concurrent_caps": {"alpha": 1},
            "runs_root": str(tmp_path / "runs"),
        },
    }
    held = lease_one_for_run(db, cfg, "holder")
    assert held is not None and held.lease_model_id == "alpha"
    db.close()
    write_json(run / "target_manifest.json", {"files": {}})

    class Args:
        run_dir = run
        config = None

    code = cmd_run_once(Args(), cfg)
    assert code == EXIT_BUSY
    db = Database.open(run / "harness.db")
    states = {t.id: t.state for t in db.list_tasks()}
    assert states[held.id] == "leased"
    queued = [t for t in db.list_tasks() if t.state == "queued"]
    assert len(queued) == 1
    db.close()


def test_settings_store_cap_by_model_id_not_host(tmp_path: Path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    hosts = [
        {"id": "small", "base_url": "http://small/v1", "api_mode": "chat_completions", "api_key": ""},
        {"id": "large", "base_url": "http://large/v1", "api_mode": "chat_completions", "api_key": ""},
    ]
    save_ui_settings({"hosts": hosts, "max_concurrent_agents": 2})
    save_ui_settings(
        {
            "available": [
                {"host_id": "small", "model_id": "alpha", "verified_at": "t0"},
                {"host_id": "large", "model_id": "alpha", "verified_at": "t0"},
                {"host_id": "large", "model_id": "beta", "verified_at": "t0"},
            ]
        }
    )
    save_ui_settings(
        {
            "hosts": hosts,
            "max_concurrent_agents": 2,
            "model": {"host_id": "small", "model_id": "alpha"},
            "model_hunt": {"host_id": "large", "model_id": "alpha"},
            "model_recon": {"host_id": "large", "model_id": "beta"},
            # A pair-shaped knob must not become the cap key.
            "available": [
                {
                    "host_id": "small",
                    "model_id": "alpha",
                    "max_concurrent_agents": 9,
                    "max_tokens": 1000,
                },
                {"host_id": "large", "model_id": "alpha", "max_concurrent_agents": 1},
                {"host_id": "large", "model_id": "beta"},
            ],
            "model_concurrent_caps": {
                "alpha": 4,
                "beta": None,
                "small": {"alpha": 9},
            },
        }
    )
    ui = load_ui_settings()
    assert ui["model_concurrent_caps"] == {"alpha": 4}
    assert "small" not in ui["model_concurrent_caps"]
    for row in ui["available"]:
        assert "max_concurrent_agents" not in row
        assert "model_concurrent_caps" not in row
    by = {(row["host_id"], row["model_id"]): row for row in ui["available"]}
    assert by[("small", "alpha")]["max_tokens"] == 1000
    assert "max_tokens" not in by[("large", "alpha")]

    cfg = apply_ui_settings_to_cfg({"llm": {}, "run": {}, "stages": {}}, ui)
    assert cfg["run"]["max_leases_parallel"] == 2
    assert cfg["run"]["model_concurrent_caps"] == {"alpha": 4}
    # Two role refs, one model id: the ceiling counts alpha once (4) and beta once (global 2).
    assert ui_lease_ceiling(ui) == 6
    assert cfg_lease_ceiling(cfg) == 6

    # Clearing the override restores the global fallback.
    save_ui_settings({"model_concurrent_caps": {"alpha": None, "beta": None}})
    ui2 = load_ui_settings()
    assert ui2["model_concurrent_caps"] == {}
    assert ui_lease_ceiling(ui2) == 4  # alpha + beta, each at the global 2


def test_worker_ceiling_without_models_stays_global():
    ui = {"max_concurrent_agents": 1, "max_tasks": 50}
    assert ui_lease_ceiling(ui) == 1
    ui3 = {"max_concurrent_agents": 3}
    assert ui_lease_ceiling(ui3) == 3


def test_put_settings_round_trip(tmp_path: Path, monkeypatch):
    from fastapi.testclient import TestClient

    from vulnforge.ui.app import create_app

    _isolate(tmp_path, monkeypatch)
    save_ui_settings(
        {
            "hosts": [
                {"id": "small", "base_url": "http://small/v1", "api_mode": "chat_completions", "api_key": ""},
            ],
            "max_concurrent_agents": 2,
        }
    )
    save_ui_settings(
        {
            "available": [{"host_id": "small", "model_id": "alpha", "verified_at": "t0"}],
            "model": {"host_id": "small", "model_id": "alpha"},
        }
    )
    client = TestClient(create_app())
    res = client.put(
        "/api/settings",
        json={
            "model_concurrent_caps": {"alpha": 3},
            "max_concurrent_agents": 2,
        },
    )
    assert res.status_code == 200
    body = res.json()["settings"]["model_concurrent_caps"]
    assert body == {"alpha": 3}
    saved = json.loads((tmp_path / "ui_settings.json").read_text(encoding="utf-8"))
    assert saved["model_concurrent_caps"] == {"alpha": 3}
    assert list(saved["model_concurrent_caps"]) == ["alpha"]
