"""Concurrent lease cap keyed by (host_id, model_id), not model id alone."""

from __future__ import annotations

import json
from pathlib import Path

from vulnforge.cli import lease_one_for_run
from vulnforge.control.exit_codes import EXIT_BUSY
from vulnforge.db import Database
from vulnforge.llm_models import lease_pair
from vulnforge.settings import apply_ui_settings_to_cfg, load_ui_settings, save_ui_settings
from vulnforge.settings.catalog import (
    cfg_lease_ceiling,
    effective_pair_cap,
    normalize_model_concurrent_caps,
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
    """Hunt is host-1/model-a. Recon is host-2/model-a. PoC is host-2/model-b."""
    return {
        "llm": {
            "model": {"host_id": "host-2", "model_id": "model-b"},
            "model_hunt": {"host_id": "host-1", "model_id": "model-a"},
            "model_recon": {"host_id": "host-2", "model_id": "model-a"},
            "model_develop_poc": {"host_id": "host-2", "model_id": "model-b"},
            "hosts": [
                {"id": "host-1", "base_url": "http://host-1/v1"},
                {"id": "host-2", "base_url": "http://host-2/v1"},
            ],
        },
        "run": {
            "max_leases_parallel": 4,
            "lease_ttl_seconds": 60,
            "model_concurrent_caps": {
                "host-1": {"model-a": 2},
                "host-2": {"model-a": 1, "model-b": 3},
            },
        },
    }


def test_flat_model_id_map_is_rejected_and_host_model_map_is_kept():
    assert normalize_model_concurrent_caps({"model-a": 2}) == {}
    assert normalize_model_concurrent_caps({"model-a": 2, "model-b": 3}) == {}
    assert normalize_model_concurrent_caps(
        {"host-1": {"model-a": 2}, "model-a": 9, "host-2": {"model-a": 1, "model-b": 3}}
    ) == {
        "host-1": {"model-a": 2},
        "host-2": {"model-a": 1, "model-b": 3},
    }
    caps = {"host-1": {"model-a": 2}, "host-2": {"model-a": 1}}
    assert effective_pair_cap(caps, "host-1", "model-a", 4) == 2
    assert effective_pair_cap(caps, "host-2", "model-a", 4) == 1
    # Same model id, no row on this host → global fallback. A flat map does not match.
    assert effective_pair_cap(caps, "host-2", "model-b", 4) == 4
    assert effective_pair_cap({"model-a": 9}, "host-1", "model-a", 4) == 4


def test_same_model_on_two_hosts_leases_independently(tmp_path: Path, toy_sqli: Path):
    db = _db(tmp_path, toy_sqli)
    cfg = _cfg()
    assert lease_pair(cfg, "hunt", {}) == ("host-1", "model-a")
    assert lease_pair(cfg, "recon", {}) == ("host-2", "model-a")
    assert lease_pair(cfg, "develop_poc", {}) == ("host-2", "model-b")

    # Two recons would share host-2/model-a (cap 1). Hunts use host-1/model-a (cap 2).
    db.enqueue_task("recon", {"agent_ids": ["default-map"]}, priority=10)
    db.enqueue_task("recon", {"agent_ids": ["default-map"]}, priority=11)
    db.enqueue_task("hunt", {"area": "a", "class": "injection"}, priority=20)
    db.enqueue_task("hunt", {"area": "b", "class": "injection"}, priority=21)
    db.enqueue_task("hunt", {"area": "c", "class": "injection"}, priority=22)

    first = lease_one_for_run(db, cfg, "w1")
    assert first is not None and first.kind == "recon"
    assert (first.lease_host_id, first.lease_model_id) == ("host-2", "model-a")
    # Second recon is the same pair and must wait. Hunt on the other host leases.
    second = lease_one_for_run(db, cfg, "w2")
    assert second is not None and second.kind == "hunt"
    assert (second.lease_host_id, second.lease_model_id) == ("host-1", "model-a")
    third = lease_one_for_run(db, cfg, "w3")
    assert third is not None and third.kind == "hunt"
    assert (third.lease_host_id, third.lease_model_id) == ("host-1", "model-a")
    # host-1/model-a is at 2 and host-2/model-a is at 1. Nothing else is queued.
    assert lease_one_for_run(db, cfg, "w4") is None
    assert db.count_leased_tasks() == 3

    db.complete_task(first.id, {"status": "succeeded"})
    nxt = lease_one_for_run(db, cfg, "w5")
    assert nxt is not None and nxt.kind == "recon"
    assert (nxt.lease_host_id, nxt.lease_model_id) == ("host-2", "model-a")
    db.close()


def test_other_pair_still_leases_when_one_host_is_full(tmp_path: Path, toy_sqli: Path):
    db = _db(tmp_path, toy_sqli)
    cfg = _cfg()
    db.enqueue_task("recon", {"agent_ids": ["default-map"]}, priority=10)
    for i in range(4):
        db.enqueue_task("develop_poc", {"finding_id": i}, priority=30 + i)
    held = lease_one_for_run(db, cfg, "w1")
    assert held is not None and held.lease_host_id == "host-2" and held.lease_model_id == "model-a"
    leased = [lease_one_for_run(db, cfg, f"w{i}") for i in range(2, 7)]
    pocs = [t for t in leased if t is not None and t.kind == "develop_poc"]
    assert len(pocs) == 3  # host-2/model-b cap is 3, global is 4
    assert all((t.lease_host_id, t.lease_model_id) == ("host-2", "model-b") for t in pocs)
    assert leased[-1] is None
    db.close()


def test_pair_without_a_number_uses_global(tmp_path: Path, toy_sqli: Path):
    db = _db(tmp_path, toy_sqli)
    cfg = _cfg()
    cfg["run"]["max_leases_parallel"] = 2
    cfg["run"]["model_concurrent_caps"] = {"host-1": {"model-a": 1}}
    cfg["llm"]["model_develop_poc"] = {"host_id": "host-1", "model_id": "model-c"}
    db.enqueue_task("hunt", {"area": "a", "class": "injection"}, priority=10)
    db.enqueue_task("hunt", {"area": "b", "class": "injection"}, priority=11)
    db.enqueue_task("develop_poc", {"finding_id": 1}, priority=20)
    db.enqueue_task("develop_poc", {"finding_id": 2}, priority=21)
    db.enqueue_task("develop_poc", {"finding_id": 3}, priority=22)
    kinds = []
    hosts = []
    for i in range(5):
        task = lease_one_for_run(db, cfg, f"w{i}")
        if task is None:
            kinds.append(None)
            continue
        kinds.append(task.kind)
        hosts.append((task.lease_host_id, task.lease_model_id))
    assert kinds.count("hunt") == 1
    assert kinds.count("develop_poc") == 2
    assert ("host-1", "model-c") in hosts
    assert kinds[-1] is None
    db.close()


def test_override_may_exceed_global(tmp_path: Path, toy_sqli: Path):
    db = _db(tmp_path, toy_sqli)
    cfg = _cfg()
    cfg["run"]["max_leases_parallel"] = 1
    cfg["run"]["model_concurrent_caps"] = {"host-2": {"model-b": 3}}
    for i in range(4):
        db.enqueue_task("develop_poc", {"finding_id": i}, priority=10 + i)
    leased = [lease_one_for_run(db, cfg, f"w{i}") for i in range(4)]
    assert sum(1 for t in leased if t is not None) == 3
    assert leased[3] is None
    db.close()


def test_run_once_busy_when_pair_cap_is_full(tmp_path: Path, toy_sqli: Path):
    from vulnforge.cli import cmd_run_once

    run = tmp_path / "runs" / "cap" / "run-001"
    run.mkdir(parents=True)
    (run / "evidence").mkdir()
    db = Database.create(run / "harness.db")
    db.insert_run("run-001", str(toy_sqli), "code_static", "pin", {})
    db.enqueue_task("hunt", {"area": "a", "class": "injection"}, priority=10)
    db.enqueue_task("hunt", {"area": "b", "class": "injection"}, priority=20)
    cfg = {
        "llm": {
            "model": {"host_id": "host-1", "model_id": "model-a"},
            "model_hunt": {"host_id": "host-1", "model_id": "model-a"},
        },
        "run": {
            "max_leases_parallel": 4,
            "lease_ttl_seconds": 60,
            "model_concurrent_caps": {"host-1": {"model-a": 1}},
            "runs_root": str(tmp_path / "runs"),
        },
    }
    held = lease_one_for_run(db, cfg, "holder")
    assert held is not None
    assert (held.lease_host_id, held.lease_model_id) == ("host-1", "model-a")
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


def test_untagged_lease_counts_against_every_pair(tmp_path: Path, toy_sqli: Path):
    db = _db(tmp_path, toy_sqli)
    cfg = _cfg()
    cfg["run"]["max_leases_parallel"] = 1
    cfg["run"]["model_concurrent_caps"] = {"host-1": {"model-a": 1}}
    db.enqueue_task("hunt", {"area": "a", "class": "injection"}, priority=10)
    held = lease_one_for_run(db, cfg, "w1")
    assert held is not None
    db.conn.execute(
        "UPDATE tasks SET lease_host_id=NULL WHERE id=?",
        (held.id,),
    )
    db.conn.commit()
    db.enqueue_task("develop_poc", {"finding_id": 1}, priority=20)
    assert lease_one_for_run(db, cfg, "w2") is None
    db.close()


def _hosts() -> list[dict]:
    return [
        {"id": "host-1", "base_url": "http://host-1/v1", "api_mode": "chat_completions", "api_key": ""},
        {"id": "host-2", "base_url": "http://host-2/v1", "api_mode": "chat_completions", "api_key": ""},
    ]


def _seed_pairs(hosts: list[dict]) -> None:
    save_ui_settings({"hosts": hosts, "max_concurrent_agents": 4})
    save_ui_settings(
        {
            "available": [
                {"host_id": "host-1", "model_id": "model-a", "verified_at": "t0"},
                {"host_id": "host-2", "model_id": "model-a", "verified_at": "t0"},
                {"host_id": "host-2", "model_id": "model-b", "verified_at": "t0"},
            ]
        }
    )


def test_settings_store_cap_on_the_row_by_host_and_model(tmp_path: Path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    hosts = _hosts()
    _seed_pairs(hosts)
    save_ui_settings(
        {
            "hosts": hosts,
            "max_concurrent_agents": 4,
            "model": {"host_id": "host-1", "model_id": "model-a"},
            "model_hunt": {"host_id": "host-1", "model_id": "model-a"},
            "model_recon": {"host_id": "host-2", "model_id": "model-a"},
            "model_develop_poc": {"host_id": "host-2", "model_id": "model-b"},
            "available": [
                {
                    "host_id": "host-1",
                    "model_id": "model-a",
                    "max_concurrent_agents": 2,
                    "max_tokens": 1000,
                    "context_tokens": 8192,
                },
                {"host_id": "host-2", "model_id": "model-a", "max_concurrent_agents": 1},
                {"host_id": "host-2", "model_id": "model-b", "max_concurrent_agents": 3},
            ],
            # Flat model-id map must not become the cap, and must not wipe the rows.
            "model_concurrent_caps": {"model-a": 9, "model-b": 9},
        }
    )
    ui = load_ui_settings()
    assert ui["model_concurrent_caps"] == {
        "host-1": {"model-a": 2},
        "host-2": {"model-a": 1, "model-b": 3},
    }
    by = {(row["host_id"], row["model_id"]): row for row in ui["available"]}
    assert by[("host-1", "model-a")]["max_concurrent_agents"] == 2
    assert by[("host-1", "model-a")]["max_tokens"] == 1000
    assert by[("host-2", "model-a")]["max_concurrent_agents"] == 1
    assert by[("host-2", "model-b")]["max_concurrent_agents"] == 3
    assert "max_tokens" not in by[("host-2", "model-a")]

    cfg = apply_ui_settings_to_cfg({"llm": {}, "run": {}, "stages": {}}, ui)
    assert cfg["run"]["max_leases_parallel"] == 4
    assert cfg["run"]["model_concurrent_caps"] == ui["model_concurrent_caps"]
    # Same pair on hunt and default counts once: 2 + 1 + 3.
    assert ui_lease_ceiling(ui) == 6
    assert cfg_lease_ceiling(cfg) == 6

    # Clearing the row restores the global fallback. No separate override section.
    save_ui_settings(
        {
            "available": [
                {"host_id": "host-1", "model_id": "model-a", "max_concurrent_agents": None},
                {"host_id": "host-2", "model_id": "model-a", "max_concurrent_agents": None},
                {"host_id": "host-2", "model_id": "model-b", "max_concurrent_agents": None},
            ]
        }
    )
    ui2 = load_ui_settings()
    assert ui2["model_concurrent_caps"] == {}
    assert all("max_concurrent_agents" not in row for row in ui2["available"])
    assert ui_lease_ceiling(ui2) == 12  # three pairs, each at the global 4


def test_settings_accept_host_model_map_and_reject_flat_map(tmp_path: Path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _seed_pairs(_hosts())
    save_ui_settings(
        {
            "model_concurrent_caps": {
                "host-1": {"model-a": 2},
                "host-2": {"model-a": 1, "model-b": 3},
            }
        }
    )
    ui = load_ui_settings()
    assert ui["model_concurrent_caps"] == {
        "host-1": {"model-a": 2},
        "host-2": {"model-a": 1, "model-b": 3},
    }
    save_ui_settings({"model_concurrent_caps": {"model-a": 9}})
    ui_flat = load_ui_settings()
    assert ui_flat["model_concurrent_caps"] == ui["model_concurrent_caps"]

    save_ui_settings({"model_concurrent_caps": {"host-2": {"model-a": None}}})
    ui_clear = load_ui_settings()
    assert ui_clear["model_concurrent_caps"] == {
        "host-1": {"model-a": 2},
        "host-2": {"model-b": 3},
    }
    by = {(row["host_id"], row["model_id"]): row for row in ui_clear["available"]}
    assert "max_concurrent_agents" not in by[("host-2", "model-a")]


def test_worker_ceiling_without_models_stays_global():
    ui = {"max_concurrent_agents": 1, "max_tasks": 50}
    assert ui_lease_ceiling(ui) == 1
    ui3 = {"max_concurrent_agents": 3}
    assert ui_lease_ceiling(ui3) == 3


def test_put_settings_round_trip(tmp_path: Path, monkeypatch):
    from fastapi.testclient import TestClient

    from vulnforge.ui.app import create_app

    _isolate(tmp_path, monkeypatch)
    _seed_pairs(_hosts())
    client = TestClient(create_app())
    res = client.put(
        "/api/settings",
        json={
            "model_concurrent_caps": {
                "host-1": {"model-a": 2},
                "host-2": {"model-a": 1, "model-b": 3},
            },
            "max_concurrent_agents": 4,
        },
    )
    assert res.status_code == 200
    body = res.json()["settings"]["model_concurrent_caps"]
    assert body == {
        "host-1": {"model-a": 2},
        "host-2": {"model-a": 1, "model-b": 3},
    }
    saved = json.loads((tmp_path / "ui_settings.json").read_text(encoding="utf-8"))
    assert saved["model_concurrent_caps"] == body
    assert list(saved["model_concurrent_caps"]) == ["host-1", "host-2"]
    rows = {(row["host_id"], row["model_id"]): row for row in saved["available"]}
    assert rows[("host-1", "model-a")]["max_concurrent_agents"] == 2
    assert rows[("host-2", "model-a")]["max_concurrent_agents"] == 1
    assert rows[("host-2", "model-b")]["max_concurrent_agents"] == 3

    rejected = client.put("/api/settings", json={"model_concurrent_caps": {"model-a": 9}})
    assert rejected.status_code == 200
    assert rejected.json()["settings"]["model_concurrent_caps"] == body
