"""Iterate-in-sandbox: host refuse, ladder, caps, settings, no auto-confirm."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from vulnforge.db import Database
from vulnforge.poc_runner import (
    build_session_docker_argv,
    build_session_exec_argv,
    harness_config,
)
from vulnforge.poc_session import (
    DockerGuestDriver,
    append_steer,
    apply_pack_rewrite,
    request_stop,
    run_iterate_session,
)
from vulnforge.settings.ui import apply_ui_settings_to_cfg, load_ui_settings, save_ui_settings
from vulnforge.stages import iterate_poc
from vulnforge.util import build_target_manifest, write_json

HUB = "---\nrun: python poc.py\nsuccess_regex: ASSERT_OK\n---\n\n## Expected signal\nok\n"


def _probe(**overrides):
    base = {
        "docker": True,
        "runtimes": {},
        "kvm": True,
        "firecracker_path": "/usr/bin/firecracker",
        "firecracker_version": (1, 15, 1),
        "firecracker_patched": True,
        "jailer_path": "/usr/bin/jailer",
        "jailer_version": (1, 15, 1),
        "jailer_patched": True,
    }
    base.update(overrides)
    return base


def _pack(tmp_path: Path) -> Path:
    pack = tmp_path / "pack"
    pack.mkdir(parents=True)
    (pack / "poc.py").write_text("print('NO')\n", encoding="utf-8")
    (pack / "poc_develop.md").write_text(HUB, encoding="utf-8")
    return pack


class Clock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t


class RecordingDriver:
    def __init__(self, results: list[dict] | None = None) -> None:
        self.results = list(results or [])
        self.started: list[dict] = []
        self.execs: list[tuple] = []
        self.stopped: list[str] = []
        self.seen: list[str] = []

    def start(self, spec: dict) -> dict:
        self.started.append(spec)
        return {
            "guest_id": spec["guest_id"],
            "hold_mode": "container",
            "guest_sees_workspace": True,
        }

    def sync(self, guest_id: str, workspace: Path) -> None:
        poc = workspace / "poc.py"
        self.seen.append(poc.read_text(encoding="utf-8") if poc.is_file() else "")

    def exec(self, guest_id: str, command: str, timeout_s: int, env) -> dict:
        self.execs.append((guest_id, command, timeout_s))
        if self.results:
            item = dict(self.results.pop(0))
        else:
            item = {
                "exit_code": 1,
                "timed_out": False,
                "spawn_error": None,
                "stdout": "no\n",
                "stderr": "",
                "duration_ms": 2,
                "ran": True,
            }
        item.setdefault("argv", ["docker", "exec", guest_id])
        item.setdefault("ran", True)
        return item

    def stop(self, guest_id: str) -> None:
        self.stopped.append(guest_id)


def _absent(n: int = 1) -> list[dict]:
    return [
        {
            "exit_code": 1,
            "timed_out": False,
            "spawn_error": None,
            "stdout": "no\n",
            "stderr": "",
            "duration_ms": 1,
            "ran": True,
        }
        for _ in range(n)
    ]


def _signal() -> dict:
    return {
        "exit_code": 0,
        "timed_out": False,
        "spawn_error": None,
        "stdout": "ASSERT_OK\n",
        "stderr": "",
        "duration_ms": 3,
        "ran": True,
    }


def test_default_caps_are_five_and_fifteen():
    hc = harness_config(None)
    assert hc["iterate_max_cycles"] == 5
    assert hc["iterate_wall_ttl_min"] == 15
    hc2 = harness_config(
        {"poc_harness": {"iterate_max_cycles": 0, "iterate_wall_ttl_min": 999}}
    )
    assert hc2["iterate_max_cycles"] == 1
    assert hc2["iterate_wall_ttl_min"] == 240


def test_host_and_runc_do_not_start_a_session(tmp_path: Path):
    pack = _pack(tmp_path)
    probe = _probe(runtimes={"runsc": {}})
    for runner in ("local_subprocess", "runc", "local"):
        driver = RecordingDriver(_absent(3))
        session = run_iterate_session(
            pack,
            cfg={"poc_harness": {"runner": runner, "network": "none"}},
            hub_text=HUB,
            finding_id=1,
            probe=probe,
            driver=driver,
        )
        assert session["state"] == "ended", runner
        assert session["end_reason"] == "unsafe_skipped", runner
        assert session["verdict"] == "unsafe_skipped"
        assert session["cycles"] == []
        assert driver.started == []
        assert driver.execs == []
        assert session["host_exec"] is False
        assert session["confirms_finding"] is False


def test_ladder_pins_microvm_then_gvisor_and_refuses_plain_runc(tmp_path: Path):
    pack = _pack(tmp_path)
    driver = RecordingDriver(_absent(1))
    both = _probe(runtimes={"kata-qemu": {}, "runsc": {}, "runc": {}})
    session = run_iterate_session(
        pack,
        cfg={"poc_harness": {"runner": "sandbox", "iterate_max_cycles": 1}},
        hub_text=HUB,
        probe=both,
        driver=driver,
    )
    assert session["isolation"] == "microvm"
    assert session["runtime"] == "kata-qemu"
    assert session["end_reason"] == "cycle_cap"
    assert {c["runtime"] for c in session["cycles"]} == {"kata-qemu"}
    assert {c["guest_id"] for c in session["cycles"]} == {session["guest_id"]}
    assert session["guest_id"].startswith("vf-poc-sess-")

    gvisor = RecordingDriver(_absent(1))
    session = run_iterate_session(
        _pack(tmp_path / "gv"),
        cfg={"poc_harness": {"runner": "sandbox", "iterate_max_cycles": 1}},
        hub_text=HUB,
        probe=_probe(runtimes={"runc": {}, "runsc": {}}, kvm=False, firecracker_patched=False),
        driver=gvisor,
    )
    assert session["isolation"] == "gvisor"
    assert session["runtime"] == "runsc"

    refused = RecordingDriver(_absent(1))
    session = run_iterate_session(
        _pack(tmp_path / "no"),
        cfg={"poc_harness": {"runner": "sandbox"}},
        hub_text=HUB,
        probe=_probe(runtimes={"runc": {}}, kvm=False, firecracker_patched=False, jailer_patched=False),
        driver=refused,
    )
    assert session["verdict"] == "sandbox_unavailable"
    assert session["end_reason"] == "sandbox_unavailable"
    assert refused.started == []
    assert session["cycles"] == []


def test_cycle_cap_and_wall_ttl_end_without_confirming(tmp_path: Path):
    pack = _pack(tmp_path)
    driver = RecordingDriver(_absent(8))
    session = run_iterate_session(
        pack,
        cfg={"poc_harness": {"runner": "sandbox", "iterate_max_cycles": 5, "network": "none"}},
        hub_text=HUB,
        probe=_probe(runtimes={"runsc": {}}),
        driver=driver,
    )
    assert len(session["cycles"]) == 5
    assert session["end_reason"] == "cycle_cap"
    assert session["verdict"] != "signal_observed"
    assert session["confirms_finding"] is False
    assert session["clears_needs_human"] is False
    assert driver.stopped == [session["guest_id"]]
    assert len({gid for gid, _cmd, _t in driver.execs}) == 1

    clock = Clock()
    ttl_driver = RecordingDriver(_absent(4))

    def exec_and_advance(guest_id, command, timeout_s, env):
        clock.t += 120
        return RecordingDriver.exec(ttl_driver, guest_id, command, timeout_s, env)

    ttl_driver.exec = exec_and_advance  # type: ignore[method-assign]
    session = run_iterate_session(
        _pack(tmp_path / "ttl"),
        cfg={"poc_harness": {"runner": "gvisor", "iterate_wall_ttl_min": 1, "iterate_max_cycles": 5}},
        hub_text=HUB,
        probe=_probe(runtimes={"runsc": {}}),
        driver=ttl_driver,
        now_fn=clock,
    )
    assert len(session["cycles"]) == 1
    assert session["end_reason"] == "wall_ttl"
    assert session["confirms_finding"] is False


def test_rewrite_stays_in_guest_workspace_and_steer_is_visible(tmp_path: Path):
    pack = _pack(tmp_path)
    driver = RecordingDriver(_absent(2))

    def rewriter(ctx):
        assert ctx["guest_id"].startswith("vf-poc-sess-")
        texts = [s["text"] for s in ctx["steers"]]
        assert "try the quote" in texts
        return {"files": {"poc.py": "print('ASSERT_OK')\n"}, "note": "steer applied"}

    append_steer(pack, "try the quote", operator="ada")
    session = run_iterate_session(
        pack,
        cfg={"poc_harness": {"runner": "gvisor", "iterate_max_cycles": 1}},
        hub_text=HUB,
        probe=_probe(runtimes={"runsc": {}}),
        driver=driver,
        rewriter=rewriter,
    )
    assert session["cycles"][0]["rewrite_files"] == ["poc.py"]
    assert session["cycles"][0]["steer_seqs"] == [1]
    assert driver.seen[0] == "print('ASSERT_OK')\n"
    assert (pack / "poc.py").read_text(encoding="utf-8") == "print('ASSERT_OK')\n"
    assert session["end_reason"] == "cycle_cap"


def test_operator_stop_ends_session(tmp_path: Path):
    pack = _pack(tmp_path)
    driver = RecordingDriver(_absent(3))

    def exec_stop(guest_id, command, timeout_s, env):
        request_stop(pack, operator="ada")
        return RecordingDriver.exec(driver, guest_id, command, timeout_s, env)

    driver.exec = exec_stop  # type: ignore[method-assign]
    session = run_iterate_session(
        pack,
        cfg={"poc_harness": {"runner": "gvisor", "iterate_max_cycles": 5}},
        hub_text=HUB,
        probe=_probe(runtimes={"runsc": {}}),
        driver=driver,
    )
    assert len(session["cycles"]) == 1
    assert session["end_reason"] == "operator_stop"
    assert session["confirms_finding"] is False
    assert driver.stopped


def test_rewrite_path_traversal_refused(tmp_path: Path):
    pack = _pack(tmp_path)
    try:
        apply_pack_rewrite(pack, {"../poc.py": "print(1)\n"})
        raised = False
    except ValueError:
        raised = True
    assert raised
    assert not (tmp_path / "poc.py").exists()


def test_docker_session_argv_is_runtime_pinned_and_runc_refused(tmp_path: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    calls: list[list[str]] = []

    def spawn(argv, timeout_s):
        calls.append(list(argv))
        return {
            "exit_code": 0,
            "timed_out": False,
            "spawn_error": None,
            "stdout": "cid\n",
            "stderr": "",
            "duration_ms": 1,
            "argv": argv,
        }

    monkeypatch.setattr(pr, "spawn_captured", spawn)
    monkeypatch.setattr("vulnforge.poc_session.spawn_captured", spawn)
    monkeypatch.setattr(pr, "run_cleanup", lambda argv: None)
    monkeypatch.setattr("vulnforge.poc_session.run_cleanup", lambda argv: None)
    work = tmp_path / "work"
    work.mkdir()
    argv = build_session_docker_argv(
        name="vf-poc-sess-abc",
        workspace=work,
        image="python:3.12.8-slim-bookworm",
        runtime="runsc",
        network="none",
        cpus="1",
        memory="512m",
        pids_limit=64,
        sleep_s=90,
    )
    assert argv[0] == "docker"
    assert "runsc" in argv
    assert "runc" not in argv
    assert "--privileged" not in " ".join(argv)
    assert "sleep" in argv
    assert "python poc.py" not in " ".join(argv)
    exec_argv = build_session_exec_argv(name="vf-poc-sess-abc", command="python poc.py")
    assert exec_argv[:3] == ["docker", "exec", "-w"]
    assert "python poc.py" in exec_argv

    driver = DockerGuestDriver()
    driver.start(
        {
            "guest_id": "vf-poc-sess-abc",
            "workspace": work,
            "image": "python:3.12.8-slim-bookworm",
            "runtime": "runsc",
            "network": "none",
            "cpus": "1",
            "memory": "512m",
            "pids_limit": 64,
            "sleep_s": 30,
        }
    )
    assert calls and calls[0][0] == "docker" and "runsc" in calls[0]
    try:
        build_session_docker_argv(
            name="vf-poc-sess-bad",
            workspace=work,
            image="python:3.12.8-slim-bookworm",
            runtime="runc",
            network="none",
            cpus="1",
            memory="512m",
            pids_limit=64,
            sleep_s=30,
        )
        refused = False
    except ValueError as exc:
        refused = "runtime_refused" in str(exc)
    assert refused
    assert all("runc" not in cmd for cmd in calls)


def test_settings_knobs_apply_to_the_session(tmp_path: Path, monkeypatch):
    settings_path = tmp_path / "ui_settings.json"
    monkeypatch.setattr("vulnforge.settings.ui.UI_SETTINGS_PATH", settings_path)
    monkeypatch.setattr("vulnforge.settings.UI_SETTINGS_PATH", settings_path)
    save_ui_settings({"poc_iterate_max_cycles": 2, "poc_iterate_wall_ttl_min": 9})
    ui = load_ui_settings()
    assert ui["poc_iterate_max_cycles"] == 2
    assert ui["poc_iterate_wall_ttl_min"] == 9
    cfg = apply_ui_settings_to_cfg({"poc_harness": {"runner": "sandbox", "network": "none"}}, ui)
    assert harness_config(cfg)["iterate_max_cycles"] == 2
    assert harness_config(cfg)["iterate_wall_ttl_min"] == 9

    driver = RecordingDriver(_absent(6))
    session = run_iterate_session(
        _pack(tmp_path / "pack"),
        cfg=cfg,
        hub_text=HUB,
        probe=_probe(runtimes={"kata-qemu": {}, "runsc": {}}),
        driver=driver,
    )
    assert len(session["cycles"]) == 2
    assert session["max_cycles"] == 2
    assert session["wall_ttl_min"] == 9
    assert session["end_reason"] == "cycle_cap"
    assert session["runtime"] == "kata-qemu"


def _setup_run(tmp_path: Path, toy_sqli: Path) -> tuple[Path, Database]:
    run_dir = tmp_path / "run-001"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    write_json(run_dir / "target_manifest.json", build_target_manifest(toy_sqli, []))
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", str(toy_sqli), "code_static", "pin", {"poc_harness": {"runner": "sandbox"}})
    return run_dir, db


def _ready_finding(db: Database, run_dir: Path) -> int:
    body = {
        "title": "SQL injection in search_users",
        "summary": "concat",
        "weakness_class": "injection",
        "threat_model": {"attacker": "user", "boundary": "query", "impact": "read rows"},
        "citations": [{"path": "app.py", "start_line": 10}],
        "severity_claim": "HIGH",
        "evidence_id": "e-iter",
    }
    fid = db.insert_finding(body, state="needs_human", evidence_id="e-iter")
    pack = run_dir / "evidence" / "e-iter"
    pack.mkdir()
    (pack / "poc.py").write_text("print('ASSERT_OK')\n", encoding="utf-8")
    (pack / "poc_develop.md").write_text(HUB, encoding="utf-8")
    return fid


def test_iterate_stage_signal_does_not_confirm_or_touch_hitl(tmp_path: Path, toy_sqli: Path, monkeypatch):
    import vulnforge.poc_runner as pr
    import vulnforge.poc_session as ps

    monkeypatch.setattr(pr, "spawn_captured", lambda *a, **k: (_ for _ in ()).throw(AssertionError("host spawn")))
    monkeypatch.setattr(
        pr,
        "probe_host",
        lambda: _probe(runtimes={"runsc": {}}, kvm=False, firecracker_patched=False),
    )
    driver = RecordingDriver([_signal()])
    monkeypatch.setattr(ps, "driver_for", lambda choice: driver)

    run_dir, db = _setup_run(tmp_path, toy_sqli)
    fid = _ready_finding(db, run_dir)
    task = SimpleNamespace(
        id=9,
        kind="iterate_poc",
        payload={"finding_id": fid, "agent": False, "operator": "tester"},
    )
    result = iterate_poc.run(
        task,
        db,
        run_dir,
        {
            "poc_harness": {"enabled": True, "runner": "sandbox", "network": "none", "iterate_max_cycles": 5},
            "llm": {"fake": True},
            "stages": {"validate_poc_referee": True, "validate_llm": True},
        },
    )
    assert result["status"] == "succeeded"
    assert result["verdict"] == "signal_observed"
    assert result["end_reason"] == "signal_observed"
    assert result["finding_state"] == "needs_human"
    finding = db.get_finding(fid)
    assert finding.state == "needs_human"
    assert finding.body["poc_session_latest"]["confirms_finding"] is False
    assert db.list_hitl_responses() == []
    session = json.loads((run_dir / "evidence" / "e-iter" / "poc_session.json").read_text(encoding="utf-8"))
    assert session["confirms_finding"] is False
    assert session["clears_needs_human"] is False
    assert session["skips_hitl"] is False
    assert session["host_exec"] is False
    assert len(driver.execs) == 1
    db.close()


def test_missing_sandbox_leaves_needs_human(tmp_path: Path, toy_sqli: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    monkeypatch.setattr(pr, "spawn_captured", lambda *a, **k: (_ for _ in ()).throw(AssertionError("spawn")))
    monkeypatch.setattr(
        pr,
        "probe_host",
        lambda: _probe(runtimes={"runc": {}}, kvm=False, firecracker_patched=False, jailer_patched=False),
    )
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    fid = _ready_finding(db, run_dir)
    task = SimpleNamespace(id=4, kind="iterate_poc", payload={"finding_id": fid, "agent": False})
    result = iterate_poc.run(
        task,
        db,
        run_dir,
        {"poc_harness": {"runner": "sandbox"}, "llm": {"fake": True}, "stages": {}},
    )
    assert result["verdict"] == "sandbox_unavailable"
    assert result["end_reason"] == "sandbox_unavailable"
    assert db.get_finding(fid).state == "needs_human"
    assert db.list_hitl_responses() == []
    db.close()


def test_parse_rewrite_payload_and_fake_llm_cycle(tmp_path: Path):
    from vulnforge.llm import LLMResult, ResponseClass

    parsed = iterate_poc.parse_rewrite_payload('```json\n{"files": {"poc.py": "print(1)\\n"}, "note": "x"}\n```')
    assert parsed and parsed["files"]["poc.py"].startswith("print")
    assert iterate_poc.parse_rewrite_payload("no json") is None

    pack = _pack(tmp_path)
    driver = RecordingDriver([
        {
            "exit_code": 1,
            "timed_out": False,
            "spawn_error": None,
            "stdout": "no\n",
            "stderr": "boom",
            "duration_ms": 1,
            "ran": True,
        },
        _signal(),
    ])
    reply = LLMResult(
        ok=True,
        classification=ResponseClass.OK,
        content=json.dumps({"files": {"poc.py": "print('ASSERT_OK')\n"}, "note": "fixed"}),
        tool_calls=[],
        raw=None,
        model_id="fake",
    )
    session = run_iterate_session(
        pack,
        cfg={
            "poc_harness": {"runner": "gvisor", "iterate_max_cycles": 3},
            "llm": {"fake": True, "fake_responses": [reply]},
        },
        hub_text=HUB,
        probe=_probe(runtimes={"runsc": {}}),
        driver=driver,
        rewriter=iterate_poc._llm_rewriter(
            {"llm": {"fake": True, "fake_responses": [reply]}},
            [],
        ),
    )
    assert session["end_reason"] == "signal_observed"
    assert session["cycles"][1]["verdict"] == "signal_observed"
    assert "ASSERT_OK" in (pack / "poc.py").read_text(encoding="utf-8")
    assert session["confirms_finding"] is False
