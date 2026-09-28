"""Sandbox one-shot: isolation ladder, no host exec, campaign toggle, HITL unchanged."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from vulnforge.cli import EXIT_IDLE, EXIT_PROGRESS, cmd_run_once
from vulnforge.db import Database
from vulnforge.poc_phase import enqueue_sandbox_oneshot_phase, sandbox_oneshot_enabled
from vulnforge.poc_runner import (
    audit_sandbox_argv,
    build_docker_argv,
    build_firecracker_plan,
    execute_poc_for_pack,
    firecracker_version_patched,
    parse_version_tuple,
    select_isolation,
)
from vulnforge.stages import validate_poc
from vulnforge.util import build_target_manifest, write_json

HUB = "---\nrun: python poc.py\nsuccess_regex: ASSERT_OK\n---\n\n## Expected signal\nok\n"


def _probe(**overrides):
    base = {
        "docker": True,
        "docker_cli": True,
        "docker_error": None,
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
    pack.mkdir()
    (pack / "poc.py").write_text("print('ASSERT_OK')\n", encoding="utf-8")
    return pack


def test_firecracker_patch_bar():
    assert firecracker_version_patched(parse_version_tuple("firecracker 1.14.4"))
    assert firecracker_version_patched(parse_version_tuple("v1.14.9"))
    assert firecracker_version_patched(parse_version_tuple("1.15.1"))
    assert firecracker_version_patched(parse_version_tuple("1.16.0"))
    assert not firecracker_version_patched(parse_version_tuple("1.14.3"))
    assert not firecracker_version_patched(parse_version_tuple("1.15.0"))
    assert not firecracker_version_patched(parse_version_tuple("1.13.2"))
    assert not firecracker_version_patched(None)


def test_isolation_ladder_prefers_microvm_then_gvisor():
    hc = {"runner": "sandbox", "network": "none", "firecracker_kernel": "", "firecracker_rootfs": ""}
    both = _probe(runtimes={"kata-qemu": {}, "runsc": {}, "runc": {}})
    choice = select_isolation(hc, probe=both)
    assert choice["ok"] is True
    assert choice["isolation"] == "microvm"
    assert choice["runtime"] == "kata-qemu"

    unpatched_fc = _probe(
        runtimes={"kata-fc": {}, "kata-qemu": {}},
        firecracker_patched=False,
        jailer_patched=False,
    )
    choice = select_isolation(hc, probe=unpatched_fc)
    assert choice["runtime"] == "kata-qemu"

    patched_fc = _probe(runtimes={"kata-fc": {}, "kata-qemu": {}, "runsc": {}})
    choice = select_isolation(hc, probe=patched_fc)
    assert choice["runtime"] == "kata-fc"
    assert choice["isolation"] == "microvm"

    gvisor_only = _probe(runtimes={"runc": {}, "runsc": {}}, kvm=False, firecracker_patched=False)
    choice = select_isolation(hc, probe=gvisor_only)
    assert choice["isolation"] == "gvisor"
    assert choice["runtime"] == "runsc"

    plain = _probe(runtimes={"runc": {}}, kvm=False, firecracker_patched=False, jailer_patched=False)
    choice = select_isolation(hc, probe=plain)
    assert choice["ok"] is False
    assert choice["verdict"] == "sandbox_unavailable"

    # Pinned microvm does not drop to gVisor.
    pinned = dict(hc)
    pinned["runner"] = "microvm"
    choice = select_isolation(pinned, probe=gvisor_only)
    assert choice["ok"] is False


def test_host_and_runc_and_hostnet_refused(tmp_path: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    monkeypatch.setattr(
        pr,
        "spawn_captured",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("spawn")),
    )
    pack = _pack(tmp_path)
    probe = _probe(runtimes={"runsc": {}})
    for runner in ("local_subprocess", "runc"):
        result = execute_poc_for_pack(
            pack,
            cfg={"poc_harness": {"runner": runner, "network": "none"}},
            hub_text=HUB,
            finding_id=1,
            probe=probe,
        )
        assert result["verdict"] == "unsafe_skipped", runner
        assert result["ran"] is False
    hostnet = execute_poc_for_pack(
        pack,
        cfg={"poc_harness": {"runner": "sandbox", "network": "none"}},
        hub_text="---\nrun: python poc.py\nsuccess_regex: ASSERT_OK\nnetwork: host\n---\n\n## Expected signal\nok\n",
        finding_id=1,
        probe=probe,
    )
    assert hostnet["verdict"] == "unsafe_skipped"
    assert hostnet["spawn_error"] == "host_network_refused"


def test_docker_argv_is_hardened(tmp_path: Path):
    pack = _pack(tmp_path)
    argv = build_docker_argv(
        name="vf-poc-test",
        pack_dir=pack,
        command="python poc.py",
        image="python:3.12.8-slim-bookworm",
        runtime="runsc",
        network="none",
        env={"TARGET_URL": "http://127.0.0.1", "AWS_SECRET_ACCESS_KEY": "nope"},
        cpus="1",
        memory="512m",
        pids_limit=128,
    )
    audit_sandbox_argv(argv)
    blob = " ".join(argv)
    assert "--runtime" in argv and "runsc" in argv
    assert "--network=none" in argv
    assert "--privileged" not in blob
    assert "docker.sock" not in blob
    assert "--pids-limit=128" in argv
    assert "--memory=512m" in argv
    assert any(part.endswith(":/work:ro") for part in argv)
    assert "AWS_SECRET_ACCESS_KEY" not in blob
    assert "TARGET_URL=http://127.0.0.1" in blob


def test_secret_target_mount_refused(tmp_path: Path):
    pack = _pack(tmp_path)
    secret = tmp_path / ".aws"
    secret.mkdir()
    try:
        build_docker_argv(
            name="vf-poc-test",
            pack_dir=pack,
            command="python poc.py",
            image="python:3.12.8-slim-bookworm",
            runtime="runsc",
            network="none",
            env=None,
            cpus="1",
            memory="512m",
            pids_limit=64,
            target_path=secret,
            mount_target_ro=True,
        )
        raise AssertionError("mount should have been refused")
    except ValueError as e:
        assert "unsafe_mount" in str(e)


def test_firecracker_plan_has_no_nic_and_pci_off(tmp_path: Path):
    pack = _pack(tmp_path)
    kernel = tmp_path / "vmlinux"
    rootfs = tmp_path / "rootfs.ext4"
    kernel.write_bytes(b"k")
    rootfs.write_bytes(b"r")
    work = tmp_path / "jail"
    plan = build_firecracker_plan(
        pack_dir=pack,
        command="python poc.py",
        kernel=str(kernel),
        rootfs=str(rootfs),
        fc_bin="/usr/bin/firecracker",
        jail_bin="/usr/bin/jailer",
        memory="512m",
        timeout_s=15,
        work_dir=work,
    )
    cfg = plan["config"]
    assert "network-interfaces" not in cfg
    assert "pci=off" in cfg["boot-source"]["boot_args"]
    assert cfg["drives"][0]["is_read_only"] is True
    assert cfg["machine-config"]["vcpu_count"] == 1
    assert cfg["machine-config"]["mem_size_mib"] == 512
    assert plan["argv"][0].endswith("jailer")
    audit_sandbox_argv(plan["argv"])


def test_gvisor_signal_and_teardown(tmp_path: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    cleaned: list[list[str]] = []

    def _spawn(argv, *, timeout_s):
        assert argv[argv.index("--runtime") + 1] == "runsc"
        return {
            "exit_code": 0,
            "timed_out": False,
            "spawn_error": None,
            "stdout": "ASSERT_OK\n",
            "stderr": "",
            "duration_ms": 3,
            "argv": argv,
        }

    monkeypatch.setattr(pr, "spawn_captured", _spawn)
    monkeypatch.setattr(pr, "run_cleanup", lambda argv: cleaned.append(list(argv)))
    result = execute_poc_for_pack(
        _pack(tmp_path),
        cfg={"poc_harness": {"runner": "sandbox", "network": "none", "timeout_s": 15}},
        hub_text=HUB,
        finding_id=7,
        probe=_probe(runtimes={"runsc": {}}, kvm=False, firecracker_patched=False),
    )
    assert result["verdict"] == "signal_observed"
    assert result["signal_matched"] is True
    assert result["isolation"] == "gvisor"
    assert any(cmd[:3] == ["docker", "rm", "-f"] for cmd in cleaned)
    assert "confirmed" not in result["verdict"]


def test_spawn_failure_still_tears_down(tmp_path: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    cleaned: list[list[str]] = []

    def _boom(argv, *, timeout_s):
        raise RuntimeError("daemon down")

    monkeypatch.setattr(pr, "spawn_captured", _boom)
    monkeypatch.setattr(pr, "run_cleanup", lambda argv: cleaned.append(list(argv)))
    result = execute_poc_for_pack(
        _pack(tmp_path),
        cfg={"poc_harness": {"runner": "gvisor"}},
        hub_text=HUB,
        finding_id=1,
        probe=_probe(runtimes={"runsc": {}}),
    )
    assert result["verdict"] == "poc_broken"
    assert any("rm" in cmd for cmd in cleaned)


def _setup_run(tmp_path: Path, toy_sqli: Path, *, sandbox: bool):
    run_dir = tmp_path / "run-001"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    write_json(run_dir / "target_manifest.json", build_target_manifest(toy_sqli, []))
    db = Database.create(run_dir / "harness.db")
    db.insert_run(
        "run-001",
        str(toy_sqli),
        "code_static",
        "pin",
        {
            "run": {"sandbox_poc_validate": sandbox},
            "poc_harness": {"sandbox_oneshot": sandbox, "runner": "sandbox"},
        },
    )
    return run_dir, db


def _ready_finding(db: Database, run_dir: Path) -> int:
    body = {
        "title": "SQL injection in search_users",
        "summary": "concat",
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "user",
            "boundary": "query",
            "impact": "read rows",
        },
        "citations": [{"path": "app.py", "start_line": 10}],
        "severity_claim": "HIGH",
        "evidence_id": "e-sbx",
    }
    fid = db.insert_finding(body, state="needs_human", evidence_id="e-sbx")
    pack = run_dir / "evidence" / "e-sbx"
    pack.mkdir()
    (pack / "poc.py").write_text("print('ASSERT_OK')\n", encoding="utf-8")
    (pack / "poc_develop.md").write_text(HUB, encoding="utf-8")
    return fid


def test_campaign_toggle_off_does_not_enqueue(tmp_path: Path, toy_sqli: Path):
    run_dir, db = _setup_run(tmp_path, toy_sqli, sandbox=False)
    fid = _ready_finding(db, run_dir)
    assert sandbox_oneshot_enabled({"run": {"sandbox_poc_validate": False}}) is False
    ids = enqueue_sandbox_oneshot_phase(db, run_dir)
    assert ids == []
    assert db.get_finding(fid).state == "needs_human"
    db.close()


def test_campaign_toggle_enqueues_once_and_validate_keeps_needs_human(
    tmp_path: Path, toy_sqli: Path, monkeypatch
):
    import vulnforge.poc_runner as pr

    monkeypatch.setattr(
        pr,
        "spawn_captured",
        lambda argv, *, timeout_s: {
            "exit_code": 0,
            "timed_out": False,
            "spawn_error": None,
            "stdout": "ASSERT_OK\n",
            "stderr": "",
            "duration_ms": 4,
            "argv": argv,
        },
    )
    monkeypatch.setattr(pr, "run_cleanup", lambda argv: None)
    monkeypatch.setattr(
        pr,
        "probe_host",
        lambda: _probe(runtimes={"runsc": {}}, kvm=False, firecracker_patched=False),
    )
    run_dir, db = _setup_run(tmp_path, toy_sqli, sandbox=True)
    fid = _ready_finding(db, run_dir)
    db.close()

    args = SimpleNamespace(run_dir=run_dir)
    code = cmd_run_once(args, {"run": {}, "llm": {"fake": True}, "stages": {"validate_poc_referee": False}})
    assert code == EXIT_PROGRESS
    db = Database.open(run_dir / "harness.db")
    tasks = [t for t in db.list_tasks() if t.kind == "validate_poc"]
    assert len(tasks) == 1
    assert tasks[0].payload.get("sandbox_oneshot") is True
    assert db.get_finding(fid).state == "needs_human"
    db.close()

    code = cmd_run_once(
        args,
        {
            "run": {},
            "llm": {"fake": True, "fake_responses": []},
            "stages": {"validate_poc_referee": False},
            "poc_harness": {"enabled": True, "runner": "sandbox", "network": "none"},
            "packet": {},
        },
    )
    assert code == EXIT_PROGRESS
    db = Database.open(run_dir / "harness.db")
    finding = db.get_finding(fid)
    assert finding.state == "needs_human"
    assert finding.body["poc_validation_latest"]["verdict"] == "signal_observed"
    assert (run_dir / "evidence" / "e-sbx" / "poc_run.json").is_file()
    data = json.loads((run_dir / "evidence" / "e-sbx" / "poc_run.json").read_text(encoding="utf-8"))
    assert data["verdict"] == "signal_observed"
    assert data["isolation"] == "gvisor"
    db.close()

    code = cmd_run_once(args, {"run": {}, "stages": {"validate_poc_referee": False}})
    assert code == EXIT_IDLE


def test_missing_sandbox_does_not_change_state(tmp_path: Path, toy_sqli: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    monkeypatch.setattr(
        pr,
        "probe_host",
        lambda: _probe(runtimes={"runc": {}}, kvm=False, firecracker_patched=False, jailer_patched=False),
    )
    run_dir, db = _setup_run(tmp_path, toy_sqli, sandbox=False)
    fid = _ready_finding(db, run_dir)
    task = SimpleNamespace(id=3, kind="validate_poc", payload={"finding_id": fid})
    result = validate_poc.run(
        task,
        db,
        run_dir,
        {
            "poc_harness": {"enabled": True, "runner": "sandbox", "network": "none"},
            "stages": {"validate_poc_referee": False},
            "llm": {"fake": True},
            "packet": {},
        },
    )
    assert result["status"] == "succeeded"
    assert result["verdict"] == "sandbox_unavailable"
    assert db.get_finding(fid).state == "needs_human"
    db.close()


def _completed(argv, *, code: int, stdout: bytes = b"", stderr: bytes = b""):
    class _Proc:
        returncode = code
        pass

    proc = _Proc()
    proc.stdout = stdout
    proc.stderr = stderr
    proc.args = argv
    return proc


def test_probe_docker_cli_without_api_is_unusable(monkeypatch):
    import subprocess

    import vulnforge.poc_runner as pr

    def which(name: str):
        return "/usr/bin/docker" if name == "docker" else None

    def run(argv, **_kwargs):
        return _completed(
            argv,
            code=1,
            stderr=b"permission denied while trying to connect to the Docker daemon socket",
        )

    monkeypatch.setattr(pr.shutil, "which", which)
    monkeypatch.setattr(pr.subprocess, "run", run)
    info = pr.probe_host()
    assert info["docker_cli"] is True
    assert info["docker"] is False
    assert info["runtimes"] == {}
    assert pr.docker_available() is False
    choice = select_isolation(
        {"runner": "sandbox", "network": "none"},
        probe=info,
    )
    assert choice["ok"] is False
    assert choice["verdict"] == "sandbox_unavailable"

    def timeout(argv, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=3)

    monkeypatch.setattr(pr.subprocess, "run", timeout)
    timed = pr.probe_host()
    assert timed["docker"] is False
    assert timed["docker_error"] == "timeout"
    assert timed["runtimes"] == {}


def test_probe_api_and_runsc_selects_gvisor(monkeypatch):
    import vulnforge.poc_runner as pr

    def which(name: str):
        return "/usr/bin/docker" if name == "docker" else None

    def run(argv, **_kwargs):
        return _completed(argv, code=0, stdout=b'{"runsc":{"path":"runsc"},"runc":{}}')

    monkeypatch.setattr(pr.shutil, "which", which)
    monkeypatch.setattr(pr.subprocess, "run", run)
    monkeypatch.setattr(pr.Path, "exists", lambda self: False)
    info = pr.probe_host()
    assert info["docker"] is True
    assert info["docker_cli"] is True
    assert "runsc" in info["runtimes"]
    assert pr.docker_available() is True
    choice = select_isolation({"runner": "sandbox", "network": "none"}, probe=info)
    assert choice["ok"] is True
    assert choice["isolation"] == "gvisor"
    assert choice["runtime"] == "runsc"


def test_probe_ignores_runtimes_json_when_info_fails(monkeypatch):
    import vulnforge.poc_runner as pr

    def which(name: str):
        return "/usr/bin/docker" if name == "docker" else None

    def run(argv, **_kwargs):
        return _completed(argv, code=1, stdout=b'{"runsc":{}}', stderr=b"Cannot connect to the Docker daemon")

    monkeypatch.setattr(pr.shutil, "which", which)
    monkeypatch.setattr(pr.subprocess, "run", run)
    info = pr.probe_host()
    assert info["docker"] is False
    assert info["runtimes"] == {}
    choice = select_isolation({"runner": "sandbox", "network": "none"}, probe=info)
    assert choice["verdict"] == "sandbox_unavailable"


def test_preflight_mentions_relogin_when_gid_blocks_api(monkeypatch):
    import vulnforge.poc_runner as pr

    monkeypatch.setattr(
        pr,
        "probe_host",
        lambda: {
            "docker": False,
            "docker_cli": True,
            "docker_error": "permission denied while trying to connect to the Docker daemon socket",
            "runtimes": {},
            "kvm": False,
            "firecracker_patched": False,
            "jailer_patched": False,
        },
    )
    monkeypatch.setattr(pr, "effective_lacks_docker_group", lambda: True)
    report = pr.sandbox_poc_preflight({"poc_harness": {"runner": "sandbox", "network": "none"}})
    assert report["ok"] is False
    text = report["message"].lower()
    assert "docker api" in text
    assert "log out" in text
    assert "newgrp" in text

    monkeypatch.setattr(pr, "effective_lacks_docker_group", lambda: False)
    quiet = pr.sandbox_poc_preflight({"poc_harness": {"runner": "sandbox", "network": "none"}})
    assert quiet["ok"] is False
    assert "log out" not in quiet["message"].lower()


def test_preflight_refuses_when_runsc_missing(monkeypatch):
    import vulnforge.poc_runner as pr

    monkeypatch.setattr(
        pr,
        "probe_host",
        lambda: _probe(runtimes={"runc": {}}, kvm=False, firecracker_patched=False, jailer_patched=False),
    )
    report = pr.sandbox_poc_preflight({"poc_harness": {"runner": "sandbox", "network": "none"}})
    assert report["ok"] is False
    assert report["isolation"]["verdict"] == "sandbox_unavailable"
    assert "runsc" in report["message"].lower() or "microvm" in report["message"].lower()


def test_preflight_accepts_gvisor(monkeypatch):
    import vulnforge.poc_runner as pr

    monkeypatch.setattr(pr, "probe_host", lambda: _probe(runtimes={"runsc": {}}, kvm=False))
    report = pr.sandbox_poc_preflight({"poc_harness": {"runner": "sandbox", "network": "none"}})
    assert report["ok"] is True
    assert report["isolation"]["isolation"] == "gvisor"


def test_start_run_refuses_sandbox_poc_without_spawning(tmp_path: Path, monkeypatch):
    import vulnforge.poc_runner as pr
    from vulnforge.ui.runner import start_run

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run(
        run_id="run-001",
        target_path=str(tmp_path),
        profile="code_static",
        prompt_pin="pin",
        config={
            "run": {"sandbox_poc_validate": True},
            "poc_harness": {"sandbox_oneshot": True, "runner": "sandbox", "network": "none"},
        },
    )
    db.close()
    monkeypatch.setattr(
        pr,
        "probe_host",
        lambda: {
            "docker": False,
            "docker_cli": True,
            "docker_error": "permission denied while trying to connect to the Docker daemon socket",
            "runtimes": {},
            "kvm": False,
            "firecracker_patched": False,
            "jailer_patched": False,
        },
    )
    monkeypatch.setattr(pr, "effective_lacks_docker_group", lambda: True)

    def explode(*_a, **_k):
        raise AssertionError("ralph must not spawn")

    import vulnforge.ui.runner as runner

    monkeypatch.setattr(runner.subprocess, "Popen", explode)
    result = start_run(run_dir)
    assert result["ok"] is False
    assert "log out" in result["error"].lower()
    assert not (run_dir / "ralph.pid").is_file()


def test_start_block_skips_when_sandbox_off(tmp_path: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run(
        run_id="run-001",
        target_path=str(tmp_path),
        profile="code_static",
        prompt_pin="pin",
        config={"run": {"sandbox_poc_validate": False}, "poc_harness": {"sandbox_oneshot": False}},
    )
    db.close()

    def explode():
        raise AssertionError("probe")

    monkeypatch.setattr(pr, "probe_host", explode)
    assert pr.sandbox_poc_start_block(run_dir) is None
