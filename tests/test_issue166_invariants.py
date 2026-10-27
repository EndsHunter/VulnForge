"""Issue 166 slice 1: safety invariants locked before any doc or comment strip.

These checks call the harness. They do not rewrite sandbox, disprove, or bench code.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from vulnforge.cli import EXIT_CONFIG, EXIT_PROGRESS, main
from vulnforge.control.ops import review_finding
from vulnforge.db import Database
from vulnforge.hitl import approval_block_id, finding_report_id, respond
from vulnforge.llm import LLMResult, ResponseClass
from vulnforge.poc_runner import (
    DEFAULT_POC_NETWORK,
    ORACLE_WRAPPER,
    audit_sandbox_argv,
    build_docker_argv,
    execute_poc_for_pack,
    run_poc_docker,
    run_poc_local,
    score_oracle_sh,
    select_isolation,
)
from vulnforge.stages import validate_llm
from vulnforge.stages.validate_mech import run as validate_mech_run
from vulnforge.util import build_target_manifest, write_json

HUB = "---\nrun: python poc.py\nsuccess_regex: ASSERT_OK\n---\n\n## Expected signal\nok\n"
_HEX_CANARY = re.compile(r"^[0-9a-f]{32}$")
_STAND = (
    "Claim holds. Alternative fails: no parameterization on path.\n"
    "Reachable: yes.\nVERDICT=stand"
)


def _empty_probe() -> dict:
    return {
        "docker": False,
        "docker_cli": False,
        "docker_error": None,
        "runtimes": {},
        "kvm": False,
        "firecracker_patched": False,
        "jailer_patched": False,
    }


def _gvisor_probe(**overrides) -> dict:
    probe = {
        "docker": True,
        "docker_cli": True,
        "docker_error": None,
        "runtimes": {"runsc": {}},
        "kvm": False,
        "firecracker_patched": False,
        "jailer_patched": False,
    }
    probe.update(overrides)
    return probe


def _pack(tmp_path: Path, source: str = "print('ASSERT_OK')\n") -> Path:
    pack = tmp_path / "pack"
    pack.mkdir(parents=True, exist_ok=True)
    (pack / "poc.py").write_text(source, encoding="utf-8")
    return pack


class _Task:
    def __init__(self, fid: int):
        self.payload = {"finding_id": fid}
        self.id = 1


def _setup_run(tmp_path: Path, toy_sqli: Path):
    run_dir = tmp_path / "run-001"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    man = build_target_manifest(toy_sqli, [])
    write_json(run_dir / "target_manifest.json", man)
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", str(toy_sqli), "code_static", "pin", {})
    return run_dir, db


def _good_body(toy_sqli: Path) -> dict:
    body = {
        "title": "SQL injection in search_users",
        "summary": "User input is concatenated into SQL.",
        "weakness_class": "injection",
        "threat_model": {
            "attacker": "unauthenticated user",
            "boundary": "HTTP query parameter to SQL engine",
            "impact": "read or modify arbitrary user rows",
        },
        "citations": [{"path": "app.py", "start_line": 10, "symbol": "search_users"}],
        "evidence_id": "e1",
        "severity_claim": "HIGH",
    }
    text = (toy_sqli / "app.py").read_text(encoding="utf-8")
    for i, line in enumerate(text.splitlines(), 1):
        if "search_users" in line:
            body["citations"][0]["start_line"] = i
            break
    return body


def _write_evidence(run_dir: Path) -> None:
    pack = run_dir / "evidence" / "e1"
    pack.mkdir(parents=True, exist_ok=True)
    (pack / "note.txt").write_text(
        "repro notes for SQL injection PoC steps\n",
        encoding="utf-8",
    )


def _fake_cfg() -> dict:
    responses = [
        LLMResult(
            ok=True,
            classification=ResponseClass.OK,
            content=_STAND,
            tool_calls=[],
            raw=None,
            model_id="fake-disprove",
        )
        for _ in range(2)
    ]
    return {
        "stages": {"validate_llm": True},
        "llm": {
            "fake": True,
            "model": "fake-disprove",
            "fake_responses": responses,
        },
        "packet": {"max_file_slice_chars": 4000},
    }


def test_sandbox_only_refuses_host_exec_and_plain_runc(tmp_path: Path, monkeypatch):
    """Host exec and plain runc are refused. A missing sandbox does not spawn."""
    import vulnforge.poc_runner as pr

    calls: list[object] = []

    def _spawn(*_a, **_k):
        calls.append(True)
        raise AssertionError("host or unsandboxed exec must not spawn")

    monkeypatch.setattr(pr, "spawn_captured", _spawn)
    empty = _empty_probe()
    for runner in (
        "local",
        "host",
        "subprocess",
        "local_subprocess",
        "runc",
        "plain",
        "docker-runc",
    ):
        choice = select_isolation({"runner": runner}, empty)
        assert choice["ok"] is False
        assert choice["isolation"] is None
        assert choice["verdict"] == "unsafe_skipped"
        assert choice["runtime"] is None

    local = run_poc_local(tmp_path, "python poc.py")
    assert local["spawn_error"] == "host_exec_refused"
    plain = run_poc_docker(tmp_path, "python poc.py")
    assert plain["spawn_error"] == "plain_runc_refused"

    refused = execute_poc_for_pack(
        _pack(tmp_path),
        cfg={"poc_harness": {"runner": "local"}},
        hub_text=HUB,
        probe=empty,
    )
    assert refused["verdict"] == "unsafe_skipped"
    assert refused["verdict"] != "signal_observed"
    assert refused.get("suggested_finding_action") != "confirmed"
    assert calls == []


def test_sandbox_ladder_microvm_then_gvisor_then_refuse():
    """Auto isolation is microVM, then gVisor, then refuse. Never host."""
    empty = _empty_probe()
    refused = select_isolation({"runner": "sandbox"}, empty)
    assert refused["ok"] is False
    assert refused["error"] == "sandbox_unavailable"
    assert refused["verdict"] == "sandbox_unavailable"
    assert refused["isolation"] is None

    gvisor_only = select_isolation({"runner": "sandbox"}, _gvisor_probe())
    assert gvisor_only["ok"] is True
    assert gvisor_only["isolation"] == "gvisor"
    assert gvisor_only["runtime"] == "runsc"

    both = select_isolation(
        {"runner": "sandbox"},
        _gvisor_probe(runtimes={"runsc": {}, "kata-qemu": {}}),
    )
    assert both["ok"] is True
    assert both["isolation"] == "microvm"
    assert both["runtime"] == "kata-qemu"

    missing_gvisor = select_isolation({"runner": "gvisor"}, empty)
    assert missing_gvisor["ok"] is False
    assert missing_gvisor["verdict"] == "sandbox_unavailable"


def test_sandbox_guest_network_defaults_to_none(tmp_path: Path):
    """Guest network is none. Host network and privileged argv are refused."""
    assert DEFAULT_POC_NETWORK == "none"
    pack = _pack(tmp_path)
    argv = build_docker_argv(
        name="vf-poc-test",
        pack_dir=pack,
        command="python poc.py",
        image="vulnforge-sandbox:test",
        runtime="runsc",
        network="none",
        env=None,
        cpus="1",
        memory="512m",
        pids_limit=64,
    )
    assert "--network=none" in argv
    assert "--network=host" not in argv
    assert "--privileged" not in argv
    assert "--runtime" in argv
    assert "runsc" in argv
    assert any(part.endswith(":ro") for part in argv)
    audit_sandbox_argv(argv)

    try:
        build_docker_argv(
            name="vf-poc-host",
            pack_dir=pack,
            command="python poc.py",
            image="vulnforge-sandbox:test",
            runtime="runsc",
            network="host",
            env=None,
            cpus="1",
            memory="512m",
            pids_limit=64,
        )
    except ValueError as exc:
        assert "host_network" in str(exc)
    else:
        raise AssertionError("host network must be refused")

    host = select_isolation(
        {"runner": "sandbox", "network": "host"},
        _gvisor_probe(),
    )
    assert host["ok"] is False
    assert host["error"] == "host_network_refused"
    assert host["verdict"] == "unsafe_skipped"

    try:
        audit_sandbox_argv(["docker", "run", "--network=host", "--privileged"])
    except ValueError as exc:
        assert "unsafe_sandbox_argv" in str(exc)
    else:
        raise AssertionError("unsafe sandbox argv must be refused")


def test_no_third_party_targets_remote_url_is_not_fetched(
    tmp_path: Path, toy_sqli: Path, monkeypatch
):
    """An audit target is a local tree. A remote URL is not fetched or initialized."""
    import socket
    import subprocess
    import urllib.request

    def _blocked(*_a, **_k):
        raise AssertionError("third-party target fetch is not allowed")

    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(urllib.request, "urlopen", _blocked)
    monkeypatch.setattr(subprocess, "run", _blocked)
    monkeypatch.setattr(subprocess, "Popen", _blocked)
    monkeypatch.setattr(subprocess, "check_call", _blocked)

    runs = tmp_path / "runs"
    for url in (
        "https://github.com/example/third-party-target",
        "http://example.com/third-party-target",
        "git@github.com:example/third-party-target.git",
    ):
        code = main(
            ["init", "--target", url, "--runs-root", str(runs), "--no-enqueue-hunts"]
        )
        assert code == EXIT_CONFIG
        assert not runs.exists() or not any(runs.rglob("harness.db"))
    monkeypatch.undo()

    code = main(
        [
            "init",
            "--target",
            str(toy_sqli),
            "--runs-root",
            str(runs),
            "--no-enqueue-hunts",
        ]
    )
    assert code == EXIT_PROGRESS
    run_dirs = [p for p in runs.rglob("harness.db")]
    assert len(run_dirs) == 1
    db = Database.open(run_dirs[0])
    try:
        target_path = str(db.get_run()["target_path"])
    finally:
        db.close()
    assert target_path == str(toy_sqli.resolve())
    assert "://" not in target_path
    assert "git@" not in target_path
    assert Path(target_path).is_dir()


def test_no_third_party_targets_bench_seed_stays_local():
    """Bench tasks are local seed trees. The manifest has no remote target."""
    from bench.tasks import SEED_DIR, load_tasks

    manifest_path = SEED_DIR / "manifest.json"
    raw = manifest_path.read_text(encoding="utf-8")
    assert "://" not in raw
    assert "git@" not in raw
    manifest = json.loads(raw)
    root = SEED_DIR.resolve()
    for item in manifest["tasks"]:
        for key in ("vulnerable", "fixed", "tree"):
            rel = item.get(key)
            if not rel:
                continue
            text = str(rel)
            assert "://" not in text
            assert not text.startswith("/")
            assert ".." not in Path(text).parts
            resolved = (SEED_DIR / text).resolve()
            resolved.relative_to(root)
            assert resolved.is_dir()
    for task in load_tasks():
        for side in (task.vulnerable, task.fixed, task.tree):
            if side is None:
                continue
            side.resolve().relative_to(root)
            assert side.is_dir()


def test_gate_chain_mech_then_disprove_then_human_accept(
    tmp_path: Path, toy_sqli: Path
):
    """Mech pass, then LLM disprove, then human accept. Automation never confirms."""
    run_dir, db = _setup_run(tmp_path, toy_sqli)
    body = _good_body(toy_sqli)
    cand = tmp_path / "candidate.json"
    cand.write_text(json.dumps(body), encoding="utf-8")
    db.close()

    code = main(
        ["apply-candidate", "--run-dir", str(run_dir), "--file", str(cand)]
    )
    assert code == EXIT_PROGRESS

    db = Database.open(run_dir / "harness.db")
    try:
        tasks = db.list_tasks()
        assert [t.kind for t in tasks] == ["validate_mech"]
        finding = db.list_findings()[0]
        fid = finding.id
        assert finding.state == "candidate"
        assert finding.state != "confirmed"
        _write_evidence(run_dir)

        early = validate_llm.run(_Task(fid), db, run_dir, _fake_cfg())
        assert early["status"] == "failed_task"
        assert early.get("error") == "mech_not_passed"
        assert db.get_finding(fid).state == "candidate"

        mech = validate_mech_run(
            _Task(fid), db, run_dir, {"stages": {"validate_llm": True}}
        )
        assert mech["verdict"] == "pending_llm"
        assert mech["finding_state"] == "needs_human"
        mid = db.get_finding(fid)
        assert mid.state == "needs_human"
        assert mid.state != "confirmed"
        assert (mid.body.get("validation_mech") or {}).get("status") == "passed"
        assert (mid.body.get("validation_mech") or {}).get("pending_llm") is True
        kinds = [t.kind for t in db.list_tasks()]
        assert "validate_llm" in kinds
        assert "confirmed" not in kinds

        db.conn.commit()
        blocked = review_finding(run_dir, fid, action="confirm", notes="too early")
        assert blocked["ok"] is False
        assert blocked["code"] == "pending_llm"
        hitl_blocked = respond(
            db,
            run_dir,
            finding_report_id(fid),
            block_id=approval_block_id(fid),
            value="approved",
        )
        assert hitl_blocked.get("ok") is False
        assert hitl_blocked.get("code") == "pending_llm"
        assert db.get_finding(fid).state == "needs_human"

        disprove = validate_llm.run(_Task(fid), db, run_dir, _fake_cfg())
        assert disprove["status"] == "succeeded"
        after = db.get_finding(fid)
        assert after.state == "needs_human"
        assert after.state != "confirmed"
        assert (after.body.get("validation_mech") or {}).get("pending_llm") is False

        db.conn.commit()
        accepted = review_finding(run_dir, fid, action="confirm", notes="human accept")
        assert accepted["ok"] is True
        assert accepted["to_state"] == "confirmed"
        assert db.get_finding(fid).state == "confirmed"
    finally:
        db.close()


# Local fixture only. Copies the canary onto fd 3 when the trigger is set.
_FORGE_COMMAND = '[ "$VF_TRIGGER" = 1 ] && cat /tmp/vf-oracle/canary >&3'


def test_poc_oracle_forged_fd3_copy_is_not_signal(tmp_path: Path):
    """A PoC that copies the canary file onto fd 3 when triggered is not a signal.

    Runs the shipped wrapper under sh. No spawn_captured mock.
    """
    pack = tmp_path / "forge"
    pack.mkdir()
    result = score_oracle_sh(pack, _FORGE_COMMAND, k=2, timeout_s=20)
    assert result["verdict"] != "signal_observed"
    assert result["signal_matched"] is not True
    assert result["oracle"]["planted"] is True
    assert result["command"] == _FORGE_COMMAND


_PRINT_POC = """\
from pathlib import Path
path = Path("/tmp/vf-oracle/canary")
print(path.read_text() if path.is_file() else "")
print("ASSERT_OK")
"""

_SINK_CLIENT = """\
import socket
import time
from pathlib import Path
payload = %s
path = Path("/tmp/vf-oracle/svc")
for _ in range(80):
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(str(path))
        sock.send(payload)
        sock.close()
        break
    except OSError:
        time.sleep(0.05)
"""


def _target_source(label: str, *, emit: bool) -> str:
    body = (
        "sys.stdout.write(Path(secret).read_text())\n"
        "    sys.stdout.flush()\n"
        if emit
        else "pass\n"
    )
    return (
        "import os, socket, sys\n"
        "from pathlib import Path\n"
        "sock = os.environ['VF_ORACLE_SOCK']\n"
        "secret = os.environ['VF_CANARY_FILE']\n"
        "if os.path.exists(sock):\n"
        "    os.unlink(sock)\n"
        "server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
        "server.bind(sock)\n"
        "os.chmod(sock, 0o666)\n"
        "server.listen(1)\n"
        "server.settimeout(3)\n"
        "try:\n"
        "    conn, _addr = server.accept()\n"
        "except socket.timeout:\n"
        "    raise SystemExit(0)\n"
        "data = conn.recv(128)\n"
        f"Path('/tmp/vf-poc-seen').open('a').write({label!r} + ':' + data.decode('utf-8', 'replace'))\n"
        "if data.startswith(b'HIT'):\n"
        f"    {body}"
        "conn.close()\n"
    )


def _write_pair(pack: Path, *, fixed_emits: bool, payload: bytes) -> None:
    pack.mkdir(parents=True, exist_ok=True)
    (pack / "target_vuln.py").write_text(_target_source("VULN", emit=True), encoding="utf-8")
    (pack / "target_fixed.py").write_text(
        _target_source("FIXED", emit=fixed_emits), encoding="utf-8"
    )
    (pack / "poc.py").write_text(_SINK_CLIENT % repr(payload), encoding="utf-8")


def test_poc_oracle_fresh_canary_is_scored_on_fd3(tmp_path: Path):
    """A sink hit on the vulnerable target scores. The fixed target does not."""
    assert "target_vuln.py" in ORACLE_WRAPPER
    assert "target_fixed.py" in ORACLE_WRAPPER
    assert "/tmp/vf-oracle/req" not in ORACLE_WRAPPER
    assert '3>"$d/target.stdout"' not in ORACLE_WRAPPER

    def _once(root: Path):
        pack = root / "pack"
        _write_pair(pack, fixed_emits=False, payload=b"HIT\n")
        seen = Path("/tmp/vf-poc-seen")
        seen.unlink(missing_ok=True)
        scored = score_oracle_sh(pack, "python3 poc.py", k=2, timeout_s=25)
        text = seen.read_text(encoding="utf-8") if seen.is_file() else ""
        return scored, text

    first, first_seen = _once(tmp_path / "a")
    second, _second_seen = _once(tmp_path / "b")
    assert first["verdict"] == "signal_observed"
    assert second["verdict"] == "signal_observed"
    assert first["oracle"]["reason"] == "differential_ok"
    assert first["triggers"] == ["1", "0", "1", "0"]
    assert _HEX_CANARY.fullmatch(first["canary"])
    assert first["canary"] != second["canary"]
    assert first["canary"] not in (first.get("command") or "")
    assert first["canary"] not in (first.get("stdout_excerpt") or "")
    assert "VULN:" in first_seen and "FIXED:" in first_seen
    controls = [t for t in first["trials"] if t.get("phase") == "control"]
    treatments = [t for t in first["trials"] if t.get("phase") == "treatment"]
    assert treatments and controls
    assert all(first["canary"] in (t.get("target_stdout") or "") for t in treatments)
    assert all(first["canary"] not in (t.get("target_stdout") or "") for t in controls)


def test_poc_oracle_sink_hit_scores_only_the_vulnerable_side(tmp_path: Path):
    """The same request is signal_observed only because the vulnerable sink ran."""
    pack = tmp_path / "pack"
    _write_pair(pack, fixed_emits=False, payload=b"HIT\n")
    Path("/tmp/vf-poc-seen").unlink(missing_ok=True)
    result = score_oracle_sh(pack, "python3 poc.py", k=1, timeout_s=20)
    assert result["verdict"] == "signal_observed"
    assert result["oracle"]["treatment_hits"] == 1
    assert result["oracle"]["control_hits"] == 0
    seen = Path("/tmp/vf-poc-seen").read_text(encoding="utf-8")
    assert seen.startswith("VULN:")
    assert "FIXED:" in seen


def test_poc_oracle_control_run_must_omit_canary(tmp_path: Path):
    """The control side is the fixed target. If that sink still emits, it is not a signal."""
    pack = tmp_path / "pack"
    _write_pair(pack, fixed_emits=True, payload=b"HIT\n")
    result = score_oracle_sh(pack, "python3 poc.py", k=1, timeout_s=20)
    assert result["oracle"]["reason"] == "control_showed_canary"
    assert result["verdict"] != "signal_observed"
    assert result["signal_matched"] is not True
    assert result["oracle"]["control_hits"] == 1


def test_poc_oracle_empty_pack_req_write_is_signal_absent(tmp_path: Path):
    """An empty pack that only writes the old request path is not a signal."""
    pack = tmp_path / "empty"
    pack.mkdir()
    result = score_oracle_sh(pack, "echo go > /tmp/vf-oracle/req", k=1, timeout_s=20)
    assert result["verdict"] == "signal_absent"
    assert result["signal_matched"] is not True
    assert result["oracle"]["reason"] == "canary_absent"


def test_poc_oracle_request_that_misses_the_sink_is_signal_absent(tmp_path: Path):
    """A request the vulnerable target accepts without reaching the sink is not a signal."""
    pack = tmp_path / "pack"
    _write_pair(pack, fixed_emits=False, payload=b"NOPE\n")
    seen = Path("/tmp/vf-poc-seen")
    seen.unlink(missing_ok=True)
    result = score_oracle_sh(pack, "python3 poc.py", k=1, timeout_s=20)
    assert result["verdict"] == "signal_absent"
    assert result["oracle"]["reason"] == "canary_absent"
    text = seen.read_text(encoding="utf-8")
    assert "VULN:" in text and "NOPE" in text
    assert result["canary"] not in text


def test_poc_oracle_direct_read_of_canary_resource_is_signal_absent(tmp_path: Path):
    """The PoC uid cannot read the canary file the sink guards."""
    pack = tmp_path / "pack"
    _write_pair(pack, fixed_emits=False, payload=b"NOPE\n")
    reader = (
        "p='/tmp/vf-oracle/secret'\n"
        "try:\n"
        "    open(p).read()\n"
        "    print('READ_OK')\n"
        "except OSError as exc:\n"
        "    print('READ_DENY', exc.errno)\n"
    )
    (pack / "read.py").write_text(reader, encoding="utf-8")
    result = score_oracle_sh(pack, "python3 read.py", k=1, timeout_s=20)
    assert result["verdict"] == "signal_absent"
    stdout = "".join(str(t.get("poc_stdout") or "") for t in result["trials"])
    assert "READ_DENY" in stdout
    assert "READ_OK" not in stdout
    assert result["canary"] not in stdout


def test_poc_oracle_proc_fd_is_not_readable(tmp_path: Path):
    """The PoC cannot open the parent or target oracle fds through /proc."""
    pack = tmp_path / "pack"
    _write_pair(pack, fixed_emits=False, payload=b"NOPE\n")
    (pack / "probe.py").write_text(
        "import os\n"
        "ppid = os.getppid()\n"
        "try:\n"
        "    os.open('/proc/%d/fd/5' % ppid, os.O_RDONLY)\n"
        "    print('PPID5_OK')\n"
        "except OSError as exc:\n"
        "    print('PPID5_DENY', exc.errno)\n"
        "opened = False\n"
        "for pid in os.listdir('/proc'):\n"
        "    if not pid.isdigit():\n"
        "        continue\n"
        "    try:\n"
        "        os.open('/proc/%s/fd/3' % pid, os.O_RDONLY)\n"
        "        print('FD3_OK', pid)\n"
        "        opened = True\n"
        "    except OSError:\n"
        "        pass\n"
        "if not opened:\n"
        "    print('FD3_DENY')\n",
        encoding="utf-8",
    )
    result = score_oracle_sh(pack, "python3 probe.py", k=1, timeout_s=20)
    assert result["verdict"] == "signal_absent"
    stdout = "".join(str(t.get("poc_stdout") or "") for t in result["trials"])
    assert "PPID5_OK" not in stdout
    assert "PPID5_DENY" in stdout
    assert "FD3_OK" not in stdout
    assert "FD3_DENY" in stdout
    assert result["canary"] not in stdout


def test_poc_oracle_target_sanitizer_abort_is_signal_on_vulnerable_side(tmp_path: Path):
    """A sanitizer abort in the target process scores only on the vulnerable side."""
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "target_vuln.py").write_text("import os\nos.abort()\n", encoding="utf-8")
    (pack / "target_fixed.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
    result = score_oracle_sh(pack, "true", k=1, timeout_s=20)
    assert result["verdict"] == "signal_observed"
    assert result["oracle"]["reason"] == "differential_ok"
    assert result["oracle"]["control_hits"] == 0


def test_poc_oracle_marker_in_poc_or_printed_by_poc_is_not_signal(tmp_path: Path):
    """A canary in the PoC source, or printed by the PoC, is not signal_observed."""
    canary = "ab" * 16
    leaked = score_oracle_sh(
        _pack(tmp_path / "src", f"print({canary!r})\n"),
        "python3 poc.py",
        canary=canary,
        k=1,
    )
    assert leaked["verdict"] == "poc_broken"
    assert leaked["oracle"]["reason"] == "marker_in_poc_source"
    assert leaked["verdict"] != "signal_observed"
    assert leaked["trials"] == []

    in_args = score_oracle_sh(
        _pack(tmp_path / "args", "print('ok')\n"),
        f"python3 poc.py {canary}",
        canary=canary,
        k=1,
    )
    assert in_args["verdict"] == "poc_broken"
    assert in_args["oracle"]["reason"] == "marker_in_args"
    assert in_args["verdict"] != "signal_observed"
    assert in_args["trials"] == []

    pack = tmp_path / "print"
    pack.mkdir()
    (pack / "print.py").write_text(_PRINT_POC, encoding="utf-8")
    printed = score_oracle_sh(pack, "python3 print.py", k=2, timeout_s=20)
    assert printed["verdict"] != "signal_observed"
    assert printed["signal_matched"] is not True

    own = tmp_path / "own"
    own.mkdir()
    (own / "own.py").write_text("print('ASSERT_OK')\n", encoding="utf-8")
    self_printed = score_oracle_sh(own, "python3 own.py", k=2, timeout_s=20)
    assert self_printed["verdict"] != "signal_observed"
    assert self_printed["signal_matched"] is not True
