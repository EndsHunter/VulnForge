"""Canary oracle: a PoC cannot certify signal_observed by printing its own marker."""

from __future__ import annotations

from pathlib import Path

from vulnforge.poc_runner import (
    execute_poc_for_pack,
    judge_oracle_trials,
    marker_in_poc_or_args,
    mint_canary,
)

HUB = "---\nrun: python poc.py\nsuccess_regex: ASSERT_OK\n---\n\n## Expected signal\nok\n"


def _probe():
    return {
        "docker": True,
        "docker_cli": True,
        "docker_error": None,
        "runtimes": {"runsc": {}},
        "kvm": False,
        "firecracker_patched": False,
        "jailer_patched": False,
    }


def _pack(tmp_path: Path, source: str = "print('ASSERT_OK')\n") -> Path:
    pack = tmp_path / "pack"
    pack.mkdir(parents=True)
    (pack / "poc.py").write_text(source, encoding="utf-8")
    return pack


def _env_from_argv(argv: list[str]) -> dict[str, str]:
    env: dict[str, str] = {}
    i = 0
    while i < len(argv):
        if argv[i] == "-e" and i + 1 < len(argv):
            key, _, val = argv[i + 1].partition("=")
            env[key] = val
            i += 2
            continue
        i += 1
    return env


def _framed(target: str, mark: str, poc_out: str = "", poc_err: str = "") -> str:
    return f"{target}\n{mark}\n{poc_out}\n{mark}ERR\n{poc_err}"


def _trial(phase: str, *, target: str = "", exit_code: int = 0, poc_out: str = "", poc_err: str = "", raw_stderr: str = "") -> dict:
    return {
        "phase": phase,
        "exit_code": exit_code,
        "timed_out": False,
        "spawn_error": None,
        "ran": True,
        "target_stdout": target,
        "poc_stdout": poc_out,
        "poc_stderr": poc_err,
        "raw_stderr": raw_stderr,
        "stdout": target,
        "stderr": raw_stderr,
    }


def test_self_printed_marker_is_not_signal_observed(tmp_path: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    calls = {"n": 0}

    def _spawn(argv, *, timeout_s):
        calls["n"] += 1
        return {
            "exit_code": 0,
            "timed_out": False,
            "spawn_error": None,
            "stdout": "ASSERT_OK\n",
            "stderr": "ASSERT_OK\n",
            "duration_ms": 1,
            "argv": argv,
        }

    monkeypatch.setattr(pr, "spawn_captured", _spawn)
    monkeypatch.setattr(pr, "run_cleanup", lambda argv: None)
    result = execute_poc_for_pack(
        _pack(tmp_path),
        cfg={"poc_harness": {"runner": "gvisor", "oracle_k": 2}},
        hub_text=HUB,
        finding_id=1,
        probe=_probe(),
    )
    assert calls["n"] == 4  # k treatment + k control
    assert result["verdict"] != "signal_observed"
    assert result["verdict"] == "signal_absent"
    assert result["signal_matched"] is not True
    assert result["confidence"] == "low"
    assert result["oracle"]["k"] == 2
    assert result["oracle"]["planted"] is True


def test_differential_canary_on_target_stdout(tmp_path: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    seen: list[str] = []

    def _spawn(argv, *, timeout_s):
        env = _env_from_argv(argv)
        canary = env["VF_CANARY"]
        mark = env["VF_ORACLE_MARK"]
        seen.append(canary)
        assert canary not in (env.get("VF_POC_COMMAND") or "")
        assert "VF_CANARY=" not in argv[-1]
        target = f"{canary}\n" if env.get("VF_TRIGGER") == "1" else ""
        return {
            "exit_code": 0,
            "timed_out": False,
            "spawn_error": None,
            "stdout": _framed(target, mark),
            "stderr": "",
            "duration_ms": 2,
            "argv": argv,
        }

    monkeypatch.setattr(pr, "spawn_captured", _spawn)
    monkeypatch.setattr(pr, "run_cleanup", lambda argv: None)
    result = execute_poc_for_pack(
        _pack(tmp_path, "raise SystemExit('poc does not print a marker')\n"),
        cfg={"poc_harness": {"runner": "gvisor", "oracle_k": 2}},
        hub_text=HUB,
        finding_id=3,
        probe=_probe(),
    )
    assert result["verdict"] == "signal_observed"
    assert result["signal_matched"] is True
    assert result["confidence"] == "medium"
    assert result["exit_code"] == 0
    assert result["oracle"]["reason"] == "differential_ok"
    assert result["oracle"]["treatment_hits"] == 2
    assert result["oracle"]["control_hits"] == 0
    assert len(set(seen)) == 1
    assert len(seen) == 4
    canary = seen[0]
    assert canary not in (result.get("command") or "")
    assert canary not in str(result.get("argv"))
    assert canary not in (result.get("stdout_excerpt") or "")


def test_control_showing_canary_is_inconclusive(tmp_path: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    def _spawn(argv, *, timeout_s):
        env = _env_from_argv(argv)
        canary = env["VF_CANARY"]
        mark = env["VF_ORACLE_MARK"]
        return {
            "exit_code": 0,
            "timed_out": False,
            "spawn_error": None,
            "stdout": _framed(f"{canary}\n", mark),
            "stderr": "",
            "duration_ms": 1,
            "argv": argv,
        }

    monkeypatch.setattr(pr, "spawn_captured", _spawn)
    monkeypatch.setattr(pr, "run_cleanup", lambda argv: None)
    result = execute_poc_for_pack(
        _pack(tmp_path),
        cfg={"poc_harness": {"runner": "gvisor", "oracle_k": 2}},
        hub_text=HUB,
        probe=_probe(),
    )
    assert result["verdict"] == "inconclusive"
    assert result["oracle"]["reason"] == "control_showed_canary"
    assert result["verdict"] != "signal_observed"


def test_poc_stdout_canary_does_not_count(tmp_path: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    def _spawn(argv, *, timeout_s):
        env = _env_from_argv(argv)
        canary = env["VF_CANARY"]
        mark = env["VF_ORACLE_MARK"]
        poc_out = canary if env.get("VF_TRIGGER") == "1" else ""
        return {
            "exit_code": 0,
            "timed_out": False,
            "spawn_error": None,
            "stdout": _framed("", mark, poc_out=poc_out),
            "stderr": "",
            "duration_ms": 1,
            "argv": argv,
        }

    monkeypatch.setattr(pr, "spawn_captured", _spawn)
    monkeypatch.setattr(pr, "run_cleanup", lambda argv: None)
    result = execute_poc_for_pack(
        _pack(tmp_path),
        cfg={"poc_harness": {"runner": "gvisor"}},
        hub_text=HUB,
        probe=_probe(),
    )
    assert result["verdict"] == "inconclusive"
    assert result["oracle"]["reason"] == "marker_on_poc_stream"


def test_stderr_only_canary_does_not_count(tmp_path: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    def _spawn(argv, *, timeout_s):
        env = _env_from_argv(argv)
        canary = env["VF_CANARY"]
        mark = env["VF_ORACLE_MARK"]
        err = canary if env.get("VF_TRIGGER") == "1" else ""
        return {
            "exit_code": 0,
            "timed_out": False,
            "spawn_error": None,
            "stdout": _framed("", mark, poc_err=err),
            "stderr": "",
            "duration_ms": 1,
            "argv": argv,
        }

    monkeypatch.setattr(pr, "spawn_captured", _spawn)
    monkeypatch.setattr(pr, "run_cleanup", lambda argv: None)
    result = execute_poc_for_pack(
        _pack(tmp_path),
        cfg={"poc_harness": {"runner": "gvisor"}},
        hub_text=HUB,
        probe=_probe(),
    )
    assert result["verdict"] == "inconclusive"
    assert result["oracle"]["reason"] == "marker_on_poc_stream"


def test_nonzero_exit_is_not_signal_observed(tmp_path: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    def _spawn(argv, *, timeout_s):
        env = _env_from_argv(argv)
        canary = env["VF_CANARY"]
        mark = env["VF_ORACLE_MARK"]
        target = f"{canary}\n" if env.get("VF_TRIGGER") == "1" else ""
        code = 0 if env.get("VF_TRIGGER") != "1" else 1
        return {
            "exit_code": code,
            "timed_out": False,
            "spawn_error": None,
            "stdout": _framed(target, mark),
            "stderr": "",
            "duration_ms": 1,
            "argv": argv,
        }

    monkeypatch.setattr(pr, "spawn_captured", _spawn)
    monkeypatch.setattr(pr, "run_cleanup", lambda argv: None)
    result = execute_poc_for_pack(
        _pack(tmp_path),
        cfg={"poc_harness": {"runner": "gvisor", "oracle_k": 2}},
        hub_text=HUB,
        probe=_probe(),
    )
    assert result["verdict"] == "inconclusive"
    assert result["oracle"]["reason"] == "nonzero_exit"
    assert result["verdict"] != "signal_observed"


def test_flaky_k_runs_are_inconclusive(tmp_path: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    state = {"treatment": 0}

    def _spawn(argv, *, timeout_s):
        env = _env_from_argv(argv)
        canary = env["VF_CANARY"]
        mark = env["VF_ORACLE_MARK"]
        target = ""
        if env.get("VF_TRIGGER") == "1":
            state["treatment"] += 1
            if state["treatment"] == 1:
                target = f"{canary}\n"
        return {
            "exit_code": 0,
            "timed_out": False,
            "spawn_error": None,
            "stdout": _framed(target, mark),
            "stderr": "",
            "duration_ms": 1,
            "argv": argv,
        }

    monkeypatch.setattr(pr, "spawn_captured", _spawn)
    monkeypatch.setattr(pr, "run_cleanup", lambda argv: None)
    result = execute_poc_for_pack(
        _pack(tmp_path),
        cfg={"poc_harness": {"runner": "gvisor", "oracle_k": 2}},
        hub_text=HUB,
        probe=_probe(),
    )
    assert result["verdict"] == "inconclusive"
    assert result["oracle"]["reason"] == "flaky"
    assert result["oracle"]["treatment_hits"] == 1


def test_marker_in_source_or_args_is_poc_broken(tmp_path: Path, monkeypatch):
    import vulnforge.poc_runner as pr

    canary = "ab" * 16
    monkeypatch.setattr(pr, "mint_canary", lambda: canary)

    def _boom(*_a, **_k):
        raise AssertionError("sandbox must not run when the marker is known")

    monkeypatch.setattr(pr, "spawn_captured", _boom)
    leaked = _pack(tmp_path, f"print({canary!r})\n")
    result = execute_poc_for_pack(
        leaked,
        cfg={"poc_harness": {"runner": "gvisor"}},
        hub_text=HUB,
        probe=_probe(),
    )
    assert result["verdict"] == "poc_broken"
    assert result["oracle"]["reason"] == "marker_in_poc_source"
    assert result["verdict"] != "signal_observed"

    pack = _pack(tmp_path / "args", "print('ok')\n")
    hub = f"---\nrun: python poc.py {canary}\nsuccess_regex: ASSERT_OK\n---\n\n## Expected signal\nok\n"
    result = execute_poc_for_pack(
        pack,
        cfg={"poc_harness": {"runner": "gvisor"}},
        hub_text=hub,
        probe=_probe(),
    )
    assert result["verdict"] == "poc_broken"
    assert result["oracle"]["reason"] == "marker_in_args"


def test_judge_unit_and_fresh_canary():
    canary = mint_canary()
    other = mint_canary()
    assert canary != other
    assert len(canary) == 32
    pair = [
        _trial("treatment", target=canary + "\n"),
        _trial("control"),
    ]
    ok = judge_oracle_trials(pair, canary=canary, k=1)
    assert ok["verdict"] == "signal_observed"
    bad = judge_oracle_trials(
        [_trial("treatment", target=canary, exit_code=2), _trial("control")],
        canary=canary,
        k=1,
    )
    assert bad["verdict"] == "inconclusive"
    assert bad["reason"] == "nonzero_exit"
    leaked = judge_oracle_trials(
        [_trial("treatment", poc_out=canary), _trial("control")],
        canary=canary,
        k=1,
    )
    assert leaked["verdict"] == "inconclusive"
    assert leaked["reason"] == "marker_on_poc_stream"
    assert marker_in_poc_or_args("nope", Path("/no/such"), "python poc.py nope") == "marker_in_args"
