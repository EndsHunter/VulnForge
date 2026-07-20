"""Ralph outer-loop helpers (import scripts/ralph.py without package install)."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
RALPH_PATH = ROOT / "scripts" / "ralph.py"


def _load_ralph():
    name = "VF_ralph_script"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, RALPH_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _base_cfg(ralph, *, run_dir: Path | None, **overrides):
    base = dict(
        run_dir=run_dir,
        max_iterations=10,
        max_infra_retries=5,
        sleep_seconds=0,
        infra_backoff_base=1.0,
        vf_command=[sys.executable, "-m", "vulnforge.cli"],
        stop_file=(run_dir / "STOP") if run_dir is not None else None,
        config_path=None,
        dry_run=False,
        verbose=False,
        task_timeout=None,
        max_wall_seconds=None,
        max_tasks=None,
    )
    base.update(overrides)
    return ralph.RalphConfig(**base)


def test_project_on_stop_invokes_vf_project(tmp_path: Path, monkeypatch):
    """P0.4: halt paths call vf project best-effort."""
    ralph = _load_ralph()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    calls: list[list[str]] = []
    kwargs_list: list[dict] = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        kwargs_list.append(kwargs)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    cfg = _base_cfg(ralph, run_dir=run_dir)
    ralph.project_on_stop(cfg, "infra_give_up")
    assert calls, "expected subprocess.run for vf project"
    assert "project" in calls[0]
    assert "--run-dir" in calls[0]
    assert str(run_dir) in calls[0]
    if os.name == "nt":
        flags = kwargs_list[0].get("creationflags", 0)
        no_win = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        assert flags & no_win, "Windows project-on-stop should hide console"
    else:
        assert "creationflags" not in kwargs_list[0]
    events = (run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert "project_on_stop" in events
    assert "infra_give_up" in events


def test_invoke_run_once_hides_console_on_windows(tmp_path: Path, monkeypatch):
    """Each vf run-once child should use CREATE_NO_WINDOW on Windows."""
    ralph = _load_ralph()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    kwargs_list: list[dict] = []

    def fake_run(argv, **kwargs):
        kwargs_list.append(kwargs)
        return SimpleNamespace(returncode=ralph.EXIT_IDLE, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    cfg = _base_cfg(ralph, run_dir=run_dir, task_timeout=30.0)
    code = ralph.invoke_run_once(cfg)
    assert code == ralph.EXIT_IDLE
    assert kwargs_list, "expected subprocess.run"
    if os.name == "nt":
        flags = kwargs_list[0].get("creationflags", 0)
        no_win = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        assert flags & no_win
    else:
        assert "creationflags" not in kwargs_list[0]


def test_subprocess_no_window_kwargs_shape(monkeypatch):
    ralph = _load_ralph()
    monkeypatch.setattr(ralph.os, "name", "nt")
    kw = ralph._subprocess_no_window_kwargs()
    assert "creationflags" in kw
    no_win = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    assert kw["creationflags"] & no_win
    monkeypatch.setattr(ralph.os, "name", "posix")
    assert ralph._subprocess_no_window_kwargs() == {}


def test_project_on_stop_skips_without_run_dir(monkeypatch):
    ralph = _load_ralph()
    called = {"n": 0}

    def fake_run(*_a, **_k):
        called["n"] += 1
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    cfg = ralph.RalphConfig(
        run_dir=None,
        max_iterations=1,
        max_infra_retries=5,
        sleep_seconds=0,
        infra_backoff_base=1.0,
        vf_command=[sys.executable, "-m", "vulnforge.cli"],
        stop_file=None,
        config_path=None,
        dry_run=False,
        verbose=False,
        task_timeout=None,
        max_wall_seconds=None,
        max_tasks=None,
    )
    ralph.project_on_stop(cfg, "stop_file")
    assert called["n"] == 0


def test_busy_does_not_burn_max_iterations(tmp_path: Path, monkeypatch):
    """Multi-worker: many EXIT_BUSY waits must not exhaust max_iterations.

    Repro: agent 2 busy-loops while recon is leased (~1 call/sec). With
    max_iterations=200 it used to exit progress_count=0 before hunts enqueue;
    stop+start then ran both agents because work was already queued.
    """
    ralph = _load_ralph()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    codes = [ralph.EXIT_BUSY] * 25 + [ralph.EXIT_PROGRESS, ralph.EXIT_IDLE]
    calls = {"n": 0}

    def fake_invoke(_cfg):
        i = calls["n"]
        calls["n"] += 1
        return codes[i] if i < len(codes) else ralph.EXIT_IDLE

    monkeypatch.setattr(ralph, "invoke_run_once", fake_invoke)
    # Avoid project-on-stop noise if budget path were taken incorrectly
    monkeypatch.setattr(ralph, "project_on_stop", lambda *_a, **_k: None)

    cfg = ralph.RalphConfig(
        run_dir=run_dir,
        max_iterations=3,  # would die if BUSY charged iterations
        max_infra_retries=5,
        sleep_seconds=0,
        infra_backoff_base=1.0,
        vf_command=[sys.executable, "-m", "vulnforge.cli"],
        stop_file=run_dir / "STOP",
        config_path=None,
        dry_run=False,
        verbose=False,
        task_timeout=None,
        max_wall_seconds=None,
        max_tasks=50,
    )
    code = ralph.run_loop(cfg)
    assert code == ralph.RALPH_IDLE
    assert calls["n"] == 27  # 25 busy + 1 progress + 1 idle
    events = (run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert "budget_iterations" not in events
    assert '"event": "idle"' in events
