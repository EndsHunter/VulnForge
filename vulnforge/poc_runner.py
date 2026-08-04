"""Execute PoC scripts under controlled conditions (evidence pack only).

Default: local subprocess with timeout, cwd = evidence pack.
Optional: docker runner when ``poc_harness.runner: docker``.

Never writes to the audit target tree. Results are structured dicts for
``poc_run.json`` / validate_poc — never set finding ``confirmed``.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

from vulnforge.poc_handoff import (
    assess_poc_readiness,
    parse_hub_frontmatter,
    resolve_run_command,
    POC_DEVELOP_RELPATH,
)
from vulnforge.util import utc_now_iso

# Caps for stored run artifacts
MAX_CAPTURE_BYTES = 48_000
MAX_CAPTURE_CHARS = 24_000

VERDICTS = frozenset(
    {
        "signal_observed",
        "signal_absent",
        "poc_broken",
        "inconclusive",
        "unsafe_skipped",
    }
)


# Safe defaults: docker + network none. Operators opt into local_subprocess / network allow.
DEFAULT_POC_RUNNER = "docker"
DEFAULT_POC_NETWORK = "none"


def harness_config(cfg: dict | None) -> dict[str, Any]:
    raw = (cfg or {}).get("poc_harness") if cfg else None
    if not isinstance(raw, dict):
        raw = {}
    runner = str(raw.get("runner") or DEFAULT_POC_RUNNER).strip().lower()
    if runner in ("local", "subprocess"):
        runner = "local_subprocess"
    network = str(raw.get("network") or DEFAULT_POC_NETWORK).strip().lower()
    if network in ("off", "false", "0", "deny", "disabled"):
        network = "none"
    if network in ("on", "true", "1", "yes", "bridge"):
        network = "allow"
    return {
        "enabled": bool(raw.get("enabled", True)),
        "runner": runner or DEFAULT_POC_RUNNER,
        "timeout_s": int(raw.get("timeout_s") or 60),
        "network": network or DEFAULT_POC_NETWORK,
        "allow_write_target": bool(raw.get("allow_write_target", False)),
        "docker_image": str(raw.get("docker_image") or "python:3.12-slim").strip(),
        "python": str(raw.get("python") or "").strip() or sys.executable,
    }


def docker_available() -> bool:
    return bool(shutil.which("docker"))


def _truncate(s: str, max_chars: int = MAX_CAPTURE_CHARS) -> str:
    if len(s) <= max_chars:
        return s
    return s[: max_chars - 1] + "…"


def _capture_to_text(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        if len(raw) > MAX_CAPTURE_BYTES:
            raw = raw[:MAX_CAPTURE_BYTES]
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return repr(raw[:200])
    return _truncate(str(raw))


def _split_command(cmd: str) -> list[str]:
    """Split a shell-ish command into argv; best-effort on Windows."""
    cmd = (cmd or "").strip()
    if not cmd:
        return []
    if os.name == "nt":
        try:
            return shlex.split(cmd, posix=False)
        except ValueError:
            return cmd.split()
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        return cmd.split()


def _normalize_argv(argv: list[str], *, python_exe: str, pack_dir: Path) -> list[str]:
    """Map ``python`` token to real interpreter; leave paths as-is."""
    if not argv:
        return argv
    out = list(argv)
    head = out[0].lower()
    if head in ("python", "python3", "py"):
        out[0] = python_exe
    # Expand bare script names that live in pack
    if len(out) >= 2:
        script = out[1]
        if not Path(script).is_absolute():
            cand = pack_dir / Path(script).name
            if cand.is_file() and Path(script).name == Path(script).as_posix().split("/")[-1]:
                # keep relative name so cwd=pack works
                out[1] = Path(script).name
    return out


def _match_signal(stdout: str, stderr: str, success_regex: str | None) -> bool | None:
    if not success_regex:
        return None
    try:
        pat = re.compile(success_regex, re.MULTILINE | re.DOTALL)
    except re.error:
        # treat as literal substring
        blob = stdout + "\n" + stderr
        return success_regex in blob
    blob = stdout + "\n" + stderr
    return bool(pat.search(blob))


def classify_run_result(
    *,
    ran: bool,
    exit_code: int | None,
    timed_out: bool,
    spawn_error: str | None,
    signal_matched: bool | None,
    skipped_reason: str | None = None,
) -> str:
    if skipped_reason:
        return "unsafe_skipped"
    if spawn_error or timed_out:
        return "poc_broken"
    if not ran:
        return "poc_broken"
    if signal_matched is True:
        return "signal_observed"
    if signal_matched is False:
        return "signal_absent"
    # No success_regex
    if exit_code == 0:
        return "inconclusive"
    return "poc_broken"


def run_poc_local(
    pack_dir: Path,
    command: str,
    *,
    timeout_s: int = 60,
    env_extra: Optional[dict[str, str]] = None,
    python_exe: str | None = None,
) -> dict[str, Any]:
    """Run command with cwd=pack_dir. shell=False after argv split."""
    pack_dir = Path(pack_dir).resolve()
    if not pack_dir.is_dir():
        return {
            "ran": False,
            "exit_code": None,
            "timed_out": False,
            "spawn_error": f"pack_missing:{pack_dir}",
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "argv": [],
            "runner": "local_subprocess",
        }

    py = python_exe or sys.executable
    argv = _normalize_argv(_split_command(command), python_exe=py, pack_dir=pack_dir)
    if not argv:
        return {
            "ran": False,
            "exit_code": None,
            "timed_out": False,
            "spawn_error": "empty_command",
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "argv": [],
            "runner": "local_subprocess",
        }

    # Minimal env: inherit PATH etc. but allow pack-local overrides
    env = os.environ.copy()
    env["VF_POC_PACK"] = str(pack_dir)
    env["PYTHONUNBUFFERED"] = "1"
    if env_extra:
        for k, v in env_extra.items():
            if k and v is not None:
                env[str(k)] = str(v)

    t0 = time.perf_counter()
    timed_out = False
    spawn_error = None
    exit_code: int | None = None
    stdout = ""
    stderr = ""
    try:
        proc = subprocess.run(
            argv,
            cwd=str(pack_dir),
            capture_output=True,
            timeout=max(1, int(timeout_s)),
            env=env,
            shell=False,
            check=False,
        )
        exit_code = int(proc.returncode)
        stdout = _capture_to_text(proc.stdout)
        stderr = _capture_to_text(proc.stderr)
    except subprocess.TimeoutExpired as e:
        timed_out = True
        stdout = _capture_to_text(e.stdout)
        stderr = _capture_to_text(e.stderr) or "timeout"
        spawn_error = f"timeout_after_{timeout_s}s"
    except OSError as e:
        spawn_error = f"spawn_error:{e}"
    except Exception as e:  # noqa: BLE001
        spawn_error = f"run_error:{e}"

    duration_ms = int((time.perf_counter() - t0) * 1000)
    return {
        "ran": spawn_error is None or timed_out,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "spawn_error": spawn_error,
        "stdout": stdout,
        "stderr": stderr,
        "duration_ms": duration_ms,
        "argv": argv,
        "cwd": str(pack_dir),
        "runner": "local_subprocess",
    }


def run_poc_docker(
    pack_dir: Path,
    command: str,
    *,
    image: str,
    timeout_s: int = 60,
    network: str = "none",
    env_extra: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    """Run command inside docker with pack mounted at /work."""
    pack_dir = Path(pack_dir).resolve()
    if not shutil.which("docker"):
        return {
            "ran": False,
            "exit_code": None,
            "timed_out": False,
            "spawn_error": "docker_not_found",
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "argv": [],
            "runner": "docker",
        }
    if not pack_dir.is_dir():
        return {
            "ran": False,
            "exit_code": None,
            "timed_out": False,
            "spawn_error": f"pack_missing:{pack_dir}",
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "argv": [],
            "runner": "docker",
        }

    net = "none" if str(network).lower() in ("none", "off", "false", "0") else "bridge"
    docker_argv = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{pack_dir}:/work:ro",
        "-w",
        "/work",
        f"--network={net}",
        # writable tmp for compile artifacts etc.
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
    ]
    if env_extra:
        for k, v in env_extra.items():
            if k:
                docker_argv.extend(["-e", f"{k}={v}"])
    docker_argv.append(image)
    # Run via sh -c for multi-step commands (gcc && ./a.out)
    docker_argv.extend(["sh", "-c", command])

    t0 = time.perf_counter()
    timed_out = False
    spawn_error = None
    exit_code: int | None = None
    stdout = ""
    stderr = ""
    try:
        proc = subprocess.run(
            docker_argv,
            capture_output=True,
            timeout=max(1, int(timeout_s)) + 15,  # pull headroom
            shell=False,
            check=False,
        )
        exit_code = int(proc.returncode)
        stdout = _capture_to_text(proc.stdout)
        stderr = _capture_to_text(proc.stderr)
    except subprocess.TimeoutExpired as e:
        timed_out = True
        stdout = _capture_to_text(e.stdout)
        stderr = _capture_to_text(e.stderr) or "timeout"
        spawn_error = f"timeout_after_{timeout_s}s"
    except OSError as e:
        spawn_error = f"spawn_error:{e}"
    except Exception as e:  # noqa: BLE001
        spawn_error = f"run_error:{e}"

    duration_ms = int((time.perf_counter() - t0) * 1000)
    return {
        "ran": spawn_error is None or timed_out,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "spawn_error": spawn_error,
        "stdout": stdout,
        "stderr": stderr,
        "duration_ms": duration_ms,
        "argv": docker_argv,
        "cwd": "/work",
        "runner": "docker",
        "docker_image": image,
        "docker_network": net,
    }


def execute_poc_for_pack(
    pack_dir: Path,
    *,
    cfg: dict | None = None,
    hub_text: str = "",
    env_extra: Optional[dict[str, str]] = None,
    finding_body: Optional[dict[str, Any]] = None,
    finding_id: int | None = None,
    force_command: str | None = None,
) -> dict[str, Any]:
    """Full pipeline: readiness → run → classify → result dict for poc_run.json."""
    hc = harness_config(cfg)
    pack_dir = Path(pack_dir)
    if not hub_text and (pack_dir / POC_DEVELOP_RELPATH).is_file():
        try:
            hub_text = (pack_dir / POC_DEVELOP_RELPATH).read_text(encoding="utf-8")
        except OSError:
            hub_text = ""

    readiness = assess_poc_readiness(
        finding_body=finding_body or {},
        pack_dir=pack_dir,
        hub_text=hub_text,
    )
    meta, _ = parse_hub_frontmatter(hub_text or "")
    command = (force_command or readiness.get("run_command") or "").strip()
    if not command:
        command, _ = resolve_run_command(meta, pack_dir)
        command = (command or "").strip()

    timeout_s = int(meta.get("timeout_s") or hc["timeout_s"] or 60)
    # Hub frontmatter may opt into network: allow; config default is none.
    network = str(meta.get("network") or hc["network"] or DEFAULT_POC_NETWORK).lower()
    if network in ("off", "false", "0", "deny", "disabled"):
        network = "none"
    if network in ("on", "true", "1", "yes", "bridge"):
        network = "allow"
    success_regex = str(meta.get("success_regex") or readiness.get("success_regex") or "").strip() or None

    env_merged: dict[str, str] = {}
    if isinstance(meta.get("env"), dict):
        env_merged.update({str(k): str(v) for k, v in meta["env"].items()})
    if env_extra:
        env_merged.update({str(k): str(v) for k, v in env_extra.items()})

    skipped_reason = None
    operator_hint: str | None = None
    if not hc["enabled"]:
        skipped_reason = "harness_disabled"
        operator_hint = "Set poc_harness.enabled: true (or force) to run the harness."
    elif not command:
        skipped_reason = "no_run_command"
        operator_hint = "Set hub frontmatter run: or an entry script in the evidence pack."
    elif readiness.get("issues") and "missing_poc_code" in (readiness.get("issues") or []):
        skipped_reason = "missing_poc_code"
        operator_hint = "Add runnable PoC code under the evidence pack (e.g. poc.py)."
    elif hc["runner"] == "docker" and not docker_available():
        skipped_reason = "docker_not_found"
        operator_hint = (
            "Docker not on PATH. Install Docker, or set poc_harness.runner: local_subprocess "
            "in config/default.yaml (less isolated; network not restricted)."
        )

    if skipped_reason:
        result = {
            "ran": False,
            "exit_code": None,
            "timed_out": False,
            "spawn_error": skipped_reason,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "argv": [],
            "runner": hc["runner"],
        }
    elif hc["runner"] == "docker":
        # Docker mount is read-only; multi-step compile may need /tmp — handled in runner
        result = run_poc_docker(
            pack_dir,
            command,
            image=hc["docker_image"],
            timeout_s=timeout_s,
            network=network,
            env_extra=env_merged or None,
        )
        if result.get("spawn_error") == "docker_not_found":
            # Race: docker vanished between check and run
            skipped_reason = "docker_not_found"
            operator_hint = (
                "Docker not on PATH. Install Docker, or set poc_harness.runner: "
                "local_subprocess in config."
            )
    else:
        result = run_poc_local(
            pack_dir,
            command,
            timeout_s=timeout_s,
            env_extra=env_merged or None,
            python_exe=hc["python"],
        )

    signal_matched = _match_signal(
        result.get("stdout") or "",
        result.get("stderr") or "",
        success_regex,
    )
    spawn_err = result.get("spawn_error")
    if spawn_err == "docker_not_found" and skipped_reason != "docker_not_found":
        skipped_reason = "docker_not_found"
        operator_hint = operator_hint or (
            "Docker not on PATH. Set poc_harness.runner: local_subprocess to run locally."
        )

    # Config / environment skips vs broken PoC code
    if skipped_reason in ("harness_disabled", "docker_not_found"):
        verdict = "unsafe_skipped"
    elif skipped_reason in ("no_run_command", "missing_poc_code"):
        verdict = "poc_broken"
    else:
        verdict = classify_run_result(
            ran=bool(result.get("ran")) and not spawn_err,
            exit_code=result.get("exit_code"),
            timed_out=bool(result.get("timed_out")),
            spawn_error=spawn_err,
            signal_matched=signal_matched,
            skipped_reason=None,
        )
        if result.get("timed_out"):
            verdict = "poc_broken"
        if spawn_err and verdict != "unsafe_skipped":
            verdict = "poc_broken"

    suggested = {
        "signal_observed": "needs_human_with_notes",
        "signal_absent": "review_or_reject",
        "poc_broken": "fix_poc",
        "inconclusive": "add_success_signal",
        "unsafe_skipped": "enable_or_configure_harness",
    }.get(verdict, "needs_human")
    if skipped_reason == "docker_not_found":
        suggested = "install_docker_or_set_local_subprocess"

    out = {
        "schema": "vulnforge.poc_run.v1",
        "at": utc_now_iso(),
        "finding_id": finding_id,
        "verdict": verdict,
        "confidence": "medium" if verdict == "signal_observed" else "low",
        "command": command,
        "success_regex": success_regex,
        "signal_matched": signal_matched,
        "timeout_s": timeout_s,
        "network": network,
        "readiness": readiness,
        "runner": result.get("runner") or hc["runner"],
        "harness": {
            "runner": hc["runner"],
            "network": network,
            "timeout_s": timeout_s,
            "docker_image": hc["docker_image"] if hc["runner"] == "docker" else None,
            "docker_available": docker_available() if hc["runner"] == "docker" else None,
        },
        "ran": bool(result.get("ran")),
        "exit_code": result.get("exit_code"),
        "timed_out": bool(result.get("timed_out")),
        "spawn_error": result.get("spawn_error"),
        "duration_ms": result.get("duration_ms"),
        "argv": result.get("argv"),
        "stdout_excerpt": _truncate(result.get("stdout") or "", 8000),
        "stderr_excerpt": _truncate(result.get("stderr") or "", 4000),
        "suggested_finding_action": suggested,
        "operator_hint": operator_hint,
        "caveats": [
            "PoC execution is not exploit proof of production impact.",
            "confirmed remains human-only.",
            "Default harness is docker with network=none; hub frontmatter may set network: allow.",
        ],
        "docker_image": result.get("docker_image"),
        "docker_network": result.get("docker_network"),
    }
    return out
