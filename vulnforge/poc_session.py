"""Long-lived PoC sandbox session. Rewrite and re-run inside one isolation boundary.

Same ladder as the one-shot runner: microVM (Kata / patched Firecracker) →
gVisor ``runsc`` → refuse. No host exec, no plain runc, no silent fallback.

A session pins one guest. Kata and gVisor keep a detached container and
``docker exec`` each cycle into it. Direct Firecracker pins the same patched
jailer policy (no NIC, ``pci=off``) and boots one VM per cycle, because the
guest contract is kernel cmdline only.

Caps (default 5 rewrite/re-run cycles, 15-minute wall TTL) end the session.
Nothing here sets ``confirmed`` or clears ``needs_human``.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from vulnforge.languages import POC_CODE_EXTS
from vulnforge.poc_handoff import (
    POC_DEVELOP_RELPATH,
    assess_poc_readiness,
    parse_hub_frontmatter,
    resolve_run_command,
)
from vulnforge.poc_runner import (
    SANDBOX_MISSING_HINT,
    VERDICTS,
    _docker_binary_missing,
    _empty_result,
    _looks_like_build_failure,
    _looks_like_missing_runtime,
    _match_signal,
    _truncate,
    build_session_docker_argv,
    build_session_exec_argv,
    classify_run_result,
    harness_config,
    run_cleanup,
    run_sandbox_firecracker,
    scrub_guest_env,
    select_isolation,
    spawn_captured,
)
from vulnforge.util import utc_now_iso

SESSION_RELPATH = "poc_session.json"
STEER_RELPATH = "poc_steer.jsonl"
CTL_RELPATH = "poc_session_ctl.json"
WORK_DIRNAME = "poc_session_work"
LOCK_NAME = "poc_session.lock"
SCHEMA = "vulnforge.poc_session.v1"

_SKIP_COPY = frozenset(
    {
        SESSION_RELPATH,
        STEER_RELPATH,
        CTL_RELPATH,
        LOCK_NAME,
        "poc_run.json",
        WORK_DIRNAME,
    }
)
_MAX_REWRITE_FILES = 8
_MAX_REWRITE_CHARS = 200_000
_MAX_COMMAND_CHARS = 4_000


class GuestStartError(RuntimeError):
    def __init__(self, message: str, verdict: str = "sandbox_unavailable") -> None:
        super().__init__(message)
        self.verdict = verdict


def _epoch_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _lock(pack_dir: Path):
    pack_dir.mkdir(parents=True, exist_ok=True)
    fh = open(pack_dir / LOCK_NAME, "a+", encoding="utf-8")
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    return fh


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


def load_session(pack_dir: Path) -> dict[str, Any] | None:
    path = Path(pack_dir) / SESSION_RELPATH
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def read_steers(pack_dir: Path) -> list[dict[str, Any]]:
    path = Path(pack_dir) / STEER_RELPATH
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("text"):
            out.append(item)
    return out


def append_steer(pack_dir: Path, text: str, *, operator: str = "operator") -> dict[str, Any]:
    """Queue a human steer for the next cycle inside this session.

    Refuses when the session has already ended. Does not execute anything.
    """
    pack_dir = Path(pack_dir)
    message = (text or "").strip()
    if not message:
        return {"ok": False, "error": "empty_steer"}
    message = message[:4000]
    fh = _lock(pack_dir)
    try:
        session = load_session(pack_dir)
        if session is not None and session.get("state") == "ended":
            return {"ok": False, "error": "session_ended", "session": public_session(session)}
        existing = read_steers(pack_dir)
        seq = 1 + max((int(s.get("seq") or 0) for s in existing), default=0)
        item = {
            "seq": seq,
            "at": utc_now_iso(),
            "operator": (operator or "operator")[:80],
            "text": message,
        }
        with (pack_dir / STEER_RELPATH).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(item) + "\n")
        return {"ok": True, "steer": item}
    finally:
        fh.close()


def request_stop(pack_dir: Path, *, operator: str = "operator") -> dict[str, Any]:
    """Ask the live session to stop after the current cycle. Not a host kill of the PoC."""
    pack_dir = Path(pack_dir)
    fh = _lock(pack_dir)
    try:
        session = load_session(pack_dir)
        if session is not None and session.get("state") == "ended":
            return {"ok": False, "error": "session_ended", "session": public_session(session)}
        ctl = {
            "stop": True,
            "at": utc_now_iso(),
            "operator": (operator or "operator")[:80],
        }
        _write_json(pack_dir / CTL_RELPATH, ctl)
        return {"ok": True, "control": ctl}
    finally:
        fh.close()


def stop_requested(pack_dir: Path) -> bool:
    path = Path(pack_dir) / CTL_RELPATH
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return bool(isinstance(data, dict) and data.get("stop"))


def public_session(session: dict[str, Any] | None) -> dict[str, Any] | None:
    if not session:
        return None
    cycles = session.get("cycles") if isinstance(session.get("cycles"), list) else []
    view_cycles = []
    for cycle in cycles:
        if not isinstance(cycle, dict):
            continue
        view_cycles.append(
            {
                "n": cycle.get("n"),
                "at": cycle.get("at"),
                "verdict": cycle.get("verdict"),
                "exit_code": cycle.get("exit_code"),
                "signal_matched": cycle.get("signal_matched"),
                "stdout_excerpt": cycle.get("stdout_excerpt") or "",
                "stderr_excerpt": cycle.get("stderr_excerpt") or "",
                "rewrite_files": cycle.get("rewrite_files") or [],
                "steer_seqs": cycle.get("steer_seqs") or [],
                "spawn_error": cycle.get("spawn_error"),
                "guest_id": cycle.get("guest_id"),
                "runtime": cycle.get("runtime"),
                "isolation": cycle.get("isolation"),
            }
        )
    return {
        "schema": session.get("schema") or SCHEMA,
        "session_id": session.get("session_id"),
        "finding_id": session.get("finding_id"),
        "state": session.get("state"),
        "end_reason": session.get("end_reason"),
        "started_at": session.get("started_at"),
        "deadline_at": session.get("deadline_at"),
        "ended_at": session.get("ended_at"),
        "max_cycles": session.get("max_cycles"),
        "wall_ttl_min": session.get("wall_ttl_min"),
        "cycles_run": len(view_cycles),
        "isolation": session.get("isolation"),
        "runtime": session.get("runtime"),
        "guest_id": session.get("guest_id"),
        "hold_mode": session.get("hold_mode"),
        "guest_sees_workspace": session.get("guest_sees_workspace"),
        "network": session.get("network"),
        "verdict": session.get("verdict"),
        "operator_hint": session.get("operator_hint"),
        "confirms_finding": False,
        "clears_needs_human": False,
        "skips_hitl": False,
        "host_exec": False,
        "cycles": view_cycles,
    }


def _safe_code_path(pack_dir: Path, rel: str) -> Path:
    raw = str(rel or "").replace("\\", "/").strip()
    if not raw or raw.startswith("/") or ".." in Path(raw).parts:
        raise ValueError(f"rewrite_path_refused:{rel}")
    path = Path(raw)
    if path.suffix.lower() not in POC_CODE_EXTS:
        raise ValueError(f"rewrite_ext_refused:{rel}")
    if path.name in _SKIP_COPY:
        raise ValueError(f"rewrite_name_refused:{rel}")
    dest = (pack_dir / path).resolve()
    root = pack_dir.resolve()
    if dest != root and root not in dest.parents:
        raise ValueError(f"rewrite_path_refused:{rel}")
    return dest


def apply_pack_rewrite(pack_dir: Path, files: dict[str, Any] | None) -> list[str]:
    """Write agent rewrite files into the evidence pack. Does not execute them."""
    if not files:
        return []
    if len(files) > _MAX_REWRITE_FILES:
        raise ValueError("rewrite_too_many_files")
    written: list[str] = []
    for rel, content in files.items():
        text = str(content if content is not None else "")
        if len(text) > _MAX_REWRITE_CHARS:
            raise ValueError(f"rewrite_too_large:{rel}")
        dest = _safe_code_path(pack_dir, str(rel))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
        written.append(str(rel).replace("\\", "/"))
    return written


def sync_workspace(pack_dir: Path, work: Path) -> None:
    """Refresh the guest-visible workspace from pack files. Skips session records.

    Updates files in place. The directory itself stays put so a live container
    mount is not detached.
    """
    work.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        os.chmod(work, 0o700)
    except OSError:
        pass
    keep: set[str] = set()
    for entry in pack_dir.iterdir():
        if entry.name in _SKIP_COPY or entry.name.startswith("."):
            continue
        if not entry.is_file():
            continue
        keep.add(entry.name)
        shutil.copy2(entry, work / entry.name)
    for existing in list(work.iterdir()):
        if existing.is_file() and existing.name not in keep:
            try:
                existing.unlink()
            except OSError:
                pass


def _blank_session(
    *,
    session_id: str,
    finding_id: int | None,
    max_cycles: int,
    wall_ttl_min: int,
    started: float,
    command: str,
    network: str,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "session_id": session_id,
        "finding_id": finding_id,
        "state": "live",
        "end_reason": None,
        "started_at": _epoch_iso(started),
        "started_epoch": started,
        "deadline_at": _epoch_iso(started + wall_ttl_min * 60),
        "deadline_epoch": started + wall_ttl_min * 60,
        "ended_at": None,
        "max_cycles": max_cycles,
        "wall_ttl_min": wall_ttl_min,
        "command": command,
        "network": network,
        "isolation": None,
        "runtime": None,
        "guest_id": None,
        "hold_mode": None,
        "guest_sees_workspace": None,
        "verdict": None,
        "operator_hint": None,
        "cycles": [],
        "confirms_finding": False,
        "clears_needs_human": False,
        "skips_hitl": False,
        "host_exec": False,
        "caveats": [
            "Sandbox iterate output is evidence only. It does not confirm the finding.",
            "confirmed stays human-only. needs_human and HITL are unchanged.",
            "Hitting the rewrite-cycle cap or the wall TTL ends the session and does not confirm.",
            "Cycles run only in a microVM (Kata or patched Firecracker) or gVisor runsc.",
        ],
    }


def _persist(pack_dir: Path, session: dict[str, Any]) -> None:
    _write_json(pack_dir / SESSION_RELPATH, session)


def _finish(
    session: dict[str, Any],
    *,
    reason: str,
    verdict: str | None,
    hint: str | None,
    now: float,
) -> None:
    if session.get("state") == "ended":
        return
    session["state"] = "ended"
    session["end_reason"] = reason
    session["ended_at"] = _epoch_iso(now)
    if verdict:
        session["verdict"] = verdict
    if hint and not session.get("operator_hint"):
        session["operator_hint"] = hint
    session["confirms_finding"] = False
    session["clears_needs_human"] = False
    session["skips_hitl"] = False
    session["host_exec"] = False


class DockerGuestDriver:
    """Hold one Kata or runsc container. Cycles are ``docker exec`` into it."""

    def start(self, spec: dict[str, Any]) -> dict[str, Any]:
        self.spec = dict(spec)
        argv = build_session_docker_argv(
            name=spec["guest_id"],
            workspace=Path(spec["workspace"]),
            image=spec["image"],
            runtime=spec["runtime"],
            network=spec["network"],
            cpus=spec["cpus"],
            memory=spec["memory"],
            pids_limit=int(spec["pids_limit"]),
            sleep_s=int(spec["sleep_s"]),
            target_path=spec.get("target_path"),
            mount_target_ro=bool(spec.get("mount_target_ro")),
            env=spec.get("env") or None,
        )
        captured = spawn_captured(argv, timeout_s=min(60, max(5, int(spec["sleep_s"]))))
        if captured.get("spawn_error") or captured.get("exit_code") not in (0, None):
            run_cleanup(["docker", "rm", "-f", spec["guest_id"]])
            err = captured.get("spawn_error") or f"exit_{captured.get('exit_code')}"
            verdict = "sandbox_unavailable"
            if "runtime_refused" in str(err) or "host_network" in str(err):
                verdict = "unsafe_skipped"
            raise GuestStartError(str(err), verdict)
        return {
            "guest_id": spec["guest_id"],
            "hold_mode": "container",
            "guest_sees_workspace": True,
        }

    def sync(self, guest_id: str, workspace: Path) -> None:
        del guest_id, workspace

    def exec(self, guest_id: str, command: str, timeout_s: int, env: dict[str, str] | None) -> dict[str, Any]:
        argv = build_session_exec_argv(name=guest_id, command=command, env=env)
        captured = spawn_captured(argv, timeout_s=max(1, int(timeout_s)))
        captured["argv"] = argv
        captured["ran"] = captured.get("spawn_error") is None or bool(captured.get("timed_out"))
        return captured

    def stop(self, guest_id: str) -> None:
        if not guest_id:
            return
        run_cleanup(["docker", "kill", guest_id])
        run_cleanup(["docker", "rm", "-f", guest_id])


class FirecrackerGuestDriver:
    """One session boundary. Each cycle boots a VM with the pinned jailer plan."""

    def start(self, spec: dict[str, Any]) -> dict[str, Any]:
        self.spec = dict(spec)
        if spec.get("runtime") != "firecracker":
            raise GuestStartError(f"runtime_refused:{spec.get('runtime')}", "unsafe_skipped")
        return {
            "guest_id": spec["guest_id"],
            "hold_mode": "per_cycle_vm",
            "guest_sees_workspace": False,
        }

    def sync(self, guest_id: str, workspace: Path) -> None:
        del guest_id, workspace

    def exec(self, guest_id: str, command: str, timeout_s: int, env: dict[str, str] | None) -> dict[str, Any]:
        del guest_id, env
        spec = self.spec
        return run_sandbox_firecracker(
            Path(spec["pack_dir"]),
            command,
            kernel=str(spec.get("kernel") or ""),
            rootfs=str(spec.get("rootfs") or ""),
            fc_bin=str(spec.get("firecracker_path") or ""),
            jail_bin=str(spec.get("jailer_path") or ""),
            memory=str(spec.get("memory") or "512m"),
            timeout_s=max(1, int(timeout_s)),
        )

    def stop(self, guest_id: str) -> None:
        del guest_id


def driver_for(choice: dict[str, Any]) -> Any:
    if choice.get("backend") == "firecracker" or choice.get("isolation") == "firecracker":
        return FirecrackerGuestDriver()
    return DockerGuestDriver()


def _resolve_command(pack_dir: Path, hub_text: str, finding_body: dict, force_command: str | None, hc: dict) -> tuple[str, dict, str, str | None]:
    readiness = assess_poc_readiness(
        finding_body=finding_body or {},
        pack_dir=pack_dir,
        hub_text=hub_text,
    )
    meta, _body = parse_hub_frontmatter(hub_text or "")
    command = (force_command or readiness.get("run_command") or "").strip()
    if not command:
        command, _why = resolve_run_command(meta, pack_dir)
        command = (command or "").strip()
    network = str(meta.get("network") or hc["network"] or "none").lower()
    if network in ("off", "false", "0", "deny", "disabled"):
        network = "none"
    if network in ("on", "true", "1", "yes", "bridge"):
        network = "allow"
    if network in ("host", "hostnet", "host-net"):
        network = "host"
    success = str(meta.get("success_regex") or readiness.get("success_regex") or "").strip() or None
    return command, readiness, network, success


def _cycle_verdict(result: dict[str, Any], success_regex: str | None) -> tuple[str, bool | None]:
    signal = _match_signal(result.get("stdout") or "", result.get("stderr") or "", success_regex)
    spawn_err = result.get("spawn_error")
    if str(spawn_err or "").startswith("unsafe_mount") or "host_network" in str(spawn_err or ""):
        return "unsafe_skipped", signal
    if _looks_like_build_failure(result):
        return "build_failed", signal
    if _looks_like_missing_runtime(result) or _docker_binary_missing(result):
        return "sandbox_unavailable", signal
    verdict = classify_run_result(
        ran=bool(result.get("ran")) and not spawn_err,
        exit_code=result.get("exit_code"),
        timed_out=bool(result.get("timed_out")),
        spawn_error=spawn_err,
        signal_matched=signal,
        skipped_reason=None,
    )
    if result.get("timed_out"):
        verdict = "poc_broken"
    if spawn_err and verdict not in ("unsafe_skipped", "sandbox_unavailable", "build_failed"):
        verdict = "poc_broken"
    if verdict not in VERDICTS:
        verdict = "inconclusive"
    return verdict, signal


def run_iterate_session(
    pack_dir: Path,
    *,
    cfg: dict | None = None,
    hub_text: str = "",
    finding_body: dict[str, Any] | None = None,
    finding_id: int | None = None,
    force_command: str | None = None,
    target_path: str | Path | None = None,
    env_extra: dict[str, str] | None = None,
    probe: dict[str, Any] | None = None,
    driver: Any | None = None,
    rewriter: Callable[..., Any] | None = None,
    now_fn: Callable[[], float] | None = None,
    operator: str = "agent",
    operator_notes: str = "",
) -> dict[str, Any]:
    """Open one sandbox session and cycle until success, cap, TTL, or stop.

    Does not touch finding state or HITL.
    """
    pack_dir = Path(pack_dir)
    pack_dir.mkdir(parents=True, exist_ok=True)
    hc = harness_config(cfg)
    clock = now_fn or time.time
    if not hub_text and (pack_dir / POC_DEVELOP_RELPATH).is_file():
        try:
            hub_text = (pack_dir / POC_DEVELOP_RELPATH).read_text(encoding="utf-8")
        except OSError:
            hub_text = ""
    command, readiness, network, success_regex = _resolve_command(
        pack_dir, hub_text, finding_body or {}, force_command, hc
    )
    if len(command) > _MAX_COMMAND_CHARS:
        command = command[:_MAX_COMMAND_CHARS]
    meta, _rest = parse_hub_frontmatter(hub_text or "")
    env_merged: dict[str, str] = {}
    if isinstance(meta.get("env"), dict):
        env_merged.update({str(k): str(v) for k, v in meta["env"].items()})
    if env_extra:
        env_merged.update({str(k): str(v) for k, v in env_extra.items()})
    env_merged, env_dropped = scrub_guest_env(env_merged)

    started = float(clock())
    session_id = uuid.uuid4().hex[:12]
    max_cycles = int(hc["iterate_max_cycles"])
    wall_ttl_min = int(hc["iterate_wall_ttl_min"])
    session = _blank_session(
        session_id=session_id,
        finding_id=finding_id,
        max_cycles=max_cycles,
        wall_ttl_min=wall_ttl_min,
        started=started,
        command=command,
        network="none" if network != "allow" else "allow",
    )
    session["readiness"] = {
        "ready": bool(readiness.get("ready")),
        "issues": list(readiness.get("issues") or []),
    }
    session["env_dropped"] = env_dropped
    session["operator"] = operator or "agent"

    notes = (operator_notes or "").strip()
    if notes:
        append_steer(pack_dir, notes, operator=operator or "operator")

    guest = None
    guest_id = ""
    choice: dict[str, Any] = {"ok": False}

    def save() -> None:
        _persist(pack_dir, session)

    try:
        if not hc["enabled"]:
            _finish(session, reason="harness_disabled", verdict="unsafe_skipped", hint="poc_harness.enabled is false.", now=float(clock()))
            save()
            return session
        if not command:
            _finish(session, reason="no_run_command", verdict="poc_broken", hint="Set hub frontmatter run: or an entry script.", now=float(clock()))
            save()
            return session
        if "missing_poc_code" in (readiness.get("issues") or []):
            _finish(session, reason="missing_poc_code", verdict="poc_broken", hint="Add runnable PoC code under the evidence pack.", now=float(clock()))
            save()
            return session

        hc_run = dict(hc)
        hc_run["network"] = network
        choice = select_isolation(hc_run, probe=probe)
        if not choice.get("ok"):
            verdict = str(choice.get("verdict") or "sandbox_unavailable")
            reason = "unsafe_skipped" if verdict == "unsafe_skipped" else "sandbox_unavailable"
            _finish(
                session,
                reason=reason,
                verdict=verdict,
                hint=str(choice.get("hint") or SANDBOX_MISSING_HINT),
                now=float(clock()),
            )
            session["spawn_error"] = choice.get("error")
            save()
            return session

        work = pack_dir / WORK_DIRNAME
        sync_workspace(pack_dir, work)
        target = Path(target_path) if target_path else None
        spec = {
            "guest_id": f"vf-poc-sess-{session_id}",
            "workspace": work,
            "pack_dir": pack_dir,
            "image": hc["docker_image"],
            "runtime": choice.get("runtime"),
            "isolation": choice.get("isolation"),
            "network": network,
            "cpus": hc["cpus"],
            "memory": hc["memory"],
            "pids_limit": hc["pids_limit"],
            "sleep_s": max(1, wall_ttl_min * 60),
            "target_path": target,
            "mount_target_ro": bool(hc.get("mount_target_ro")),
            "env": env_merged or None,
            "kernel": hc.get("firecracker_kernel") or "",
            "rootfs": hc.get("firecracker_rootfs") or "",
            "firecracker_path": choice.get("firecracker_path") or "",
            "jailer_path": choice.get("jailer_path") or "",
        }
        guest = driver if driver is not None else driver_for(choice)
        try:
            started_guest = guest.start(spec)
        except GuestStartError as exc:
            _finish(session, reason=exc.verdict, verdict=exc.verdict, hint=str(exc), now=float(clock()))
            save()
            return session
        except ValueError as exc:
            verdict = "unsafe_skipped" if "refused" in str(exc) or "host_network" in str(exc) else "sandbox_unavailable"
            _finish(session, reason=verdict, verdict=verdict, hint=str(exc), now=float(clock()))
            save()
            return session

        guest_id = str(started_guest.get("guest_id") or spec["guest_id"])
        session["guest_id"] = guest_id
        session["hold_mode"] = started_guest.get("hold_mode")
        session["guest_sees_workspace"] = bool(started_guest.get("guest_sees_workspace"))
        session["isolation"] = choice.get("isolation")
        session["runtime"] = choice.get("runtime")
        session["state"] = "live"
        save()

        applied_steer_seq = 0
        while True:
            now = float(clock())
            fh = _lock(pack_dir)
            try:
                if stop_requested(pack_dir):
                    _finish(session, reason="operator_stop", verdict=session.get("verdict") or "inconclusive", hint="Operator stopped the sandbox session.", now=now)
                    save()
                    break
                if now >= float(session["deadline_epoch"]):
                    _finish(session, reason="wall_ttl", verdict=session.get("verdict") or "inconclusive", hint="Wall TTL elapsed. Session ended without confirming.", now=now)
                    save()
                    break
                cycles = session.get("cycles") or []
                if len(cycles) >= max_cycles:
                    _finish(session, reason="cycle_cap", verdict=session.get("verdict") or "inconclusive", hint="Rewrite/re-run cap reached. Session ended without confirming.", now=now)
                    save()
                    break
                steers = [s for s in read_steers(pack_dir) if int(s.get("seq") or 0) > applied_steer_seq]
                cycle_index = len(cycles)
            finally:
                fh.close()

            rewrite_files: list[str] = []
            rewrite_note = ""
            if rewriter is not None and (cycle_index > 0 or steers):
                ctx = {
                    "cycle_index": cycle_index,
                    "steers": steers,
                    "last": (session.get("cycles") or [None])[-1],
                    "pack_dir": pack_dir,
                    "command": session.get("command") or command,
                    "isolation": session.get("isolation"),
                    "runtime": session.get("runtime"),
                    "guest_id": guest_id,
                }
                try:
                    rewrite = rewriter(ctx)
                except Exception as exc:  # noqa: BLE001
                    rewrite = None
                    rewrite_note = f"rewrite_error:{exc}"
                if isinstance(rewrite, dict):
                    try:
                        rewrite_files = apply_pack_rewrite(pack_dir, rewrite.get("files") or {})
                    except ValueError as exc:
                        rewrite_note = str(exc)
                        rewrite_files = []
                    note = str(rewrite.get("note") or "").strip()
                    if note and not rewrite_note:
                        rewrite_note = note[:500]
            if steers:
                applied_steer_seq = max(int(s.get("seq") or 0) for s in steers)
            sync_workspace(pack_dir, work)
            try:
                guest.sync(guest_id, work)
            except Exception:
                pass

            remaining = int(float(session["deadline_epoch"]) - float(clock()))
            if remaining < 1:
                _finish(session, reason="wall_ttl", verdict=session.get("verdict") or "inconclusive", hint="Wall TTL elapsed before the next cycle.", now=float(clock()))
                save()
                break
            timeout_s = max(1, min(int(hc["timeout_s"]), remaining))
            run_command = str(session.get("command") or command)
            try:
                captured = guest.exec(guest_id, run_command, timeout_s, env_merged or None)
            except Exception as exc:  # noqa: BLE001
                captured = _empty_result(str(choice.get("isolation") or "sandbox"), f"run_error:{exc}")
            if not isinstance(captured, dict):
                captured = _empty_result(str(choice.get("isolation") or "sandbox"), "run_error:bad_driver")
            verdict, signal = _cycle_verdict(captured, success_regex)
            stdout = captured.get("stdout") or ""
            digest = hashlib.sha256(stdout.encode("utf-8", errors="replace")).hexdigest()[:12]
            cycle = {
                "n": cycle_index + 1,
                "at": _epoch_iso(float(clock())),
                "command": run_command,
                "verdict": verdict,
                "exit_code": captured.get("exit_code"),
                "signal_matched": signal,
                "timed_out": bool(captured.get("timed_out")),
                "spawn_error": captured.get("spawn_error"),
                "duration_ms": captured.get("duration_ms"),
                "stdout_excerpt": _truncate(stdout, 4000),
                "stderr_excerpt": _truncate(captured.get("stderr") or "", 2000),
                "stdout_sha256_12": digest,
                "rewrite_files": rewrite_files,
                "rewrite_note": rewrite_note,
                "steer_seqs": [int(s.get("seq") or 0) for s in steers],
                "guest_id": guest_id,
                "runtime": choice.get("runtime"),
                "isolation": choice.get("isolation"),
                "host_exec": False,
            }
            session.setdefault("cycles", []).append(cycle)
            session["verdict"] = verdict
            if verdict in ("sandbox_unavailable", "unsafe_skipped"):
                _finish(session, reason=verdict, verdict=verdict, hint=str(captured.get("spawn_error") or verdict), now=float(clock()))
                save()
                break
            if verdict == "signal_observed":
                _finish(
                    session,
                    reason="signal_observed",
                    verdict="signal_observed",
                    hint="Signal observed inside the sandbox. Evidence only — finding stays unconfirmed.",
                    now=float(clock()),
                )
                save()
                break
            save()
    finally:
        if guest is not None and guest_id:
            try:
                guest.stop(guest_id)
            except Exception:
                pass
        if session.get("state") != "ended":
            _finish(
                session,
                reason="error",
                verdict=session.get("verdict") or "inconclusive",
                hint="Session closed.",
                now=float(clock()),
            )
        session["confirms_finding"] = False
        session["clears_needs_human"] = False
        session["skips_hitl"] = False
        session["host_exec"] = False
        save()
    return session


def session_to_poc_run(session: dict[str, Any]) -> dict[str, Any]:
    """Last-cycle evidence in the one-shot ``poc_run`` shape, marked as iterate."""
    cycles = session.get("cycles") if isinstance(session.get("cycles"), list) else []
    last = cycles[-1] if cycles and isinstance(cycles[-1], dict) else {}
    verdict = session.get("verdict") or last.get("verdict") or "inconclusive"
    return {
        "schema": "vulnforge.poc_run.v1",
        "mode": "iterate",
        "at": session.get("ended_at") or session.get("started_at") or utc_now_iso(),
        "finding_id": session.get("finding_id"),
        "verdict": verdict,
        "confidence": "medium" if verdict == "signal_observed" else "low",
        "command": last.get("command") or session.get("command"),
        "signal_matched": last.get("signal_matched"),
        "network": session.get("network") or "none",
        "runner": session.get("isolation") or "sandbox",
        "isolation": session.get("isolation"),
        "runtime": session.get("runtime"),
        "ran": bool(cycles) and verdict not in ("sandbox_unavailable", "unsafe_skipped"),
        "exit_code": last.get("exit_code"),
        "timed_out": bool(last.get("timed_out")),
        "spawn_error": last.get("spawn_error") or session.get("spawn_error"),
        "stdout_excerpt": last.get("stdout_excerpt") or "",
        "stderr_excerpt": last.get("stderr_excerpt") or "",
        "operator_hint": session.get("operator_hint"),
        "suggested_finding_action": "needs_human",
        "harness": {
            "runner": "sandbox",
            "isolation": session.get("isolation"),
            "runtime": session.get("runtime"),
            "network": session.get("network") or "none",
            "mode": "iterate",
            "max_cycles": session.get("max_cycles"),
            "wall_ttl_min": session.get("wall_ttl_min"),
            "cycles_run": len(cycles),
            "end_reason": session.get("end_reason"),
            "guest_id": session.get("guest_id"),
            "hold_mode": session.get("hold_mode"),
            "sandbox_selected": bool(session.get("runtime")),
        },
        "iterate": {
            "session_id": session.get("session_id"),
            "end_reason": session.get("end_reason"),
            "cycles_run": len(cycles),
            "max_cycles": session.get("max_cycles"),
            "wall_ttl_min": session.get("wall_ttl_min"),
            "confirms_finding": False,
        },
        "caveats": session.get("caveats") or [],
        "docker_network": "none" if session.get("network") != "allow" else "bridge",
    }
