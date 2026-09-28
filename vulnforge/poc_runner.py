"""One-shot PoC execution inside a real sandbox. Never on the host.

Isolation order (v1):

1. MicroVM — Kata (``kata-fc`` only when Firecracker/jailer are patched) or
   direct Firecracker+jailer when a kernel and rootfs are configured.
2. gVisor — Docker ``--runtime=runsc`` when that runtime is registered.
3. Refuse. Plain runc and ``local_subprocess`` are hard failures.

No ``--privileged``, host network, or docker.sock. Default network is none.
Results are evidence (``poc_run.json``) and never set ``confirmed``.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from vulnforge.poc_handoff import (
    POC_DEVELOP_RELPATH,
    assess_poc_readiness,
    parse_hub_frontmatter,
    resolve_run_command,
)
from vulnforge.util import utc_now_iso

MAX_CAPTURE_BYTES = 48_000
MAX_CAPTURE_CHARS = 24_000

# Pinned guest image. Override in config with a digest if you need a freeze.
PINNED_SANDBOX_IMAGE = "python:3.12.8-slim-bookworm"

# CVE-2026-5747: virtio-pci OOB, fixed in 1.14.4 and 1.15.1.
# CVE-2026-1386: jailer symlink overwrite, fixed in 1.13.2 and 1.14.1.
# Intersection that clears both: 1.14.4 <= v < 1.15.0, or v >= 1.15.1.
FIRECRACKER_PATCH_NOTE = (
    "Firecracker and jailer must be patched for CVE-2026-5747 "
    "(1.14.4+ or 1.15.1+) and CVE-2026-1386 (1.13.2+ / 1.14.1+). "
    "Accepted builds: 1.14.4 through 1.14.x, or 1.15.1 and later. "
    "Boot with pci=off (no virtio-pci)."
)

VERDICTS = frozenset(
    {
        "signal_observed",
        "signal_absent",
        "poc_broken",
        "inconclusive",
        "build_failed",
        "sandbox_unavailable",
        "unsafe_skipped",
    }
)

DEFAULT_POC_RUNNER = "sandbox"
DEFAULT_POC_NETWORK = "none"

_HOST_RUNNERS = frozenset({"local_subprocess", "local", "subprocess", "host"})
_PLAIN_RUNNERS = frozenset({"runc", "docker-runc", "plain", "default-runc"})
_MICROVM_RUNTIMES = ("kata-fc", "kata-qemu", "kata-clh", "kata")
_SECRET_ENV = re.compile(
    r"(SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|AWS_|PRIVATE|API_KEY|AUTH)",
    re.I,
)
_FORBIDDEN_PARTS = frozenset({".aws", ".ssh", ".gnupg", ".kube", ".docker"})

HOST_EXEC_HINT = (
    "Host execution is disabled. validate_poc runs only in a microVM "
    "(Kata / patched Firecracker) or gVisor (runsc). "
    "There is no local_subprocess fallback."
)
PLAIN_RUNC_HINT = (
    "Plain shared-kernel runc is not a v1 sandbox. "
    "Install Kata (microVM) or register gVisor as Docker runtime runsc. "
    "Refusing to run."
)
SANDBOX_MISSING_HINT = (
    "No microVM (Kata or patched Firecracker+jailer with /dev/kvm) "
    "and no gVisor runsc runtime. Refusing host exec and plain runc. "
    "Linux sandbox host required (macOS/Windows need a Linux host). "
    + FIRECRACKER_PATCH_NOTE
)
HOST_NET_HINT = (
    "Host network is refused. Default is --network=none. "
    "Hub network: allow uses an isolated bridge, never --network=host."
)


def harness_config(cfg: dict | None) -> dict[str, Any]:
    raw = (cfg or {}).get("poc_harness") if cfg else None
    if not isinstance(raw, dict):
        raw = {}
    runner = str(raw.get("runner") or DEFAULT_POC_RUNNER).strip().lower()
    runner = {
        "docker": "sandbox",
        "auto": "sandbox",
        "": "sandbox",
        "local": "local_subprocess",
        "subprocess": "local_subprocess",
        "host": "local_subprocess",
        "runsc": "gvisor",
        "gvisor": "gvisor",
        "kata": "microvm",
        "microvm": "microvm",
        "kata-qemu": "microvm",
        "kata-fc": "microvm",
        "firecracker": "firecracker",
        "runc": "runc",
        "plain": "runc",
        "docker-runc": "runc",
    }.get(runner, runner)
    network = str(raw.get("network") or DEFAULT_POC_NETWORK).strip().lower()
    if network in ("off", "false", "0", "deny", "disabled"):
        network = "none"
    if network in ("on", "true", "1", "yes", "bridge"):
        network = "allow"
    if network in ("host", "hostnet", "host-net"):
        network = "host"
    try:
        timeout_s = int(raw.get("timeout_s") or 60)
    except (TypeError, ValueError):
        timeout_s = 60
    timeout_s = max(1, min(timeout_s, 300))
    try:
        pids = int(raw.get("pids_limit") or 128)
    except (TypeError, ValueError):
        pids = 128
    pids = max(16, min(pids, 256))
    cpus = str(raw.get("cpus") or "1").strip() or "1"
    memory = str(raw.get("memory") or "512m").strip() or "512m"
    return {
        "enabled": bool(raw.get("enabled", True)),
        "runner": runner or DEFAULT_POC_RUNNER,
        "timeout_s": timeout_s,
        "network": network or DEFAULT_POC_NETWORK,
        # Writable audit target is never honored.
        "allow_write_target": False,
        "mount_target_ro": bool(raw.get("mount_target_ro", False)),
        "docker_image": str(raw.get("docker_image") or PINNED_SANDBOX_IMAGE).strip()
        or PINNED_SANDBOX_IMAGE,
        "cpus": cpus,
        "memory": memory,
        "pids_limit": pids,
        "firecracker_kernel": str(raw.get("firecracker_kernel") or "").strip(),
        "firecracker_rootfs": str(raw.get("firecracker_rootfs") or "").strip(),
        "python": "",
    }


def docker_available() -> bool:
    return bool(shutil.which("docker"))


def parse_version_tuple(text: str | None) -> tuple[int, int, int] | None:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    if not match:
        return None
    return tuple(int(x) for x in match.groups())  # type: ignore[return-value]


def firecracker_version_patched(ver: tuple[int, int, int] | None) -> bool:
    """True only for builds that clear CVE-2026-5747 and CVE-2026-1386."""
    if ver is None:
        return False
    if ver >= (1, 15, 1):
        return True
    if (1, 14, 4) <= ver < (1, 15, 0):
        return True
    return False


def memory_to_mib(memory: str) -> int:
    s = (memory or "512m").strip().lower()
    try:
        if s.endswith("g"):
            mib = int(float(s[:-1]) * 1024)
        elif s.endswith("m"):
            mib = int(float(s[:-1]))
        elif s.endswith("k"):
            mib = max(1, int(float(s[:-1]) / 1024))
        else:
            mib = int(float(s))
    except ValueError:
        mib = 512
    return max(64, min(mib, 2048))


def mount_forbidden_reason(path: Path) -> str | None:
    """Reject secret trees, dotenv files, and the docker socket."""
    try:
        resolved = path.resolve()
    except OSError:
        return "unresolvable"
    parts = {p.lower() for p in resolved.parts}
    if parts & _FORBIDDEN_PARTS:
        return "secret_dir"
    for part in resolved.parts:
        low = part.lower()
        if low == ".env" or low.startswith(".env."):
            return "dotenv"
    blob = str(resolved).lower()
    if blob.endswith("docker.sock") or "/docker.sock" in blob:
        return "docker_sock"
    return None


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
        return raw.decode("utf-8", errors="replace")
    return _truncate(str(raw))


def _split_command(cmd: str) -> list[str]:
    cmd = (cmd or "").strip()
    if not cmd:
        return []
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        return cmd.split()


def _match_signal(stdout: str, stderr: str, success_regex: str | None) -> bool | None:
    if not success_regex:
        return None
    try:
        pat = re.compile(success_regex, re.MULTILINE | re.DOTALL)
    except re.error:
        blob = stdout + "\n" + stderr
        return success_regex in blob
    blob = stdout + "\n" + stderr
    return bool(pat.search(blob))


def scrub_guest_env(env: dict[str, str] | None) -> tuple[dict[str, str], list[str]]:
    """Drop secret-looking keys. Never forward the host environment."""
    out: dict[str, str] = {"PYTHONUNBUFFERED": "1"}
    dropped: list[str] = []
    for key, value in (env or {}).items():
        name = str(key or "").strip()
        if not name or name in ("HOME", "USERPROFILE", "DOCKER_HOST"):
            if name:
                dropped.append(name)
            continue
        if _SECRET_ENV.search(name):
            dropped.append(name)
            continue
        out[name] = str(value)
    return out, dropped


def classify_run_result(
    *,
    ran: bool,
    exit_code: int | None,
    timed_out: bool,
    spawn_error: str | None,
    signal_matched: bool | None,
    skipped_reason: str | None = None,
) -> str:
    if skipped_reason == "sandbox_unavailable" or spawn_error == "sandbox_unavailable":
        return "sandbox_unavailable"
    if skipped_reason:
        return "unsafe_skipped"
    if spawn_error and str(spawn_error).startswith("build_failed"):
        return "build_failed"
    if spawn_error or timed_out:
        return "poc_broken"
    if not ran:
        return "poc_broken"
    if signal_matched is True:
        return "signal_observed"
    if signal_matched is False:
        return "signal_absent"
    if exit_code == 0:
        return "inconclusive"
    return "poc_broken"


def _empty_result(runner: str, spawn_error: str) -> dict[str, Any]:
    return {
        "ran": False,
        "exit_code": None,
        "timed_out": False,
        "spawn_error": spawn_error,
        "stdout": "",
        "stderr": "",
        "duration_ms": 0,
        "argv": [],
        "runner": runner,
    }


def run_poc_local(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    """Hard-fail. Host subprocess execution is not available."""
    out = _empty_result("local_subprocess", "host_exec_refused")
    out["operator_hint"] = HOST_EXEC_HINT
    return out


def audit_sandbox_argv(argv: list[str]) -> None:
    """Raise ValueError if an argv would weaken the sandbox boundary."""
    blob = " ".join(argv).lower()
    banned = (
        "--privileged",
        "--network=host",
        "--net=host",
        "--pid=host",
        "--ipc=host",
        "--userns=host",
        "docker.sock",
        "/.aws",
        "--cap-add",
    )
    for item in banned:
        if item in blob:
            raise ValueError(f"unsafe_sandbox_argv:{item}")
    if any(part == "host" and prev in ("--network", "--net") for prev, part in zip(argv, argv[1:])):
        raise ValueError("unsafe_sandbox_argv:network_host")


def build_docker_argv(
    *,
    name: str,
    pack_dir: Path,
    command: str,
    image: str,
    runtime: str,
    network: str,
    env: dict[str, str] | None,
    cpus: str,
    memory: str,
    pids_limit: int,
    target_path: Path | None = None,
    mount_target_ro: bool = False,
) -> list[str]:
    """Argv for one-shot Kata or gVisor. Read-only mounts, no host net."""
    if network == "host":
        raise ValueError("host_network_refused")
    if mount_forbidden_reason(pack_dir):
        raise ValueError("unsafe_mount:pack")
    net = "none" if network != "allow" else "bridge"
    argv = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--runtime",
        runtime,
        f"--network={net}",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        f"--cpus={cpus}",
        f"--memory={memory}",
        f"--memory-swap={memory}",
        f"--pids-limit={int(pids_limit)}",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=64m",
        "-v",
        f"{pack_dir.resolve()}:/work:ro",
        "-w",
        "/work",
    ]
    if mount_target_ro and target_path is not None:
        reason = mount_forbidden_reason(target_path)
        if reason:
            raise ValueError(f"unsafe_mount:target:{reason}")
        if not target_path.exists():
            raise ValueError("unsafe_mount:target_missing")
        argv.extend(["-v", f"{target_path.resolve()}:/target:ro"])
    guest_env, _dropped = scrub_guest_env(env)
    for key, value in guest_env.items():
        argv.extend(["-e", f"{key}={value}"])
    argv.append(image)
    argv.extend(["sh", "-c", command])
    audit_sandbox_argv(argv)
    return argv


def _kill_process_group(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            proc.kill()
        except OSError:
            pass


def spawn_captured(argv: list[str], *, timeout_s: int) -> dict[str, Any]:
    """Run argv with a wall clock. Kills the process group on timeout."""
    t0 = time.perf_counter()
    timed_out = False
    spawn_error: str | None = None
    exit_code: int | None = None
    stdout = b""
    stderr = b""
    proc: subprocess.Popen | None = None
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=max(1, int(timeout_s)))
            exit_code = int(proc.returncode) if proc.returncode is not None else None
        except subprocess.TimeoutExpired:
            timed_out = True
            spawn_error = f"timeout_after_{timeout_s}s"
            _kill_process_group(proc)
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except Exception:
                stdout, stderr = stdout or b"", b"timeout"
            if proc.returncode is not None:
                exit_code = int(proc.returncode)
    except OSError as e:
        spawn_error = f"spawn_error:{e}"
    except Exception as e:  # noqa: BLE001
        spawn_error = f"run_error:{e}"
    finally:
        if proc is not None and proc.poll() is None:
            _kill_process_group(proc)
    return {
        "exit_code": exit_code,
        "timed_out": timed_out,
        "spawn_error": spawn_error,
        "stdout": _capture_to_text(stdout),
        "stderr": _capture_to_text(stderr),
        "duration_ms": int((time.perf_counter() - t0) * 1000),
        "argv": argv,
    }


def run_cleanup(argv: list[str]) -> None:
    """Best-effort teardown command (docker rm). Never raises."""
    try:
        subprocess.run(
            argv,
            capture_output=True,
            timeout=20,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return


def _binary_version(path: str) -> tuple[int, int, int] | None:
    try:
        proc = subprocess.run(
            [path, "--version"],
            capture_output=True,
            timeout=3,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (proc.stdout or b"").decode("utf-8", "replace") + (proc.stderr or b"").decode(
        "utf-8", "replace"
    )
    return parse_version_tuple(text)


def _read_docker_runtimes() -> dict[str, Any]:
    if not shutil.which("docker"):
        return {}
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{json .Runtimes}}"],
            capture_output=True,
            timeout=3,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    raw = (proc.stdout or b"").decode("utf-8", "replace").strip()
    if not raw:
        return {}
    try:
        import json

        data = json.loads(raw)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def probe_host() -> dict[str, Any]:
    """What this machine can actually isolate. No execution of PoC code."""
    runtimes = _read_docker_runtimes()
    fc_path = shutil.which("firecracker")
    jail_path = shutil.which("jailer")
    fc_ver = _binary_version(fc_path) if fc_path else None
    jail_ver = _binary_version(jail_path) if jail_path else None
    return {
        "docker": bool(shutil.which("docker")),
        "runtimes": {str(k): v for k, v in runtimes.items()},
        "kvm": Path("/dev/kvm").exists(),
        "firecracker_path": fc_path,
        "firecracker_version": fc_ver,
        "firecracker_patched": firecracker_version_patched(fc_ver),
        "jailer_path": jail_path,
        "jailer_version": jail_ver,
        "jailer_patched": firecracker_version_patched(jail_ver),
    }


def _refuse(error: str, verdict: str, hint: str) -> dict[str, Any]:
    return {
        "ok": False,
        "isolation": None,
        "runtime": None,
        "error": error,
        "verdict": verdict,
        "hint": hint,
    }


def _pick_microvm(info: dict[str, Any]) -> dict[str, Any] | None:
    runtimes = info.get("runtimes") or {}
    if not isinstance(runtimes, dict) or not info.get("docker"):
        return None
    names = {str(k) for k in runtimes}
    if "kata-fc" in names:
        if info.get("kvm") and info.get("firecracker_patched") and info.get("jailer_patched"):
            return {
                "ok": True,
                "isolation": "microvm",
                "runtime": "kata-fc",
                "error": None,
                "verdict": None,
                "hint": None,
                "backend": "docker",
            }
        # Unpatched or unknown Firecracker: do not use kata-fc.
    for name in ("kata-qemu", "kata-clh", "kata"):
        if name in names:
            return {
                "ok": True,
                "isolation": "microvm",
                "runtime": name,
                "error": None,
                "verdict": None,
                "hint": None,
                "backend": "docker",
            }
    return None


def _pick_gvisor(info: dict[str, Any]) -> dict[str, Any] | None:
    runtimes = info.get("runtimes") or {}
    if not info.get("docker") or not isinstance(runtimes, dict):
        return None
    if "runsc" not in {str(k) for k in runtimes}:
        return None
    return {
        "ok": True,
        "isolation": "gvisor",
        "runtime": "runsc",
        "error": None,
        "verdict": None,
        "hint": None,
        "backend": "docker",
    }


def _pick_firecracker(info: dict[str, Any], hc: dict[str, Any]) -> dict[str, Any] | None:
    kernel = hc.get("firecracker_kernel") or ""
    rootfs = hc.get("firecracker_rootfs") or ""
    if not (kernel and rootfs and Path(kernel).is_file() and Path(rootfs).is_file()):
        return None
    if not info.get("kvm"):
        return None
    if not info.get("firecracker_path") or not info.get("jailer_path"):
        return None
    if not info.get("firecracker_patched") or not info.get("jailer_patched"):
        return None
    return {
        "ok": True,
        "isolation": "firecracker",
        "runtime": "firecracker",
        "error": None,
        "verdict": None,
        "hint": None,
        "backend": "firecracker",
        "firecracker_path": info.get("firecracker_path"),
        "jailer_path": info.get("jailer_path"),
    }


def select_isolation(hc: dict[str, Any], probe: dict[str, Any] | None = None) -> dict[str, Any]:
    """Choose microVM, else gVisor, else refuse. Never plain runc or host."""
    runner = str(hc.get("runner") or DEFAULT_POC_RUNNER)
    if runner in _HOST_RUNNERS or runner == "local_subprocess":
        return _refuse("host_exec_refused", "unsafe_skipped", HOST_EXEC_HINT)
    if runner in _PLAIN_RUNNERS or runner == "runc":
        return _refuse("plain_runc_refused", "unsafe_skipped", PLAIN_RUNC_HINT)
    if str(hc.get("network") or "") == "host":
        return _refuse("host_network_refused", "unsafe_skipped", HOST_NET_HINT)
    info = probe if probe is not None else probe_host()
    micro = _pick_microvm(info)
    direct = _pick_firecracker(info, hc)
    gvisor = _pick_gvisor(info)
    if runner == "gvisor":
        return gvisor or _refuse("sandbox_unavailable", "sandbox_unavailable", SANDBOX_MISSING_HINT)
    if runner == "firecracker":
        return direct or _refuse(
            "sandbox_unavailable",
            "sandbox_unavailable",
            "Direct Firecracker is not usable (need /dev/kvm, patched firecracker+jailer, "
            "and poc_harness.firecracker_kernel/rootfs). " + FIRECRACKER_PATCH_NOTE,
        )
    if runner == "microvm":
        return micro or direct or _refuse(
            "sandbox_unavailable", "sandbox_unavailable", SANDBOX_MISSING_HINT
        )
    # sandbox auto: microVM, then direct Firecracker, then gVisor, else refuse.
    if micro:
        return micro
    if direct:
        return direct
    if gvisor:
        return gvisor
    return _refuse("sandbox_unavailable", "sandbox_unavailable", SANDBOX_MISSING_HINT)


def _looks_like_build_failure(result: dict[str, Any]) -> bool:
    blob = f"{result.get('stderr') or ''}\n{result.get('stdout') or ''}".lower()
    err = str(result.get("spawn_error") or "")
    if err.startswith("build_failed"):
        return True
    if result.get("exit_code") == 125 and (
        "unable to find image" in blob
        or "manifest unknown" in blob
        or "pull access denied" in blob
        or "error response from daemon" in blob and "image" in blob
    ):
        return True
    return False


def _docker_binary_missing(result: dict[str, Any]) -> bool:
    err = str(result.get("spawn_error") or "")
    return "No such file" in err and "docker" in err


def _looks_like_missing_runtime(result: dict[str, Any]) -> bool:
    blob = f"{result.get('stderr') or ''}\n{result.get('stdout') or ''}".lower()
    return "unknown runtime" in blob or "invalid runtime" in blob or "executable file not found in $path" in blob and "runsc" in blob


def run_sandbox_docker(
    pack_dir: Path,
    command: str,
    *,
    image: str,
    runtime: str,
    isolation: str,
    timeout_s: int,
    network: str,
    env_extra: dict[str, str] | None,
    cpus: str,
    memory: str,
    pids_limit: int,
    target_path: Path | None,
    mount_target_ro: bool,
) -> dict[str, Any]:
    """Run inside Docker with a Kata or runsc runtime. Always tears the container down."""
    name = f"vf-poc-{uuid.uuid4().hex[:12]}"
    try:
        argv = build_docker_argv(
            name=name,
            pack_dir=pack_dir,
            command=command,
            image=image,
            runtime=runtime,
            network=network,
            env=env_extra,
            cpus=cpus,
            memory=memory,
            pids_limit=pids_limit,
            target_path=target_path,
            mount_target_ro=mount_target_ro,
        )
    except ValueError as e:
        code = str(e)
        out = _empty_result(isolation, code)
        out["operator_hint"] = (
            HOST_NET_HINT if "host_network" in code else f"Refused unsafe sandbox spec: {code}"
        )
        return out
    captured: dict[str, Any] | None = None
    try:
        captured = spawn_captured(argv, timeout_s=timeout_s)
    finally:
        # Wall-clock kill plus remove. --rm is not enough if the daemon stalls.
        run_cleanup(["docker", "kill", name])
        run_cleanup(["docker", "rm", "-f", name])
    if captured is None:
        captured = _empty_result(isolation, "run_error:spawn_failed")
    captured["runner"] = isolation
    captured["runtime"] = runtime
    captured["isolation"] = isolation
    captured["docker_image"] = image
    captured["docker_network"] = "none" if network != "allow" else "bridge"
    captured["ran"] = captured.get("spawn_error") is None or bool(captured.get("timed_out"))
    return captured


def build_firecracker_plan(
    *,
    pack_dir: Path,
    command: str,
    kernel: str,
    rootfs: str,
    fc_bin: str,
    jail_bin: str,
    memory: str,
    timeout_s: int,
    work_dir: Path,
) -> dict[str, Any]:
    """Jailer plan: no NIC, pci=off, patched binary paths, fresh 0700 work dir.

    Guest contract: rootfs ``/bin/sh`` (or init) reads ``vf.cmd=<base64>`` from
    ``/proc/cmdline`` and runs it. Serial console is the captured stdout.
    Evidence files are not mounted from the host except via that guest.
    """
    import base64
    import json

    if mount_forbidden_reason(pack_dir):
        raise ValueError("unsafe_mount:pack")
    encoded = base64.b64encode(command.encode("utf-8")).decode("ascii")
    if len(encoded) > 1500:
        raise ValueError("firecracker_command_too_long")
    work_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(work_dir, 0o700)
    boot_args = (
        "console=ttyS0 reboot=k panic=1 pci=off nomodules "
        f"vf.cmd={encoded}"
    )
    cfg = {
        "boot-source": {
            "kernel_image_path": str(Path(kernel).resolve()),
            "boot_args": boot_args,
        },
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": str(Path(rootfs).resolve()),
                "is_root_device": True,
                "is_read_only": True,
            }
        ],
        "machine-config": {
            "vcpu_count": 1,
            "mem_size_mib": memory_to_mib(memory),
        },
    }
    # No network-interfaces key: deny egress.
    cfg_path = work_dir / "firecracker.json"
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    serial = work_dir / "serial.log"
    cid = f"vf{uuid.uuid4().hex[:10]}"
    argv = [
        jail_bin,
        "--id",
        cid,
        "--exec-file",
        fc_bin,
        "--uid",
        str(os.getuid()),
        "--gid",
        str(os.getgid()),
        "--chroot-base-dir",
        str(work_dir),
        "--",
        "--no-api",
        "--config-file",
        str(cfg_path),
    ]
    audit_sandbox_argv(argv)
    return {
        "argv": argv,
        "config": cfg,
        "config_path": cfg_path,
        "serial": serial,
        "timeout_s": timeout_s,
        "id": cid,
    }


def run_sandbox_firecracker(
    pack_dir: Path,
    command: str,
    *,
    kernel: str,
    rootfs: str,
    fc_bin: str,
    jail_bin: str,
    memory: str,
    timeout_s: int,
) -> dict[str, Any]:
    work = Path(tempfile.mkdtemp(prefix="vf-poc-fc-"))
    os.chmod(work, 0o700)
    try:
        plan = build_firecracker_plan(
            pack_dir=pack_dir,
            command=command,
            kernel=kernel,
            rootfs=rootfs,
            fc_bin=fc_bin,
            jail_bin=jail_bin,
            memory=memory,
            timeout_s=timeout_s,
            work_dir=work,
        )
        captured = spawn_captured(plan["argv"], timeout_s=timeout_s)
        serial = plan["serial"]
        if serial.is_file():
            extra = serial.read_text(encoding="utf-8", errors="replace")
            captured["stdout"] = _truncate((captured.get("stdout") or "") + extra)
    except ValueError as e:
        captured = _empty_result("firecracker", str(e))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    captured["runner"] = "firecracker"
    captured["runtime"] = "firecracker"
    captured["isolation"] = "firecracker"
    captured["ran"] = captured.get("spawn_error") is None or bool(captured.get("timed_out"))
    captured["docker_network"] = "none"
    return captured


def run_isolated(
    pack_dir: Path,
    command: str,
    *,
    choice: dict[str, Any],
    hc: dict[str, Any],
    network: str,
    env_extra: dict[str, str] | None,
    target_path: Path | None,
) -> dict[str, Any]:
    if choice.get("backend") == "firecracker" or choice.get("isolation") == "firecracker":
        return run_sandbox_firecracker(
            pack_dir,
            command,
            kernel=hc["firecracker_kernel"],
            rootfs=hc["firecracker_rootfs"],
            fc_bin=str(choice.get("firecracker_path") or ""),
            jail_bin=str(choice.get("jailer_path") or ""),
            memory=hc["memory"],
            timeout_s=int(hc["timeout_s"]),
        )
    return run_sandbox_docker(
        pack_dir,
        command,
        image=hc["docker_image"],
        runtime=str(choice.get("runtime") or ""),
        isolation=str(choice.get("isolation") or "sandbox"),
        timeout_s=int(hc["timeout_s"]),
        network=network,
        env_extra=env_extra,
        cpus=str(hc["cpus"]),
        memory=str(hc["memory"]),
        pids_limit=int(hc["pids_limit"]),
        target_path=target_path,
        mount_target_ro=bool(hc.get("mount_target_ro")),
    )


def execute_poc_for_pack(
    pack_dir: Path,
    *,
    cfg: dict | None = None,
    hub_text: str = "",
    env_extra: Optional[dict[str, str]] = None,
    finding_body: Optional[dict[str, Any]] = None,
    finding_id: int | None = None,
    force_command: str | None = None,
    target_path: str | Path | None = None,
    probe: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Readiness → sandbox run → honest verdict. Never confirms a finding."""
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
    timeout_s = max(1, min(int(timeout_s), 300))
    hc = dict(hc)
    hc["timeout_s"] = timeout_s
    network = str(meta.get("network") or hc["network"] or DEFAULT_POC_NETWORK).lower()
    if network in ("off", "false", "0", "deny", "disabled"):
        network = "none"
    if network in ("on", "true", "1", "yes", "bridge"):
        network = "allow"
    if network in ("host", "hostnet", "host-net"):
        network = "host"
    hc["network"] = network
    success_regex = str(meta.get("success_regex") or readiness.get("success_regex") or "").strip() or None

    env_merged: dict[str, str] = {}
    if isinstance(meta.get("env"), dict):
        env_merged.update({str(k): str(v) for k, v in meta["env"].items()})
    if env_extra:
        env_merged.update({str(k): str(v) for k, v in env_extra.items()})
    env_merged, env_dropped = scrub_guest_env(env_merged)

    target: Path | None = Path(target_path) if target_path else None
    skipped_reason = None
    operator_hint: str | None = None
    verdict_override: str | None = None
    result: dict[str, Any] | None = None
    choice: dict[str, Any] = {"ok": False, "isolation": None, "runtime": None}

    if not hc["enabled"]:
        skipped_reason = "harness_disabled"
        operator_hint = "Set poc_harness.enabled: true (or force) to run the harness."
        verdict_override = "unsafe_skipped"
    elif not command:
        skipped_reason = "no_run_command"
        operator_hint = "Set hub frontmatter run: or an entry script in the evidence pack."
        verdict_override = "poc_broken"
    elif readiness.get("issues") and "missing_poc_code" in (readiness.get("issues") or []):
        skipped_reason = "missing_poc_code"
        operator_hint = "Add runnable PoC code under the evidence pack (e.g. poc.py)."
        verdict_override = "poc_broken"
    else:
        choice = select_isolation(hc, probe=probe)
        if not choice.get("ok"):
            skipped_reason = str(choice.get("error") or "sandbox_unavailable")
            operator_hint = str(choice.get("hint") or SANDBOX_MISSING_HINT)
            verdict_override = str(choice.get("verdict") or "sandbox_unavailable")
        else:
            try:
                result = run_isolated(
                    pack_dir,
                    command,
                    choice=choice,
                    hc=hc,
                    network=network,
                    env_extra=env_merged or None,
                    target_path=target,
                )
            except Exception as e:  # noqa: BLE001
                result = _empty_result(str(choice.get("isolation") or "sandbox"), f"run_error:{e}")

    if result is None:
        result = _empty_result(str(choice.get("isolation") or hc["runner"]), skipped_reason or "skipped")

    signal_matched = _match_signal(
        result.get("stdout") or "",
        result.get("stderr") or "",
        success_regex,
    )
    spawn_err = result.get("spawn_error")
    if verdict_override in ("unsafe_skipped", "sandbox_unavailable", "poc_broken") and skipped_reason:
        verdict = verdict_override
    elif str(spawn_err or "").startswith("unsafe_mount") or "host_network" in str(spawn_err or ""):
        verdict = "unsafe_skipped"
        operator_hint = operator_hint or (
            "Refused unsafe mount or host network. Evidence pack and optional target stay read-only."
        )
    elif _looks_like_build_failure(result):
        verdict = "build_failed"
        operator_hint = operator_hint or (
            f"Sandbox image {hc['docker_image']} was not usable. "
            "Pre-pull the pinned image on the Linux sandbox host. PoC was not run on the host."
        )
    elif _looks_like_missing_runtime(result) or _docker_binary_missing(result):
        verdict = "sandbox_unavailable"
        operator_hint = operator_hint or SANDBOX_MISSING_HINT
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
        if spawn_err and verdict not in ("unsafe_skipped", "sandbox_unavailable", "build_failed"):
            verdict = "poc_broken"

    if verdict not in VERDICTS:
        verdict = "inconclusive"

    suggested = {
        "signal_observed": "needs_human_with_notes",
        "signal_absent": "review_or_reject",
        "poc_broken": "fix_poc",
        "inconclusive": "add_success_signal",
        "unsafe_skipped": "use_microvm_or_gvisor",
        "sandbox_unavailable": "install_microvm_or_gvisor",
        "build_failed": "pin_sandbox_image",
    }.get(verdict, "needs_human")

    isolation = result.get("isolation") or choice.get("isolation")
    runtime = result.get("runtime") or choice.get("runtime")
    return {
        "schema": "vulnforge.poc_run.v1",
        "at": utc_now_iso(),
        "finding_id": finding_id,
        "verdict": verdict,
        "confidence": "medium" if verdict == "signal_observed" else "low",
        "command": command,
        "success_regex": success_regex,
        "signal_matched": signal_matched,
        "timeout_s": timeout_s,
        "network": "none" if network != "allow" else "allow",
        "readiness": readiness,
        "runner": isolation or hc["runner"],
        "isolation": isolation,
        "runtime": runtime,
        "harness": {
            "runner": hc["runner"],
            "isolation": isolation,
            "runtime": runtime,
            "network": "none" if network != "allow" else "allow",
            "timeout_s": timeout_s,
            "image": hc["docker_image"],
            "cpus": hc["cpus"],
            "memory": hc["memory"],
            "pids_limit": hc["pids_limit"],
            "sandbox_selected": bool(choice.get("ok")),
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
        "operator_hint": operator_hint or result.get("operator_hint"),
        "env_dropped": env_dropped,
        "caveats": [
            "Sandbox output is evidence only. It is not exploit proof and does not confirm the finding.",
            "confirmed stays human-only. needs_human and HITL are unchanged by a sandbox hit.",
            "PoC failure or signal_absent is not a false positive.",
            "Guest network defaults to none. Host network and docker.sock are refused.",
            "v1 runs only in a microVM (Kata or patched Firecracker) or gVisor runsc.",
            FIRECRACKER_PATCH_NOTE,
        ],
        "docker_image": result.get("docker_image") or hc["docker_image"],
        "docker_network": result.get("docker_network") or ("none" if network != "allow" else "bridge"),
        "image_pin": hc["docker_image"],
    }


# Back-compat name. Plain docker (runc) is not invoked.
def run_poc_docker(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    out = _empty_result("docker", "plain_runc_refused")
    out["operator_hint"] = PLAIN_RUNC_HINT
    return out
