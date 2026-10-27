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

import json
import os
import re
import secrets
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
# Treatment + neutralized control, repeated. A single self-printed marker is not a signal.
DEFAULT_ORACLE_K = 2
CANARY_ENV = "VF_CANARY"
TRIGGER_ENV = "VF_TRIGGER"
ORACLE_MARK_ENV = "VF_ORACLE_MARK"
POC_COMMAND_ENV = "VF_POC_COMMAND"

# Guest script. Secrets arrive as env on this process only. It re-execs a clean
# shell so the PoC cannot read them from the environment or /proc/<pid>/environ.
# A separate target process owns the oracle pipe (unlinked, no path). The PoC is
# started with that fd closed and with no canary file. Treatment vs control is
# visible only to the target. The PoC's request channel is /tmp/vf-oracle/req.
# Any non-empty line makes the target write the canary on a treatment run.
# The line "emit-on-control" also writes it on a control run, which the judge
# rejects. The PoC's own stdout/stderr are framed after a per-run mark.
ORACLE_WRAPPER = r"""b=$(mktemp -d)
chmod 700 "$b"
mkfifo "$b/p"
env | grep -Ev '^(VF_CANARY|VF_TRIGGER|VF_ORACLE_MARK|VF_POC_COMMAND)=' >"$b/e" || true
(
  printf '%s\n' "$VF_TRIGGER" "$VF_CANARY" "$VF_ORACLE_MARK"
  printf '%s' "$VF_POC_COMMAND" | base64 | tr -d '\n'
  printf '\n'
) >"$b/p" &
exec env -i PATH="$PATH" HOME="${HOME:-/tmp}" TMPDIR="${TMPDIR:-/tmp}" PYTHONUNBUFFERED=1 \
  sh -c 'IFS= read -r phase
IFS= read -r can
IFS= read -r mark
IFS= read -r cmd_b64
exec </dev/null
cmd=$(printf "%s" "$cmd_b64" | base64 -d)
boot=$1
d=/tmp/vf-oracle
rm -rf "$d"
mkdir -p "$d"
chmod 700 "$d"
mkfifo "$d/req" "$d/out"
chmod 622 "$d/req"
(
  exec 3>"$d/out"
  rm -f "$d/out"
  exec 4<>"$d/req"
  IFS= read -r line <&4 || line=
  if [ "$phase" = 1 ] && [ -n "$line" ]; then
    printf "%s\n" "$can" >&3
  elif [ "$line" = emit-on-control ]; then
    printf "%s\n" "$can" >&3
  fi
) &
tp=$!
exec 5<"$d/out"
rm -f "$d/out" "$d/canary"
if [ -f "$boot/e" ]; then
  while IFS= read -r rec; do
    key=${rec%%=*}
    case $key in ""|*[!A-Za-z0-9_]*|VF_*) continue ;; esac
    export "$key=${rec#*=}"
  done <"$boot/e"
  rm -f "$boot/e"
fi
rm -f "$boot/p"
sh -c "$cmd" >"$d/o" 2>"$d/e" </dev/null 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
ec=$?
i=0
while kill -0 "$tp" 2>/dev/null && [ "$i" -lt 20 ]; do
  sleep 0.05
  i=$((i + 1))
done
kill "$tp" 2>/dev/null || true
wait "$tp" 2>/dev/null || true
cat <&5 >"$d/t"
cat "$d/t"
printf "\n%s\n" "$mark"
cat "$d/o"
printf "\n%sERR\n" "$mark"
cat "$d/e"
rm -rf "$d" "$boot"
exit "$ec"' vf "$b" <"$b/p"
"""

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
    cycles = _clamp_int(raw.get("iterate_max_cycles"), default=5, lo=1, hi=50)
    ttl_min = _clamp_int(raw.get("iterate_wall_ttl_min"), default=15, lo=1, hi=240)
    oracle_k = _clamp_int(raw.get("oracle_k"), default=DEFAULT_ORACLE_K, lo=1, hi=5)
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
        # Iterate-in-sandbox caps. Settings overrides these via poc_harness.
        "iterate_max_cycles": cycles,
        "iterate_wall_ttl_min": ttl_min,
        "oracle_k": oracle_k,
    }


def _clamp_int(value: Any, *, default: int, lo: int, hi: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def docker_available() -> bool:
    """True only when this process can talk to the Docker API."""
    return bool(_docker_api_probe()["ok"])


def effective_lacks_docker_group() -> bool:
    """True when a ``docker`` group exists and this process's effective GIDs omit it.

    Uses ``os.getgroups()`` / ``getegid()``, not ``/etc/group`` membership.
    Root is not reported as lacking the group. Hosts without a docker group
    (or without POSIX groups) return False.
    """
    geteuid = getattr(os, "geteuid", None)
    try:
        if geteuid is not None and int(geteuid()) == 0:
            return False
    except (OSError, TypeError, ValueError):
        pass
    try:
        import grp

        docker = grp.getgrnam("docker")
    except KeyError:
        return False
    except Exception:
        return False
    gids: set[int] = set()
    getgroups = getattr(os, "getgroups", None)
    if getgroups is not None:
        try:
            gids.update(int(g) for g in getgroups())
        except (OSError, TypeError, ValueError):
            pass
    for fn_name in ("getegid", "getgid"):
        fn = getattr(os, fn_name, None)
        if fn is None:
            continue
        try:
            gids.add(int(fn()))
        except (OSError, TypeError, ValueError):
            pass
    try:
        docker_gid = int(docker.gr_gid)
    except (TypeError, ValueError, AttributeError):
        return False
    return docker_gid not in gids


def _docker_error_is_permission(err: str | None) -> bool:
    text = (err or "").lower()
    return "permission denied" in text or "access denied" in text


def _first_stderr_line(raw: bytes | None, *, code: int) -> str:
    text = (raw or b"").decode("utf-8", "replace")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            if len(stripped) > 300:
                return stripped[:300] + "…"
            return stripped
    return f"docker info exited {code}"


def _docker_api_probe() -> dict[str, Any]:
    """One ``docker info`` call. Fail closed unless the API answers.

    ``ok`` is true only when this process is authorized and the daemon
    returns exit 0 with a JSON runtimes object. Socket permission errors,
    an inactive daemon, a non-zero exit, a timeout, and unparseable output
    are all ``ok: False`` with empty runtimes.
    """
    cli = bool(shutil.which("docker"))
    if not cli:
        return {"ok": False, "cli": False, "runtimes": {}, "error": "docker_cli_missing"}
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{json .Runtimes}}"],
            capture_output=True,
            timeout=3,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "cli": True, "runtimes": {}, "error": "timeout"}
    except OSError as e:
        return {"ok": False, "cli": True, "runtimes": {}, "error": f"spawn_error:{e}"}
    if proc.returncode != 0:
        return {
            "ok": False,
            "cli": True,
            "runtimes": {},
            "error": _first_stderr_line(proc.stderr, code=int(proc.returncode)),
        }
    raw = (proc.stdout or b"").decode("utf-8", "replace").strip()
    if not raw:
        return {"ok": False, "cli": True, "runtimes": {}, "error": "empty_docker_info"}
    try:
        data = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {"ok": False, "cli": True, "runtimes": {}, "error": "bad_docker_info"}
    if not isinstance(data, dict):
        return {"ok": False, "cli": True, "runtimes": {}, "error": "bad_docker_info"}
    return {"ok": True, "cli": True, "runtimes": data, "error": None}


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
    # A marker on a non-zero exit is not a reproduction.
    if signal_matched is True:
        if exit_code == 0 and not timed_out:
            return "signal_observed"
        return "inconclusive"
    if signal_matched is False:
        return "signal_absent"
    if exit_code == 0:
        return "inconclusive"
    return "poc_broken"


def mint_canary() -> str:
    """Fresh secret for one harness invocation. The PoC cannot know it ahead of time."""
    return secrets.token_hex(16)


def mint_oracle_mark() -> str:
    """Framing token so PoC stdout cannot be mistaken for target stdout."""
    return "VF_MARK_" + secrets.token_hex(8)


def marker_in_poc_or_args(marker: str, pack_dir: Path, command: str) -> str | None:
    """Return a reason if the harness marker is already in the PoC or its command."""
    if not marker:
        return None
    if marker in (command or ""):
        return "marker_in_args"
    root = Path(pack_dir)
    if not root.is_dir():
        return None
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > 200_000 or size == 0:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if marker in text:
            return "marker_in_poc_source"
    return None


def split_oracle_capture(stdout: str, mark: str) -> tuple[str, str, str]:
    """Split wrapper output into target stdout, PoC stdout, PoC stderr.

    Missing framing means the scored channel was not produced. Those bytes are
    treated as PoC output, not a target signal.
    """
    text = stdout or ""
    if not mark:
        return "", text, ""
    token = f"\n{mark}\n"
    err_token = f"\n{mark}ERR\n"
    if token not in text:
        return "", text, ""
    target, rest = text.split(token, 1)
    if err_token in rest:
        poc_out, poc_err = rest.split(err_token, 1)
    else:
        poc_out, poc_err = rest, ""
    return target, poc_out, poc_err


def _shows_canary(text: str, canary: str) -> bool:
    return bool(canary) and canary in (text or "")


def _trial_from_capture(phase: str, captured: dict[str, Any], mark: str) -> dict[str, Any]:
    target, poc_out, poc_err = split_oracle_capture(captured.get("stdout") or "", mark)
    return {
        "phase": phase,
        "exit_code": captured.get("exit_code"),
        "timed_out": bool(captured.get("timed_out")),
        "spawn_error": captured.get("spawn_error"),
        "ran": bool(captured.get("ran")),
        "target_stdout": target,
        "poc_stdout": poc_out,
        "poc_stderr": poc_err,
        "raw_stderr": captured.get("stderr") or "",
        "stdout": captured.get("stdout") or "",
        "stderr": captured.get("stderr") or "",
        "duration_ms": captured.get("duration_ms"),
        "argv": captured.get("argv"),
        "capture": captured,
    }


def judge_oracle_trials(
    trials: list[dict[str, Any]],
    *,
    canary: str,
    k: int,
) -> dict[str, Any]:
    """Decide signal_observed only from a differential canary oracle.

    Requirements, all of them:
    - k treatment runs and k control runs
    - canary on target stdout only (not PoC stdout/stderr, not raw stderr)
    - treatment exit 0
    - neutralized control does not show the canary
    """
    k = max(1, int(k))

    def _infra(trial: dict[str, Any]) -> str | None:
        err = str(trial.get("spawn_error") or "")
        if err.startswith("unsafe_mount") or "host_network" in err:
            return "unsafe_skipped"
        if _looks_like_build_failure(trial):
            return "build_failed"
        if _looks_like_missing_runtime(trial) or _docker_binary_missing(trial):
            return "sandbox_unavailable"
        if err == "sandbox_unavailable":
            return "sandbox_unavailable"
        return None

    for trial in trials:
        infra = _infra(trial)
        if infra:
            return {
                "verdict": infra,
                "signal_matched": None,
                "reason": trial.get("spawn_error") or infra,
            }

    if not trials or any(
        trial.get("spawn_error") or trial.get("timed_out") or not trial.get("ran")
        for trial in trials
    ):
        return {
            "verdict": "poc_broken",
            "signal_matched": None,
            "reason": "spawn_failed",
        }

    treatment = [t for t in trials if t.get("phase") == "treatment"]
    control = [t for t in trials if t.get("phase") == "control"]
    if len(treatment) < k or len(control) < k:
        return {
            "verdict": "inconclusive",
            "signal_matched": False,
            "reason": "short_run",
        }

    def _poc_leaked(trial: dict[str, Any]) -> bool:
        return (
            _shows_canary(str(trial.get("poc_stdout") or ""), canary)
            or _shows_canary(str(trial.get("poc_stderr") or ""), canary)
            or _shows_canary(str(trial.get("raw_stderr") or ""), canary)
        )

    if any(_poc_leaked(t) for t in trials):
        return {
            "verdict": "inconclusive",
            "signal_matched": False,
            "reason": "marker_on_poc_stream",
        }

    control_hits = sum(
        1 for t in control if _shows_canary(str(t.get("target_stdout") or ""), canary)
    )
    if control_hits:
        return {
            "verdict": "inconclusive",
            "signal_matched": False,
            "reason": "control_showed_canary",
            "control_hits": control_hits,
        }

    hits = 0
    for trial in treatment:
        showed = _shows_canary(str(trial.get("target_stdout") or ""), canary)
        if showed and trial.get("exit_code") != 0:
            return {
                "verdict": "inconclusive",
                "signal_matched": False,
                "reason": "nonzero_exit",
            }
        if showed and trial.get("exit_code") == 0:
            hits += 1
    if hits == k and len(treatment) == k:
        return {
            "verdict": "signal_observed",
            "signal_matched": True,
            "reason": "differential_ok",
            "treatment_hits": hits,
            "control_hits": 0,
        }
    if hits == 0:
        if any(t.get("exit_code") != 0 for t in treatment):
            return {
                "verdict": "poc_broken",
                "signal_matched": False,
                "reason": "nonzero_exit",
                "treatment_hits": 0,
                "control_hits": 0,
            }
        return {
            "verdict": "signal_absent",
            "signal_matched": False,
            "reason": "canary_absent",
            "treatment_hits": 0,
            "control_hits": 0,
        }
    return {
        "verdict": "inconclusive",
        "signal_matched": False,
        "reason": "flaky",
        "treatment_hits": hits,
        "control_hits": 0,
    }


def _redact_marker(value: Any, markers: list[str]) -> Any:
    if isinstance(value, str):
        out = value
        for marker in markers:
            if marker:
                out = out.replace(marker, "<redacted>")
        return out
    if isinstance(value, list):
        return [_redact_marker(item, markers) for item in value]
    return value


def _shell_exports(env: dict[str, str]) -> str:
    parts: list[str] = []
    for key, value in env.items():
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(key)):
            continue
        parts.append(f"{key}={shlex.quote(str(value))}")
    if not parts:
        return ""
    return "export " + " ".join(parts) + "; "


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


# Runtimes a long-lived session may pin. Plain runc is not in this set.
SESSION_RUNTIMES = frozenset({"kata-fc", "kata-qemu", "kata-clh", "kata", "runsc"})


def build_session_docker_argv(
    *,
    name: str,
    workspace: Path,
    image: str,
    runtime: str,
    network: str,
    cpus: str,
    memory: str,
    pids_limit: int,
    sleep_s: int,
    target_path: Path | None = None,
    mount_target_ro: bool = False,
    env: dict[str, str] | None = None,
) -> list[str]:
    """Detached Kata or runsc container. ``sleep`` holds the guest for the TTL.

    The PoC command is not on this argv. Later cycles use ``docker exec`` into
    this same container. The workspace is read-only from the guest.
    """
    if runtime not in SESSION_RUNTIMES:
        raise ValueError(f"runtime_refused:{runtime or 'empty'}")
    if network == "host":
        raise ValueError("host_network_refused")
    if mount_forbidden_reason(workspace):
        raise ValueError("unsafe_mount:workspace")
    net = "none" if network != "allow" else "bridge"
    argv = [
        "docker",
        "run",
        "-d",
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
        f"{workspace.resolve()}:/work:ro",
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
    argv.extend(["sleep", str(max(1, int(sleep_s)))])
    audit_sandbox_argv(argv)
    return argv


def build_session_exec_argv(
    *,
    name: str,
    command: str,
    env: dict[str, str] | None = None,
) -> list[str]:
    """``docker exec`` into an existing session container. Never a host shell."""
    if not name or not str(name).startswith("vf-poc-sess-"):
        raise ValueError("session_guest_refused")
    argv = ["docker", "exec", "-w", "/work"]
    guest_env, _dropped = scrub_guest_env(env)
    for key, value in guest_env.items():
        argv.extend(["-e", f"{key}={value}"])
    argv.extend([name, "sh", "-c", command])
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


def spawn_captured(
    argv: list[str],
    *,
    timeout_s: int,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
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
            cwd=str(cwd) if cwd is not None else None,
            env=env,
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


def _oracle_child_env(extra: dict[str, str] | None) -> dict[str, str]:
    """Environment for one wrapper process. Not the host environment."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
        "LANG": "C",
        "PYTHONUNBUFFERED": "1",
    }
    for key, value in (extra or {}).items():
        name = str(key or "").strip()
        if not name:
            continue
        env[name] = str(value)
    return env


def run_oracle_wrapper_sh(
    *,
    command: str,
    canary: str,
    mark: str,
    trigger: str,
    cwd: str | Path,
    timeout_s: int,
    extra_env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run ``ORACLE_WRAPPER`` under ``sh``. The sandbox uses this same script."""
    env = _oracle_child_env(extra_env)
    env[CANARY_ENV] = canary
    env[TRIGGER_ENV] = trigger
    env[ORACLE_MARK_ENV] = mark
    env[POC_COMMAND_ENV] = command
    captured = spawn_captured(
        ["sh", "-c", ORACLE_WRAPPER],
        timeout_s=max(1, int(timeout_s)),
        cwd=cwd,
        env=env,
    )
    captured["ran"] = captured.get("spawn_error") is None or bool(captured.get("timed_out"))
    return captured


def score_oracle_sh(
    pack_dir: Path,
    command: str,
    *,
    k: int = DEFAULT_ORACLE_K,
    canary: str | None = None,
    extra_env: dict[str, str] | None = None,
    timeout_s: int = 30,
) -> dict[str, Any]:
    """Score one PoC command by running the real oracle wrapper under ``sh``.

    This is the same script the sandbox runs. It does not mock ``spawn_captured``.
    """
    pack_dir = Path(pack_dir)
    k = max(1, int(k))
    secret = canary or mint_canary()
    mark = mint_oracle_mark()
    oracle: dict[str, Any] = {
        "k": k,
        "reason": None,
        "stdout_only": True,
        "exit_required": 0,
        "planted": False,
        "runs": 0,
    }
    leak = marker_in_poc_or_args(secret, pack_dir, command)
    if leak:
        oracle["reason"] = leak
        return {
            "verdict": "poc_broken",
            "signal_matched": False,
            "command": command,
            "stdout_excerpt": "",
            "oracle": oracle,
            "canary": secret,
            "trials": [],
            "triggers": [],
        }
    trials: list[dict[str, Any]] = []
    triggers: list[str] = []
    for _n in range(k):
        for phase, trigger in (("treatment", "1"), ("control", "0")):
            triggers.append(trigger)
            captured = run_oracle_wrapper_sh(
                command=command,
                canary=secret,
                mark=mark,
                trigger=trigger,
                cwd=pack_dir,
                timeout_s=timeout_s,
                extra_env=extra_env,
            )
            trials.append(_trial_from_capture(phase, captured, mark))
    oracle["planted"] = True
    oracle["runs"] = len(trials)
    judged = judge_oracle_trials(trials, canary=secret, k=k)
    verdict = str(judged.get("verdict") or "inconclusive")
    oracle["reason"] = judged.get("reason")
    if "treatment_hits" in judged:
        oracle["treatment_hits"] = judged.get("treatment_hits")
    if "control_hits" in judged:
        oracle["control_hits"] = judged.get("control_hits")
    last = next((t for t in reversed(trials) if t.get("phase") == "treatment"), trials[-1])
    excerpt = _truncate(
        str(_redact_marker(last.get("target_stdout") or "", [secret, mark])),
        8000,
    )
    return {
        "verdict": verdict,
        "signal_matched": judged.get("signal_matched"),
        "command": command,
        "stdout_excerpt": excerpt,
        "oracle": oracle,
        "canary": secret,
        "trials": trials,
        "triggers": triggers,
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


def probe_host() -> dict[str, Any]:
    """What this machine can actually isolate. No execution of PoC code.

    ``docker`` is true only when this process can use the Docker API.
    ``docker_cli`` is binary-on-PATH and can be true while ``docker`` is false.
    """
    api = _docker_api_probe()
    runtimes = api["runtimes"] if api["ok"] and isinstance(api.get("runtimes"), dict) else {}
    fc_path = shutil.which("firecracker")
    jail_path = shutil.which("jailer")
    fc_ver = _binary_version(fc_path) if fc_path else None
    jail_ver = _binary_version(jail_path) if jail_path else None
    return {
        "docker": bool(api["ok"]),
        "docker_cli": bool(api["cli"]),
        "docker_error": api.get("error"),
        "runtimes": {str(k): v for k, v in runtimes.items()},
        "kvm": Path("/dev/kvm").exists(),
        "firecracker_path": fc_path,
        "firecracker_version": fc_ver,
        "firecracker_patched": firecracker_version_patched(fc_ver),
        "jailer_path": jail_path,
        "jailer_version": jail_ver,
        "jailer_patched": firecracker_version_patched(jail_ver),
    }


_RELOGIN_HINT = (
    "Effective groups for this process do not include docker. "
    "After usermod -aG docker, log out and back in completely so the session "
    "picks up the group. newgrp docker only changes that shell."
)


def sandbox_poc_preflight(cfg: dict | None = None) -> dict[str, Any]:
    """Check that this process can isolate a sandbox PoC.

    Callers invoke this only when sandbox one-shot is being turned on.
    Refusal covers an unusable Docker API, a missing ``runsc`` / microVM
    (``select_isolation`` → ``sandbox_unavailable``), and a permission
    failure while the effective GID list lacks the docker group.
    """
    probe = probe_host()
    hc = harness_config(cfg)
    choice = select_isolation(hc, probe=probe)
    if choice.get("ok"):
        return {"ok": True, "message": "", "probe": probe, "isolation": choice}
    message = _sandbox_preflight_message(probe, choice)
    return {"ok": False, "message": message, "probe": probe, "isolation": choice}


def _sandbox_preflight_message(probe: dict[str, Any], choice: dict[str, Any]) -> str:
    if not probe.get("docker"):
        err = str(probe.get("docker_error") or "").strip()
        if not probe.get("docker_cli"):
            head = (
                "Sandbox PoC refused: docker is not on PATH, so this process "
                "cannot use the Docker API."
            )
        else:
            detail = err or "docker info failed"
            head = (
                "Sandbox PoC refused: docker is on PATH but this process cannot "
                f"use the Docker API ({detail})."
            )
        if probe.get("docker_cli") and effective_lacks_docker_group() and _docker_error_is_permission(err):
            return f"{head} {_RELOGIN_HINT}"
        return head
    hint = str(choice.get("hint") or "").strip()
    if hint:
        return f"Sandbox PoC refused: {hint}"
    return (
        "Sandbox PoC refused: select_isolation is sandbox_unavailable. "
        "Need a microVM runtime or gVisor runsc."
    )


def sandbox_poc_start_block(run_dir: Path) -> str | None:
    """Refuse campaign start when this run opted into sandbox PoC and isolation is unusable.

    Returns None when the run did not opt in, or when the run config cannot be
    read (no invented opt-in). Returns an operator message when it did opt in
    and preflight fails.
    """
    cfg = _read_run_config(run_dir)
    if cfg is None:
        return None
    run = cfg.get("run") if isinstance(cfg.get("run"), dict) else {}
    ph = cfg.get("poc_harness") if isinstance(cfg.get("poc_harness"), dict) else {}
    if not (run.get("sandbox_poc_validate") or ph.get("sandbox_oneshot")):
        return None
    report = sandbox_poc_preflight(cfg)
    if report.get("ok"):
        return None
    return str(report.get("message") or "Sandbox PoC refused: isolation unavailable")


def _read_run_config(run_dir: Path) -> dict[str, Any] | None:
    try:
        from vulnforge.db import Database

        db_path = Path(run_dir) / "harness.db"
        if not db_path.is_file():
            return None
        db = Database.open(db_path)
        try:
            row = db.get_run()
            raw = row["config_json"] if row and "config_json" in row.keys() else None
        finally:
            db.close()
    except Exception:
        return None
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


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
    # Floor for a 2048-byte kernel cmdline. Refuse rather than boot a truncated
    # vf.cmd. The oracle wrapper does not fit; direct Firecracker then fails closed.
    boot_args = (
        "console=ttyS0 reboot=k panic=1 pci=off nomodules "
        f"vf.cmd={encoded}"
    )
    if len(boot_args) > 2048:
        raise ValueError("firecracker_command_too_long")
    work_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(work_dir, 0o700)
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
    env_extra: dict[str, str] | None = None,
) -> dict[str, Any]:
    work = Path(tempfile.mkdtemp(prefix="vf-poc-fc-"))
    os.chmod(work, 0o700)
    guest_env, _dropped = scrub_guest_env(env_extra)
    guest_command = _shell_exports(guest_env) + command
    try:
        plan = build_firecracker_plan(
            pack_dir=pack_dir,
            command=guest_command,
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
            env_extra=env_extra,
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
    # Frontmatter success_regex is not the oracle. A PoC that prints its own
    # marker cannot certify signal_observed.
    success_regex = str(meta.get("success_regex") or readiness.get("success_regex") or "").strip() or None
    oracle_k = int(hc.get("oracle_k") or DEFAULT_ORACLE_K)
    canary = ""
    oracle_mark = ""
    oracle_meta: dict[str, Any] = {
        "k": oracle_k,
        "reason": None,
        "stdout_only": True,
        "exit_required": 0,
        "planted": False,
        "runs": 0,
    }
    trials: list[dict[str, Any]] = []

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
        canary = mint_canary()
        oracle_mark = mint_oracle_mark()
        leak = marker_in_poc_or_args(canary, pack_dir, command)
        if leak:
            skipped_reason = leak
            verdict_override = "poc_broken"
            oracle_meta["reason"] = leak
            operator_hint = (
                "The harness canary appears in the PoC source or run command. "
                "That is poc_broken, not a signal."
            )
        else:
            choice = select_isolation(hc, probe=probe)
            if not choice.get("ok"):
                skipped_reason = str(choice.get("error") or "sandbox_unavailable")
                operator_hint = str(choice.get("hint") or SANDBOX_MISSING_HINT)
                verdict_override = str(choice.get("verdict") or "sandbox_unavailable")
            else:
                oracle_meta["planted"] = True
                for _n in range(oracle_k):
                    for phase, trigger in (("treatment", "1"), ("control", "0")):
                        trial_env = dict(env_merged)
                        trial_env[CANARY_ENV] = canary
                        trial_env[TRIGGER_ENV] = trigger
                        trial_env[ORACLE_MARK_ENV] = oracle_mark
                        trial_env[POC_COMMAND_ENV] = command
                        try:
                            captured = run_isolated(
                                pack_dir,
                                ORACLE_WRAPPER,
                                choice=choice,
                                hc=hc,
                                network=network,
                                env_extra=trial_env,
                                target_path=target,
                            )
                        except Exception as e:  # noqa: BLE001
                            captured = _empty_result(
                                str(choice.get("isolation") or "sandbox"),
                                f"run_error:{e}",
                            )
                        trials.append(_trial_from_capture(phase, captured, oracle_mark))
                oracle_meta["runs"] = len(trials)
                if trials:
                    result = trials[-1]["capture"]

    if result is None:
        result = _empty_result(str(choice.get("isolation") or hc["runner"]), skipped_reason or "skipped")

    if verdict_override in ("unsafe_skipped", "sandbox_unavailable", "poc_broken") and skipped_reason:
        verdict = verdict_override
        signal_matched = False if oracle_meta.get("reason") else None
    elif trials:
        judged = judge_oracle_trials(trials, canary=canary, k=oracle_k)
        verdict = str(judged.get("verdict") or "inconclusive")
        signal_matched = judged.get("signal_matched")
        oracle_meta["reason"] = judged.get("reason")
        if "treatment_hits" in judged:
            oracle_meta["treatment_hits"] = judged.get("treatment_hits")
        if "control_hits" in judged:
            oracle_meta["control_hits"] = judged.get("control_hits")
        hint = {
            "control_showed_canary": (
                "The neutralized control also showed the canary. Not a signal."
            ),
            "marker_on_poc_stream": (
                "The canary was on the PoC's own stdout or stderr. "
                "Only target stdout (fd 3) counts, and exit 0 is required."
            ),
            "nonzero_exit": "The canary was on target stdout but the process did not exit 0.",
            "flaky": "The canary was not observed on every treatment run.",
            "canary_absent": "The harness canary was not on target stdout.",
        }.get(str(oracle_meta.get("reason") or ""))
        if hint:
            operator_hint = operator_hint or hint
        last_treatment = next(
            (t for t in reversed(trials) if t.get("phase") == "treatment"),
            trials[-1],
        )
        result = dict(last_treatment["capture"])
        result["stdout"] = last_treatment.get("target_stdout") or ""
        result["stderr"] = last_treatment.get("raw_stderr") or ""
    else:
        signal_matched = None
        verdict = "inconclusive"

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
            "oracle_k": oracle_k,
        },
        "oracle": oracle_meta,
        "ran": bool(result.get("ran")),
        "exit_code": result.get("exit_code"),
        "timed_out": bool(result.get("timed_out")),
        "spawn_error": result.get("spawn_error"),
        "duration_ms": result.get("duration_ms"),
        "argv": _redact_marker(result.get("argv"), [canary, oracle_mark]),
        "stdout_excerpt": _truncate(
            str(_redact_marker(result.get("stdout") or "", [canary, oracle_mark])),
            8000,
        ),
        "stderr_excerpt": _truncate(
            str(_redact_marker(result.get("stderr") or "", [canary, oracle_mark])),
            4000,
        ),
        "suggested_finding_action": suggested,
        "operator_hint": operator_hint or result.get("operator_hint"),
        "env_dropped": env_dropped,
        "caveats": [
            "Sandbox output is evidence only. It is not exploit proof and does not confirm the finding.",
            "signal_observed requires the harness canary on target stdout (fd 3) for every treatment run, absent when the trigger is neutralized, with exit 0. A marker in the PoC source, args, or the PoC's own streams is not a signal.",
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
