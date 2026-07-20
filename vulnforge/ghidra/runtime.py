"""Run-scoped Ghidra headless lifecycle for binary_re.

Starts the GhidraMCP headless HTTP server (Java), loads the target PE, runs
auto-analysis, and only then reports ready. Windows process start breaks away
from Job Objects so the server survives after init/Ralph exit.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Optional

from vulnforge.ghidra.client import GhidraClient, GhidraError
from vulnforge.util import utc_now_iso, write_json


ProgressFn = Optional[Callable[[dict[str, Any]], None]]


def _find_java(br: dict[str, Any]) -> str:
    """Resolve java executable (JAVA_HOME or well-known Temurin paths)."""
    java_home = (br.get("java_home") or os.environ.get("JAVA_HOME") or "").strip()
    candidates: list[Path] = []
    if java_home:
        candidates.append(Path(java_home) / "bin" / "java.exe")
        candidates.append(Path(java_home) / "bin" / "java")
    candidates.extend(
        [
            Path(r"C:\Program Files\Eclipse Adoptium\jdk-25.0.3.9-hotspot\bin\java.exe"),
            Path(r"C:\Program Files\Eclipse Adoptium\jdk-21.0.7.6-hotspot\bin\java.exe"),
            Path(r"C:\Program Files\Java\jdk-25\bin\java.exe"),
            Path(r"C:\Program Files\Java\jdk-21\bin\java.exe"),
        ]
    )
    for c in candidates:
        if c.is_file():
            return str(c)
    return "java.exe" if os.name == "nt" else "java"


def _build_ghidra_classpath(ghidra_home: Path, mcp_jar: Path) -> str:
    jars: list[str] = [str(mcp_jar.resolve())]
    for sub in ("Framework", "Features", "Processors", "Configurations", "Debug"):
        root = ghidra_home / "Ghidra" / sub
        if root.is_dir():
            for p in root.rglob("*.jar"):
                jars.append(str(p))
    ls = ghidra_home / "support" / "LaunchSupport.jar"
    if ls.is_file():
        jars.append(str(ls))
    # de-dupe preserve order
    seen: set[str] = set()
    out: list[str] = []
    for j in jars:
        if j not in seen:
            seen.add(j)
            out.append(j)
    sep = ";" if os.name == "nt" else ":"
    return sep.join(out)


def build_direct_java_argv(br: dict[str, Any]) -> list[str]:
    """Build ``java … GhidraMCPHeadlessServer`` argv (no PowerShell wrapper)."""
    from vulnforge.ghidra.paths import default_mcp_jar, project_root, resolve_path

    root = project_root()
    ghidra = resolve_path(br.get("ghidra_install_dir") or "ghidra", base=root)
    if ghidra is None or not ghidra.is_dir():
        raise GhidraError(
            f"Ghidra install not found at {ghidra or 'ghidra'}. "
            "Place a Ghidra distribution in ./ghidra under the project root."
        )
    jar: Path | None = None
    if br.get("ghidra_mcp_jar"):
        jar = resolve_path(br["ghidra_mcp_jar"], base=root)
    if jar is None or not jar.is_file():
        jar = default_mcp_jar(root)
    if jar is None or not jar.is_file():
        raise GhidraError(
            "GhidraMCP jar not found (expected ghidra-mcp/build/libs/GhidraMCP*.jar). "
            "Build ghidra-mcp against ./ghidra first."
        )
    java = _find_java(br)
    classpath = _build_ghidra_classpath(ghidra, jar)
    port = str(int(br.get("mcp_port") or 8089))
    bind = str(br.get("mcp_bind") or "127.0.0.1")
    xmx = str(br.get("java_xmx") or "4G")
    return [
        java,
        f"-Xmx{xmx}",
        f"-Dghidra.home={ghidra}",
        "-Dapplication.name=GhidraMCP",
        "-classpath",
        classpath,
        "com.xebyte.headless.GhidraMCPHeadlessServer",
        "--port",
        port,
        "--bind",
        bind,
    ]


class GhidraRuntime:
    """Start/attach GhidraMCP, import binary, run analysis; persist state under run_dir."""

    def __init__(
        self,
        run_dir: Path,
        target_binary: Path,
        cfg: dict,
        *,
        progress: ProgressFn = None,
    ) -> None:
        self.run_dir = Path(run_dir)
        self.target_binary = Path(target_binary).resolve()
        self.cfg = cfg
        self.progress = progress
        from vulnforge.profiles.binary_re import BinaryReProfile

        self.br = BinaryReProfile().binary_re_config(cfg)
        self.project_root = self.run_dir / str(
            self.br.get("project_subdir") or "ghidra_project"
        )
        self.runtime_path = self.project_root / "runtime.json"
        self.client = GhidraClient(
            str(self.br.get("mcp_base_url") or "http://127.0.0.1:8089"),
            timeout=float(self.br.get("request_timeout_seconds") or 60),
            auth_token=os.environ.get("GHIDRA_MCP_AUTH_TOKEN"),
        )

    def _prog(self, **kw: Any) -> None:
        if callable(self.progress):
            try:
                self.progress(kw)
            except Exception:
                pass

    def load_state(self) -> dict[str, Any]:
        if self.runtime_path.is_file():
            try:
                return json.loads(self.runtime_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return {}
        return {}

    def save_state(self, state: dict[str, Any]) -> None:
        self.project_root.mkdir(parents=True, exist_ok=True)
        write_json(self.runtime_path, state)

    def ensure_ready(self) -> dict[str, Any]:
        """Health-check, start headless if needed, load+analyze target PE."""
        state = self.load_state()
        # Only skip work if MCP is up AND the target program is actually loaded.
        if self.client.healthy() and self._program_loaded():
            state["ready"] = True
            state["imported"] = True
            state["analyzed"] = True
            state["ready_at"] = utc_now_iso()
            state["target"] = str(self.target_binary)
            self.save_state(state)
            self._prog(
                phase="ghidra",
                status="running",
                message="Ghidra MCP already ready with program loaded",
                percent=95,
            )
            return state

        self.project_root.mkdir(parents=True, exist_ok=True)
        if not self.client.healthy():
            self._start_headless(state)
        else:
            state["attached"] = True
            state["mcp_base_url"] = self.client.base_url
            self.save_state(state)

        self._import_and_analyze(state)
        if not self._program_loaded():
            raise GhidraError(
                "Ghidra MCP is up but no program is loaded after import/analyze. "
                f"Target={self.target_binary}"
            )
        state["ready"] = True
        state["ready_at"] = utc_now_iso()
        state["target"] = str(self.target_binary)
        self.save_state(state)
        self._prog(
            phase="ghidra",
            status="running",
            message="Ghidra ready (program loaded + analyzed)",
            percent=96,
        )
        return state

    def _start_headless(self, state: dict[str, Any]) -> None:
        log_dir = self.project_root
        log_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = log_dir / "headless_stdout.log"
        stderr_path = log_dir / "headless_stderr.log"

        # Prefer direct Java launch (reliable). Fall back to configured command.
        use_shell = False
        argv: list[str] | str
        try:
            argv = build_direct_java_argv(self.br)
            use_shell = False
        except GhidraError:
            cmd = self.br.get("headless_command")
            if not cmd:
                from vulnforge.ghidra.paths import build_headless_command

                try:
                    cmd = build_headless_command(self.br)
                except FileNotFoundError as e:
                    raise GhidraError(str(e)) from e
            if not cmd:
                raise GhidraError(
                    "Cannot start GhidraMCP: no Java argv and headless_command unset. "
                    "Need ./ghidra + ghidra-mcp/build/libs/GhidraMCP*.jar"
                )
            if isinstance(cmd, list):
                argv = [str(x) for x in cmd]
                use_shell = False
            elif isinstance(cmd, str):
                argv = cmd if os.name == "nt" else shlex.split(cmd)
                use_shell = os.name == "nt"
            else:
                raise GhidraError("binary_re.headless_command must be a string or list")

        cwd = self.br.get("headless_cwd") or self.br.get("ghidra_install_dir")
        cwd_path = Path(cwd) if cwd else None
        ghidra_home = self.br.get("ghidra_install_dir") or "ghidra"
        self._prog(
            phase="ghidra",
            status="running",
            message=f"Starting Ghidra headless MCP (install={ghidra_home})...",
            percent=40,
        )

        # Truncate logs for this start attempt
        try:
            stdout_path.write_bytes(b"")
            stderr_path.write_bytes(b"")
        except OSError:
            pass

        try:
            out_f = open(stdout_path, "ab")
            err_f = open(stderr_path, "ab")
            popen_kwargs: dict[str, Any] = {
                "args": argv,
                "cwd": str(cwd_path) if cwd_path and Path(cwd_path).is_dir() else None,
                "shell": use_shell,
                "stdout": out_f,
                "stderr": err_f,
                "close_fds": True,
            }
            if os.name == "nt":
                # Break away from Job Objects (dashboard/Ralph shells kill children).
                # Do NOT use DETACHED_PROCESS — it makes powershell/java exit 0 instantly.
                CREATE_NEW_PROCESS_GROUP = 0x00000200
                CREATE_BREAKAWAY_FROM_JOB = 0x01000000
                popen_kwargs["creationflags"] = (
                    CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB
                )
            proc = subprocess.Popen(**popen_kwargs)
            out_f.close()
            err_f.close()
        except OSError as e:
            raise GhidraError(f"failed to start headless Ghidra: {e}") from e

        state["pid"] = proc.pid
        state["started_at"] = utc_now_iso()
        state["mcp_base_url"] = self.client.base_url
        state["ghidra_install_dir"] = str(ghidra_home)
        state["headless_log"] = str(stderr_path)
        state["headless_argv0"] = (
            argv[0] if isinstance(argv, list) and argv else str(argv)[:80]
        )
        self.save_state(state)

        timeout = float(self.br.get("start_timeout_seconds") or 300)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.client.healthy():
                return
            rc = proc.poll()
            if rc is not None:
                # Parent may be a short-lived launcher; give Java a few seconds
                # to bind if a breakaway child is still coming up.
                grace_deadline = time.time() + 15
                while time.time() < grace_deadline:
                    if self.client.healthy():
                        return
                    time.sleep(0.5)
                tail = ""
                try:
                    if stderr_path.is_file():
                        tail = stderr_path.read_text(
                            encoding="utf-8", errors="replace"
                        )[-1200:]
                    if not tail.strip() and stdout_path.is_file():
                        tail = stdout_path.read_text(
                            encoding="utf-8", errors="replace"
                        )[-1200:]
                except OSError:
                    pass
                raise GhidraError(
                    f"headless Ghidra exited early with code {rc}. "
                    f"See {stderr_path}. {tail}"
                )
            time.sleep(1.0)
        raise GhidraError(
            f"Ghidra MCP not healthy within {timeout}s at {self.client.base_url}. "
            f"See {stderr_path}"
        )

    def _program_loaded(self) -> bool:
        """True if headless server has a program with listable functions."""
        try:
            data = self.client.list_functions(offset=0, limit=1)
        except GhidraError:
            return False
        if isinstance(data, dict):
            if data.get("error"):
                return False
            # our client wraps as {ok, data} or {ok, text}
            if data.get("ok") is False:
                return False
            text = str(data.get("text") or data.get("data") or data)
        else:
            text = str(data)
        low = text.lower()
        if "no program" in low or "not loaded" in low:
            return False
        if "error" in low and "fun_" not in low and "at " not in low:
            # bare error string
            if low.strip().startswith("{") and "error" in low:
                return False
        # Non-empty function listing text or structured list
        return bool(text.strip()) and text.strip() not in ("{}", "[]", "null")

    def _import_and_analyze(self, state: dict[str, Any]) -> None:
        if self._program_loaded():
            state["imported"] = True
            state["analyzed"] = True
            self.save_state(state)
            return

        proj_name = "vf_binary"
        proj_dir = str(self.project_root.resolve())
        self.project_root.mkdir(parents=True, exist_ok=True)
        self._prog(
            phase="ghidra",
            status="running",
            message="Creating/opening Ghidra project...",
            percent=55,
        )
        try:
            self.client.create_project(proj_dir, proj_name)
        except GhidraError:
            try:
                self.client.open_project(str(Path(proj_dir) / f"{proj_name}.gpr"))
            except GhidraError:
                pass

        self._prog(
            phase="ghidra",
            status="running",
            message=f"Loading {self.target_binary.name} into headless Ghidra...",
            percent=65,
        )
        binary = str(self.target_binary)
        try:
            result = self.client.load_program(binary)
            if isinstance(result, dict) and result.get("error"):
                raise GhidraError(str(result.get("error")))
            if isinstance(result, dict) and result.get("ok") is True:
                inner = result.get("data")
                if isinstance(inner, dict) and inner.get("error"):
                    raise GhidraError(str(inner.get("error")))
        except GhidraError as e:
            # Last resort: GUI import endpoint (usually fails headless)
            try:
                self.client.import_file(binary, project_path=proj_dir)
            except GhidraError as e2:
                if not self._program_loaded():
                    raise GhidraError(
                        f"load_program failed: {e}; import_file: {e2}"
                    ) from e2

        state["imported"] = True
        state["project_dir"] = proj_dir
        self.save_state(state)

        self._prog(
            phase="ghidra",
            status="running",
            message="Running Ghidra auto-analysis (may take several minutes)...",
            percent=75,
        )
        analyze_to = float(self.br.get("analyze_timeout_seconds") or 900)
        try:
            result = self.client.run_analysis()
            if isinstance(result, dict) and result.get("error"):
                # continue if functions already present
                if not self._program_loaded():
                    raise GhidraError(str(result.get("error")))
        except GhidraError as e:
            if not self._program_loaded():
                raise GhidraError(f"analysis failed: {e}") from e

        deadline = time.time() + min(analyze_to, 300)
        while time.time() < deadline:
            if self._program_loaded():
                break
            time.sleep(1.5)
        if not self._program_loaded():
            raise GhidraError("program still not loaded after analysis wait")
        state["analyzed"] = True
        self.save_state(state)

    def stop(self) -> None:
        """Best-effort stop of process we started (does not kill foreign Ghidra)."""
        state = self.load_state()
        pid = state.get("pid")
        if not pid:
            return
        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    capture_output=True,
                    check=False,
                )
            else:
                os.kill(int(pid), 15)
        except OSError:
            pass
        state["stopped_at"] = utc_now_iso()
        state["ready"] = False
        self.save_state(state)


def ensure_ghidra_for_run(
    run_dir: Path,
    target_binary: Path,
    cfg: dict,
    *,
    progress: ProgressFn = None,
) -> GhidraRuntime:
    """Construct runtime and ensure MCP is ready for the binary."""
    # Merge full cfg: binary_re_config needs top-level binary_re block
    rt = GhidraRuntime(run_dir, target_binary, cfg, progress=progress)
    rt.ensure_ready()
    return rt


def client_from_cfg(cfg: dict) -> GhidraClient:
    from vulnforge.profiles.binary_re import BinaryReProfile

    br = BinaryReProfile().binary_re_config(cfg)
    return GhidraClient(
        str(br.get("mcp_base_url") or "http://127.0.0.1:8089"),
        timeout=float(br.get("request_timeout_seconds") or 60),
        auth_token=os.environ.get("GHIDRA_MCP_AUTH_TOKEN"),
    )
