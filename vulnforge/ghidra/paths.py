"""Resolve binary_re Ghidra/MCP paths relative to the VulnForge project root.

Portable layout (no machine-specific absolutes required):

  <project>/
    ghidra/                 # Ghidra distribution (ghidraRun.bat, Ghidra/, support/)
    ghidra-mcp/             # optional: bethington/ghidra-mcp clone + build
    scripts/start_ghidra_mcp_headless.ps1
    config/default.yaml     # binary_re.ghidra_install_dir: ghidra
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

# vulnforge/ghidra/paths.py → parents[2] = package root (VulnForge repo)
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def project_root() -> Path:
    """VulnForge package/repo root (directory containing config/, vulnforge/)."""
    env = (os.environ.get("VULNFORGE_ROOT") or "").strip()
    if env:
        return Path(env).expanduser().resolve()
    return PROJECT_ROOT


def resolve_path(
    value: str | Path | None,
    *,
    base: Path | None = None,
    must_exist: bool = False,
) -> Optional[Path]:
    """Resolve a config path: absolute stays absolute; relative is under base (project root)."""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    p = Path(s).expanduser()
    if not p.is_absolute():
        root = base or project_root()
        p = (root / p).resolve()
    else:
        p = p.resolve()
    if must_exist and not p.exists():
        return None
    return p


def default_ghidra_install_dir(base: Path | None = None) -> Path:
    return resolve_path("ghidra", base=base) or (project_root() / "ghidra")


def default_mcp_jar(base: Path | None = None) -> Optional[Path]:
    """First existing GhidraMCP jar under the project layout."""
    root = base or project_root()
    candidates = [
        root / "ghidra-mcp" / "build" / "libs" / "GhidraMCP-5.15.0.jar",
        root / "ghidra-mcp" / "build" / "libs" / "GhidraMCP.jar",
    ]
    # Also any GhidraMCP*.jar in build/libs
    libs = root / "ghidra-mcp" / "build" / "libs"
    if libs.is_dir():
        for j in sorted(libs.glob("GhidraMCP*.jar"), reverse=True):
            candidates.insert(0, j)
    # User extension install (Windows)
    appdata = os.environ.get("APPDATA") or ""
    if appdata:
        ext = Path(appdata) / "ghidra"
        if ext.is_dir():
            for j in ext.rglob("GhidraMCP*.jar"):
                candidates.append(j)
    for c in candidates:
        if c.is_file():
            return c.resolve()
    return None


def default_headless_script(base: Path | None = None) -> Path:
    return (base or project_root()) / "scripts" / "start_ghidra_mcp_headless.ps1"


def build_headless_command(br: dict[str, Any], base: Path | None = None) -> list[str] | str:
    """Return a command list/string to start headless MCP, or raise if impossible."""
    explicit = br.get("headless_command")
    if explicit:
        # Resolve embedded relative -File path when using default pattern
        if isinstance(explicit, list):
            return [str(x) for x in explicit]
        return str(explicit)

    root = base or project_root()
    script = resolve_path(br.get("headless_script") or "scripts/start_ghidra_mcp_headless.ps1", base=root)
    if script is None or not script.is_file():
        script = default_headless_script(root)
    if not script.is_file():
        raise FileNotFoundError(
            f"headless start script missing: {script}. "
            "Set binary_re.headless_command or place scripts/start_ghidra_mcp_headless.ps1"
        )

    ghidra = resolve_path(br.get("ghidra_install_dir") or "ghidra", base=root)
    jar = resolve_path(br.get("ghidra_mcp_jar"), base=root) if br.get("ghidra_mcp_jar") else None
    if jar is None:
        jar = default_mcp_jar(root)

    # Prefer argv list (no shell) for reliable process control
    argv: list[str] = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script),
    ]
    if ghidra and ghidra.is_dir():
        argv.extend(["-GhidraHome", str(ghidra)])
    if jar and jar.is_file():
        argv.extend(["-McpJar", str(jar)])
    port = br.get("mcp_port")
    if port:
        argv.extend(["-Port", str(int(port))])
    return argv


def normalize_binary_re_paths(br: dict[str, Any], base: Path | None = None) -> dict[str, Any]:
    """Copy binary_re config and resolve path fields to absolute paths for runtime."""
    out = dict(br)
    root = base or project_root()
    out["project_root"] = str(root)

    ghidra = resolve_path(out.get("ghidra_install_dir") or "ghidra", base=root)
    if ghidra is not None:
        out["ghidra_install_dir"] = str(ghidra)

    for key in ("ghidra_mcp_repo", "ghidra_mcp_jar", "headless_cwd", "headless_script"):
        if out.get(key):
            resolved = resolve_path(out[key], base=root)
            if resolved is not None:
                out[key] = str(resolved)

    if not out.get("ghidra_mcp_jar"):
        jar = default_mcp_jar(root)
        if jar:
            out["ghidra_mcp_jar"] = str(jar)

    if not out.get("headless_cwd"):
        out["headless_cwd"] = str(root)

    # Materialize headless_command if unset so subprocess has something concrete
    if not out.get("headless_command"):
        try:
            out["headless_command"] = build_headless_command(out, base=root)
        except FileNotFoundError:
            out["headless_command"] = None

    return out
