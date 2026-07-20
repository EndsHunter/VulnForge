"""
Binary reverse-engineering profile: single PE target via Ghidra MCP (read-only).

Authorized research only — requires binary_re.i_am_authorized or CLI flag.

Portable paths (relative to VulnForge project root / VULNFORGE_ROOT):
  ghidra/                 Ghidra distribution
  ghidra-mcp/             optional MCP build tree
  scripts/start_ghidra_mcp_headless.ps1
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """Raised when binary_re is misconfigured or unauthorized."""


class BinaryReProfile:
    name = "binary_re"
    allow_exec = False  # analysis tools only; never execute the target binary

    # Curated Ghidra wrappers (see vulnforge/tools/ghidra_tools.py)
    GHIDRA_TOOLS = [
        "ghidra_status",
        "ghidra_metadata",
        "ghidra_list_functions",
        "ghidra_decompile",
        "ghidra_disassemble",
        "ghidra_xrefs",
        "ghidra_imports",
        "ghidra_import_callers",
        "ghidra_exports",
        "ghidra_strings",
        "ghidra_call_graph",
        "ghidra_search_bytes",
        "ghidra_function_at",
    ]

    SHARED_TOOLS = [
        "write_evidence",
        "submit_candidate",
        "submit_none",
        "submit_architecture",
        "note",
        "list_hunt_profiles",
        "request_hunt",
    ]

    DEFAULT_EXTENSIONS = (".exe", ".dll")

    def allowed_tools(self) -> list[str]:
        return list(self.GHIDRA_TOOLS) + list(self.SHARED_TOOLS)

    def require_authorization_flag(self, cfg: dict) -> None:
        """Hard gate: refuse unless authorized via config or CLI overlay."""
        br = cfg.get("binary_re") if isinstance(cfg.get("binary_re"), dict) else {}
        if bool(br.get("i_am_authorized")):
            return
        run = cfg.get("run") if isinstance(cfg.get("run"), dict) else {}
        if bool(run.get("binary_re_authorized")):
            return
        raise ConfigError(
            "binary_re requires authorization: set binary_re.i_am_authorized: true "
            "in config or pass --i-am-authorized-for-binary-re on init"
        )

    def validate_target(self, target: Path, cfg: dict | None = None) -> str | None:
        """Return error string if target is invalid for binary_re; else None."""
        t = Path(target)
        if not t.is_file():
            return f"binary_re target must be a single file: {t}"
        br = (cfg or {}).get("binary_re") if isinstance((cfg or {}).get("binary_re"), dict) else {}
        exts = br.get("allowed_extensions") or list(self.DEFAULT_EXTENSIONS)
        exts_n = {
            str(e).lower() if str(e).startswith(".") else f".{str(e).lower()}" for e in exts
        }
        if t.suffix.lower() not in exts_n:
            return f"binary_re v1 supports {sorted(exts_n)} only; got {t.suffix!r}"
        return None

    def validate_target_hint(self, inventory: dict) -> str | None:
        """Hint for wrong-profile detection (source tree vs binary)."""
        if inventory.get("kind") == "single_binary":
            return None
        ext = inventory.get("extensions") or {}
        total = sum(ext.values()) or 1
        source_exts = {".py", ".js", ".ts", ".go", ".rs", ".java", ".c", ".cpp", ".rb"}
        src_count = sum(ext.get(e, 0) for e in source_exts)
        if src_count / total > 0.5:
            return "tree looks source-heavy; use code_static profile instead of binary_re"
        return None

    def binary_re_config(self, cfg: dict) -> dict[str, Any]:
        """Normalized binary_re config with project-relative path defaults resolved."""
        br = dict(cfg.get("binary_re") or {}) if isinstance(cfg.get("binary_re"), dict) else {}
        # Portable defaults (relative to project root — resolved in ghidra.paths)
        br.setdefault("ghidra_install_dir", "ghidra")
        br.setdefault("mcp_base_url", "http://127.0.0.1:8089")
        br.setdefault("headless_command", None)  # auto-built from headless_script
        br.setdefault("headless_script", "scripts/start_ghidra_mcp_headless.ps1")
        br.setdefault("headless_cwd", None)  # defaults to project root
        br.setdefault("ghidra_mcp_repo", "ghidra-mcp")
        br.setdefault("ghidra_mcp_jar", None)  # auto-discover under ghidra-mcp/build/libs
        br.setdefault("start_timeout_seconds", 180)
        br.setdefault("analyze_timeout_seconds", 600)
        # Ghidra project workspace under the *run* dir (not the Ghidra install)
        br.setdefault("project_subdir", "ghidra_project")
        br.setdefault("allowed_extensions", list(self.DEFAULT_EXTENSIONS))
        br.setdefault("i_am_authorized", False)
        br.setdefault("max_decompile_chars", 24000)
        br.setdefault("max_list_page", 100)
        br.setdefault("request_timeout_seconds", 45)

        from vulnforge.ghidra.paths import normalize_binary_re_paths

        return normalize_binary_re_paths(br)
