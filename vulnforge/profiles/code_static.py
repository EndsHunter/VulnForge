"""Default profile: source audit, read-only target, no process execution."""

from __future__ import annotations


class CodeStaticProfile:
    name = "code_static"
    allow_exec = False

    def allowed_tools(self) -> list[str]:
        base = [
            "list_dir",
            "file_inventory",
            "read_file",
            "grep",
            "write_evidence",
            "submit_candidate",
            "submit_none",
            "submit_architecture",
            "note",
        ]
        try:
            from vulnforge.tools.extra_registry import extra_tool_names

            for n in extra_tool_names():
                if n not in base:
                    base.append(n)
        except Exception:
            pass
        return base

    def validate_target_hint(self, inventory: dict) -> str | None:
        ext = inventory.get("extensions") or {}
        total = sum(ext.values()) or 1
        binary_exts = {".exe", ".dll", ".so", ".dylib", ".bin"}
        bin_count = sum(ext.get(e, 0) for e in binary_exts)
        source_exts = {".py", ".js", ".ts", ".go", ".rs", ".java", ".c", ".cpp", ".rb"}
        src_count = sum(ext.get(e, 0) for e in source_exts)
        if bin_count / total > 0.7 and src_count == 0:
            return "tree looks binary-heavy; consider binary_re profile later"
        return None
