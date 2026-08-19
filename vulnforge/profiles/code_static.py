"""Default profile: source audit, read-only target, no process execution."""

from __future__ import annotations


class CodeStaticProfile:
    name = "code_static"
    allow_exec = False

    def allowed_tools(self) -> list[str]:
        """Built-in agent tools (registry) + operator-integrated extras."""
        try:
            from vulnforge.tools.registry import allowed_tool_names

            return allowed_tool_names(include_extras=True)
        except Exception:
            # Fallback if registry unavailable during early import
            return [
                "list_dir",
                "file_inventory",
                "read_file",
                "grep",
                "find_symbol",
                "query_sinks",
                "query_codemap",
                "query_flows",
                "get_architecture",
                "write_evidence",
                "list_evidence",
                "read_evidence",
                "preflight_candidate",
                "submit_candidate",
                "submit_none",
                "submit_architecture",
                "note",
                "list_hunt_profiles",
                "request_hunt",
                "continue_hunt",
                "continue_recon",
            ]

    def validate_target_hint(self, inventory: dict) -> str | None:
        from vulnforge.languages import SOURCE_EXTS

        ext = inventory.get("extensions") or {}
        total = sum(ext.values()) or 1
        binary_exts = {".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".class"}
        bin_count = sum(ext.get(e, 0) for e in binary_exts)
        src_count = sum(ext.get(e, 0) for e in SOURCE_EXTS)
        # Also accept language summary when extensions are sparse
        langs = inventory.get("languages") or {}
        if not src_count and isinstance(langs, dict):
            src_count = sum(int(v) for v in langs.values() if v)
        if bin_count / total > 0.7 and src_count == 0:
            return (
                "tree looks binary-heavy with little source; "
                "VulnForge is source-code analysis only — point at a source tree "
                "(C/C++/Ada/Java/Perl/Python/JS and other source trees are supported)"
            )
        return None
