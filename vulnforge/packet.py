"""
Context packet builder — keep each LLM call under budget.

Tool-loop context: each stage packet's tools_schema is the only tool surface the
model should see for that call (recon has no submit_candidate; disprove is text-only).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


class OverBudgetError(Exception):
    pass


@dataclass
class Packet:
    system: str
    user: str
    tools_schema: list[dict] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    over_budget: bool = False


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def load_prompt_slice(prompts_root: Path, relative: str) -> str:
    root = prompts_root.resolve()
    path = (root / relative).resolve()
    if root not in path.parents and path != root:
        raise PermissionError(f"path escape: {relative}")
    if not path.is_file():
        raise FileNotFoundError(path)
    return path.read_text(encoding="utf-8")


def _load_hunt_class_body(cls: str) -> str:
    """Load hunt class markdown from the operator collection (not package prompts)."""
    from vulnforge.hunt_profiles import HuntProfileError, get_body, normalize_class

    want = normalize_class(cls)
    try:
        return get_body(want)
    except HuntProfileError:
        pass
    if want != "wildcard":
        try:
            return get_body("wildcard")
        except HuntProfileError:
            pass
    return (
        f"# Hunt class: {want}\n\n"
        "(No body registered for this class. Use tools and submit carefully.)\n"
    )


def format_hunt_class_registry_section(
    allowed_ids: list[str] | None = None,
    *,
    mode: str | None = None,
    skill_ids: list[str] | None = None,
) -> str:
    """Dynamic class list for recon packets (active vs optional).

    When ``mode`` / ``skill_ids`` or ``allowed_ids`` restrict the run, only list
    those class ids (operator run policy — not the full Dev catalog).
    """
    from vulnforge.hunt_profiles import (
        filter_profiles_for_run,
        list_profiles,
        resolve_run_class_ids,
    )

    restricted = False
    if allowed_ids is not None:
        allowed_set = set(allowed_ids)
        restricted = True
        try:
            profiles = [
                p for p in list_profiles(include_body=False) if p.get("id") in allowed_set
            ]
            # Preserve allowlist order when possible
            by_id = {p["id"]: p for p in profiles}
            profiles = [by_id[i] for i in allowed_ids if i in by_id]
        except Exception:
            profiles = []
    elif mode is not None or skill_ids is not None:
        mode_n = mode or "all_active"
        restricted = str(mode_n).strip().lower().replace("-", "_") != "all_active"
        try:
            if restricted:
                allowed = resolve_run_class_ids(mode_n, skill_ids)
                profiles = filter_profiles_for_run(mode_n, skill_ids)
                by_id = {p["id"]: p for p in profiles}
                profiles = [by_id[i] for i in allowed if i in by_id]
            else:
                profiles = list_profiles(include_body=False)
        except Exception:
            profiles = []
    else:
        try:
            profiles = list_profiles(include_body=False)
        except Exception:
            return (
                "\n## Registered hunt classes\n"
                "(collection unavailable — use only well-known short class ids)\n"
            )

    if not profiles and restricted:
        return (
            "\n## Registered hunt classes (use only these ids in hunt_focus)\n"
            "\n(none allowed for this run's hunt skill mode — leave hunt_focus "
            "empty or the planner will enqueue zero hunts)\n"
        )
    if not profiles:
        return "\n## Registered hunt classes\n(none registered)\n"
    lines = [
        "\n## Registered hunt classes (use only these ids in hunt_focus)",
        "",
        "Prefer a **small** set. **Active** profiles are used when you omit hunt_focus."
        if not restricted
        else "This run restricts hunt classes to the list below. Do not invent others.",
        "",
    ]
    if restricted:
        lines.extend(
            [
                "### Allowed for this run",
                "",
                "| class id | title |",
                "|----------|-------|",
            ]
        )
        for p in profiles:
            title = (p.get("title") or p["id"]).replace("|", "/")
            desc = (p.get("description") or "").replace("|", "/")
            label = f"{title}" + (f" — {desc}" if desc else "")
            lines.append(f"| `{p['id']}` | {label} |")
    else:
        lines.extend(
            [
                "### Active (bulk / fallback enqueue)",
                "",
                "| class id | title |",
                "|----------|-------|",
            ]
        )
        active = [p for p in profiles if p.get("active")]
        inactive = [p for p in profiles if not p.get("active")]
        if not active:
            active = list(profiles)
            inactive = []
        for p in active:
            title = (p.get("title") or p["id"]).replace("|", "/")
            desc = (p.get("description") or "").replace("|", "/")
            label = f"{title}" + (f" — {desc}" if desc else "")
            lines.append(f"| `{p['id']}` | {label} |")
        if inactive:
            lines.extend(
                [
                    "",
                    "### Optional (include only when inventory warrants)",
                    "",
                    "| class id | title |",
                    "|----------|-------|",
                ]
            )
            for p in inactive:
                title = (p.get("title") or p["id"]).replace("|", "/")
                desc = (p.get("description") or "").replace("|", "/")
                label = f"{title}" + (f" — {desc}" if desc else "")
                lines.append(f"| `{p['id']}` | {label} |")
    lines.append("")
    lines.append(
        "Never invent class ids outside this list. "
        "`hunt_focus` items: "
        '`{ "area": "...", "class": "<id>", "path_hints": ["..."] }`.'
    )
    lines.append("")
    return "\n".join(lines)


def truncate(text: str, max_chars: int, label: str = "") -> str:
    if len(text) <= max_chars:
        return text
    return text[: max(0, max_chars - 40)] + f"\n...[truncated {label} chars={len(text)}]...\n"


def _budget_chars(cfg: dict) -> int:
    # rough: assume 32k context * 0.25 * 4 chars/token ≈ 32k chars default
    frac = float((cfg.get("llm") or {}).get("max_context_fraction", 0.25))
    # conservative default window if unknown
    window_tokens = int((cfg.get("llm") or {}).get("context_tokens", 32768))
    return max(4000, int(window_tokens * frac * 4))


def refuse_if_over_budget(packet: Packet) -> None:
    if packet.over_budget:
        raise OverBudgetError(packet.meta)


def _principles_without_hunt_tools(prompts_root: Path) -> str:
    """PRINCIPLES severity/exclusions/self-verify — drop Evidence/Tools hunt sections."""
    full = load_prompt_slice(prompts_root, "PRINCIPLES.md")
    cut_markers = ("\n## Evidence rules", "\n## Tools\n")
    cut_at = len(full)
    for m in cut_markers:
        i = full.find(m)
        if i >= 0:
            cut_at = min(cut_at, i)
    return full[:cut_at].rstrip() + "\n"


def tool_schemas_for(
    profile: str,
    stage: str,
    *,
    apply_defaults: bool = True,
) -> list[dict]:
    """OpenAI-style tool schemas for profile stages.

    When apply_defaults is True (runtime packets), operator global defaults from
    config/default_tools.json may narrow the set. Catalog / Dev UI should pass
    apply_defaults=False to list the full integrated surface.
    """

    def fn(name: str, description: str, properties: dict, required: list[str] | None = None):
        return {
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required or [],
                },
            },
        }

    def _finish(tools: list[dict]) -> list[dict]:
        if not apply_defaults or stage not in ("recon", "hunt", "develop_poc"):
            return tools
        try:
            from vulnforge.tools.default_tools import resolve_stage_tools

            names: list[str] = []
            for t in tools:
                fn_obj = (t.get("function") or {}) if isinstance(t, dict) else {}
                n = fn_obj.get("name") if isinstance(fn_obj, dict) else None
                if n:
                    names.append(str(n))
            resolved = resolve_stage_tools(stage, names)
            if list(resolved) == names:
                return tools
            always = (
                HUNT_ALWAYS_KEEP_TOOLS
                if stage == "hunt"
                else RECON_ALWAYS_KEEP_TOOLS
                if stage == "recon"
                else frozenset({"write_evidence"})
            )
            return _filter_tools_by_allowlist(tools, resolved, always_keep=always)
        except Exception:
            return tools

    # Read-only target inspection (shared). Hunt-only tools added per stage.
    # Descriptions are operator-facing AND model-facing: local models need
    # when-to-use, path rules, and finish contracts in the tool schema itself.
    ro = [
        fn(
            "list_dir",
            "List ONE directory level under the audit target (read-only). "
            "Paths are relative to the target root (use '.' for root). "
            "Returns names + is_dir only — not recursive. "
            "Prefer file_inventory for a full subtree or tree in one call; "
            "use list_dir when you only need children of a known folder.",
            {
                "path": {
                    "type": "string",
                    "description": (
                        "Directory relative to target root. "
                        "Default '.' if omitted. No leading slash; no '..'."
                    ),
                },
                "max_entries": {
                    "type": "integer",
                    "description": (
                        "Max children to return (default from config, often 200). "
                        "If truncated is true, narrow path or raise cap carefully."
                    ),
                },
            },
            [],
        ),
        fn(
            "file_inventory",
            "Recursive file inventory / directory tree under a path (read-only). "
            "Prefer this over many list_dir rounds. "
            "Filter with extension (e.g. '.c', 'py', '*.go') or glob ('**/pkcs11/*'). "
            "format=tree for structure, list for paths, both for both. "
            "If truncated, narrow path/depth or add extension/glob — do not re-walk "
            "the whole tree with the same args.",
            {
                "path": {
                    "type": "string",
                    "description": (
                        "Subtree root relative to target (default '.'). "
                        "E.g. 'src/libopensc' to inventory one package."
                    ),
                },
                "max_depth": {
                    "type": "integer",
                    "description": (
                        "Max directory depth from path (default from config, often 10). "
                        "Lower depth for huge trees."
                    ),
                },
                "max_entries": {
                    "type": "integer",
                    "description": (
                        "Max files to return (default from config, often 2000). "
                        "Response includes truncated=true when capped."
                    ),
                },
                "extension": {
                    "type": "string",
                    "description": (
                        "Keep only this file extension: '.c', 'c', or '*.c' all work. "
                        "Case-insensitive."
                    ),
                },
                "glob": {
                    "type": "string",
                    "description": (
                        "fnmatch on full relative path or basename, e.g. '*.go', "
                        "'**/tools/*', 'Makefile*'."
                    ),
                },
                "format": {
                    "type": "string",
                    "enum": ["tree", "list", "both"],
                    "description": (
                        "tree (default): indented tree string; "
                        "list: paths array; both: tree + paths."
                    ),
                },
            },
            [],
        ),
        fn(
            "read_file",
            "Read a text file (or line range) from the audit target (read-only). "
            "path is relative to the target root. "
            "start_line/end_line are 1-based inclusive line numbers "
            "(omit both to read from the start, subject to max size). "
            "Large files are truncated — use a line range for long sources. "
            "Prefer grep to find a symbol, then read_file around that line. "
            "Never invent path contents; only cite what this tool returns.",
            {
                "path": {
                    "type": "string",
                    "description": (
                        "File path relative to target root, e.g. 'src/tools/opensc-tool.c'. "
                        "Must be a file, not a directory."
                    ),
                },
                "start_line": {
                    "type": "integer",
                    "description": (
                        "First line to include (1-based). Default 1 if end_line is set. "
                        "Omit both start and end to read from line 1 (may truncate)."
                    ),
                },
                "end_line": {
                    "type": "integer",
                    "description": (
                        "Last line to include (1-based, inclusive). "
                        "Omit to read through end of file (or max bytes)."
                    ),
                },
            },
            ["path"],
        ),
        fn(
            "grep",
            "Search target files with a regex (read-only). "
            "pattern is a Python/PCRE-style regex over file lines "
            "(or over path/filename when match_path=true). "
            "Narrow with extension and/or glob before broad searches on large trees. "
            "files_only=true returns unique paths only (faster inventory of hits). "
            "Empty pattern + extension or glob lists matching files by path "
            "(prefer file_inventory for directory trees). "
            "On 0 matches, read the response hint — do not repeat the same empty query. "
            "Avoid catastrophic regex (nested quantifiers are rejected).",
            {
                "pattern": {
                    "type": "string",
                    "description": (
                        "Regex to match file lines (default mode). "
                        "With match_path=true, also matches relative path/filename. "
                        "Empty string allowed only with extension/glob/match_path "
                        "for path-listing mode."
                    ),
                },
                "glob": {
                    "type": "string",
                    "description": (
                        "Limit scan to paths matching fnmatch, e.g. '*.py', "
                        "'**/pkcs11/*', 'src/tools/*'."
                    ),
                },
                "extension": {
                    "type": "string",
                    "description": (
                        "Limit scan to this extension: '.c', 'c', or '*.c'."
                    ),
                },
                "files_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return unique matching paths only "
                        "(no line text). Good for building a read list."
                    ),
                },
                "match_path": {
                    "type": "boolean",
                    "description": (
                        "If true, also match pattern against relative path and "
                        "basename (filename search)."
                    ),
                },
                "max_matches": {
                    "type": "integer",
                    "description": (
                        "Stop after this many hits (default from config). "
                        "Lower on huge trees to keep responses small."
                    ),
                },
            },
            [],
        ),
        fn(
            "note",
            "Store a short operator-facing note (not a finding). "
            "kind=codemap: interesting path/symbol for the project CODEMAP. "
            "kind=wishlist: missing tool or capability you wished you had. "
            "kind=sibling_seed: area/class/path idea for a future hunt sibling. "
            "Does not finish the task — still call submit_* when done.",
            {
                "kind": {
                    "type": "string",
                    "enum": ["wishlist", "sibling_seed", "codemap"],
                    "description": "Note category (see tool description).",
                },
                "payload": {
                    "description": (
                        "Object or string body. "
                        "codemap: {\"path\": \"...\", \"symbol\": \"...\", \"note\": \"...\"} "
                        "or a short string. "
                        "wishlist: {\"need\": \"...\", \"why\": \"...\"} or string. "
                        "sibling_seed: {\"area\": \"...\", \"class\": \"injection\", "
                        "\"path_hints\": [\"...\"]}."
                    ),
                },
            },
            ["kind", "payload"],
        ),
    ]
    if stage == "recon":
        # No write_evidence / submit_candidate / submit_none — architecture only.
        ro.append(
            fn(
                "submit_architecture",
                "Finish recon: submit the architecture map (not vulnerabilities). "
                "Call exactly once when done exploring. "
                "summary is required and must be non-empty. "
                "Prefer path-backed components, input_surfaces, and hunt_focus "
                "from files you actually listed/read/grepped. "
                "hunt_focus.class must be a registered hunt class id from the "
                "prompt registry (never invent ids). "
                "Do not call submit_candidate or submit_none in recon.",
                {
                    "summary": {
                        "type": "string",
                        "description": (
                            "1–3 paragraphs: what the system is, main modules, "
                            "and attacker-relevant shape. Non-empty required."
                        ),
                    },
                    "trust_boundaries": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Boundaries untrusted input crosses, e.g. "
                            "'CLI argv → libopensc', 'PKCS#11 app → token', "
                            "'config file → parser'."
                        ),
                    },
                    "components": {
                        "type": "array",
                        "description": (
                            "Major modules/packages with path_hints you inspected."
                        ),
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {
                                    "type": "string",
                                    "description": "Component name (e.g. pkcs11, tools)",
                                },
                                "path_hints": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": (
                                        "Relative paths under the target "
                                        "(dirs or key files)."
                                    ),
                                },
                                "role": {
                                    "type": "string",
                                    "description": "Optional short role description.",
                                },
                            },
                        },
                    },
                    "input_surfaces": {
                        "type": "array",
                        "description": (
                            "Where untrusted data enters. Prefer short path-backed "
                            "strings, or objects with name + path_hints."
                        ),
                        "items": {
                            "anyOf": [
                                {"type": "string"},
                                {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "path_hints": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                        },
                                        "protocol": {"type": "string"},
                                    },
                                },
                            ]
                        },
                    },
                    "hunt_focus": {
                        "type": "array",
                        "description": (
                            "Optional small set of area × registered class × path_hints "
                            "for later hunts. Omit weak/generic focus."
                        ),
                        "items": {
                            "type": "object",
                            "properties": {
                                "area": {
                                    "type": "string",
                                    "description": "Logical area name (often a component).",
                                },
                                "class": {
                                    "type": "string",
                                    "description": (
                                        "Registered hunt class id only "
                                        "(e.g. injection, memory-safety, cryptography)."
                                    ),
                                },
                                "path_hints": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Paths to bound the hunt.",
                                },
                            },
                        },
                    },
                },
                ["summary"],
            )
        )
        return _finish(ro)
    if stage == "hunt":
        ro.extend(
            [
                fn(
                    "write_evidence",
                    "Write a text file into this task's evidence pack under evidence/ "
                    "(never into the audit target). "
                    "Use for notes, excerpts, or draft PoC material. "
                    "relpath is relative to the pack root (e.g. 'notes.md', 'excerpt.c').",
                    {
                        "relpath": {
                            "type": "string",
                            "description": (
                                "Path inside the evidence pack only, e.g. 'notes.md'. "
                                "No '..' or absolute paths."
                            ),
                        },
                        "content": {
                            "type": "string",
                            "description": "Full file contents to write (UTF-8 text).",
                        },
                    },
                    ["relpath", "content"],
                ),
                fn(
                    "submit_candidate",
                    "Finish hunt with one vulnerability candidate (not confirmed). "
                    "Requires path-backed citations from files you read. "
                    "weakness_class should match this hunt's class when possible. "
                    "threat_model must state attacker, boundary crossed, and impact. "
                    "This is not exploit proof — human review decides confirmed. "
                    "Do not call submit_none after a successful candidate.",
                    {
                        "title": {
                            "type": "string",
                            "description": "Short specific title (not just the class name).",
                        },
                        "summary": {
                            "type": "string",
                            "description": (
                                "What is wrong, where, and why it matters. "
                                "Ground in citations."
                            ),
                        },
                        "weakness_class": {
                            "type": "string",
                            "description": (
                                "Weakness / hunt class id, e.g. injection, "
                                "access-control, memory-safety."
                            ),
                        },
                        "threat_model": {
                            "type": "object",
                            "description": "Who attacks, what boundary, what impact.",
                            "properties": {
                                "attacker": {
                                    "type": "string",
                                    "description": (
                                        "Who can reach the sink "
                                        "(e.g. local CLI user, remote PKCS#11 client)."
                                    ),
                                },
                                "boundary": {
                                    "type": "string",
                                    "description": (
                                        "Trust boundary crossed "
                                        "(e.g. untrusted APDU → parser)."
                                    ),
                                },
                                "impact": {
                                    "type": "string",
                                    "description": (
                                        "Concrete impact if exploited "
                                        "(RCE, auth bypass, secret leak, DoS…)."
                                    ),
                                },
                            },
                            "required": ["attacker", "boundary", "impact"],
                        },
                        "citations": {
                            "type": "array",
                            "description": (
                                "One or more code locations. path required; "
                                "include start_line/end_line when known."
                            ),
                            "items": {
                                "type": "object",
                                "properties": {
                                    "path": {
                                        "type": "string",
                                        "description": "Relative path under the target.",
                                    },
                                    "start_line": {
                                        "type": "integer",
                                        "description": "1-based start line.",
                                    },
                                    "end_line": {
                                        "type": "integer",
                                        "description": "1-based end line (inclusive).",
                                    },
                                    "symbol": {
                                        "type": "string",
                                        "description": "Optional function/type name.",
                                    },
                                },
                                "required": ["path"],
                            },
                        },
                        "evidence_id": {
                            "type": "string",
                            "description": (
                                "Optional evidence pack id if you wrote supporting files."
                            ),
                        },
                        "poc_relpath": {
                            "type": "string",
                            "description": (
                                "Optional path of a PoC file inside the evidence pack."
                            ),
                        },
                        "severity_claim": {
                            "type": "string",
                            "enum": [
                                "CRITICAL",
                                "HIGH",
                                "MEDIUM",
                                "LOW",
                                "INFORMATIONAL",
                            ],
                            "description": (
                                "Optional severity rating only — one of CRITICAL, HIGH, "
                                "MEDIUM, LOW, INFORMATIONAL. Not free-text impact prose "
                                "(put impact in threat_model.impact / summary)."
                            ),
                        },
                    },
                    ["title", "summary", "weakness_class", "threat_model", "citations"],
                ),
                fn(
                    "submit_none",
                    "Finish hunt with no solid finding after a real search. "
                    "reason must say what you checked and why nothing met the bar "
                    "(not just 'looks fine'). "
                    "Do not use submit_none to skip work; use tools first. "
                    "Do not call submit_candidate after submit_none.",
                    {
                        "reason": {
                            "type": "string",
                            "description": (
                                "Concrete negative result: paths/patterns checked "
                                "and residual uncertainty if any."
                            ),
                        },
                    },
                    ["reason"],
                ),
                fn(
                    "list_hunt_profiles",
                    "List registered hunt profile ids (and titles) you may pass to "
                    "request_hunt. Prefer active profiles. "
                    "No arguments. Call before request_hunt if you are unsure of ids.",
                    {},
                    [],
                ),
                fn(
                    "request_hunt",
                    "Queue a separate Ralph hunt for another registered profile "
                    "(does not finish this task). "
                    "Use when the current area clearly needs a different class skill "
                    "(e.g. auth code found during injection → access-control). "
                    "Rejected if that profile is already queued/leased, if it would "
                    "circularly re-queue a profile on this spawn chain (A→B→A), "
                    "or if spawn caps are hit. "
                    "Do not re-run the same profile as this task. "
                    "Still finish THIS hunt with submit_candidate or submit_none.",
                    {
                        "profile": {
                            "type": "string",
                            "description": (
                                "Registered hunt profile id "
                                "(e.g. injection, access-control). "
                                "Use list_hunt_profiles if unsure."
                            ),
                        },
                        "reason": {
                            "type": "string",
                            "description": (
                                "Why that class should run on this area "
                                "(path or symbol evidence)."
                            ),
                        },
                        "area": {
                            "type": "string",
                            "description": (
                                "Optional area override (default: this task's area)."
                            ),
                        },
                        "path_hints": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Optional paths to bound the spawned hunt "
                                "(default: this task's path_hints)."
                            ),
                        },
                        "force_depth": {
                            "type": "boolean",
                            "description": (
                                "If true (default), spawned hunt must use deeper "
                                "tools before submit_none."
                            ),
                        },
                    },
                    ["profile", "reason"],
                ),
            ]
        )
        return _finish(ro)
    if stage == "develop_poc":
        # Read tools already in ro; add write_evidence only (no submit_*).
        ro.append(
            fn(
                "write_evidence",
                "Write a file into the evidence pack (not the audit target). "
                "Prefer runnable PoC scripts: poc.py, poc.sh, poc.ps1, or poc.c. "
                "Also write/update hub poc_develop.md with run instructions only — "
                "do not rewrite the finding narrative. "
                "relpath is relative to the pack (or pack selected by evidence_id).",
                {
                    "relpath": {
                        "type": "string",
                        "description": (
                            "Path inside the evidence pack, e.g. 'poc.py', "
                            "'poc_develop.md'."
                        ),
                    },
                    "content": {
                        "type": "string",
                        "description": "Full file contents (UTF-8 text).",
                    },
                    "evidence_id": {
                        "type": "string",
                        "description": (
                            "Evidence pack id for this finding (use the task pack id)."
                        ),
                    },
                },
                ["relpath", "content"],
            )
        )
        return _finish(ro)
    if stage == "disprove":
        return []  # text-only

    # Operator-integrated extras (toolgen) for this stage.
    try:
        from vulnforge.tools.extra_registry import list_extra_specs

        for spec in list_extra_specs():
            stages = {str(s) for s in (spec.get("stages") or [])}
            if stage not in stages and stages:
                continue
            name = str(spec.get("name") or "").strip()
            if not name:
                continue
            params = spec.get("parameters") if isinstance(spec.get("parameters"), dict) else {}
            props = params.get("properties") if isinstance(params.get("properties"), dict) else {}
            req = params.get("required") if isinstance(params.get("required"), list) else []
            ro.append(
                fn(
                    name,
                    str(spec.get("description") or name),
                    dict(props),
                    [str(x) for x in req],
                )
            )
    except Exception:
        pass
    return _finish(ro)


def _filter_tools_by_allowlist(
    tools: list[dict],
    allowlist: list[str] | None,
    *,
    always_keep: frozenset[str] | set[str] | None = None,
) -> list[dict]:
    """Keep only named tools; always retain stage-critical submit tools."""
    if not allowlist:
        return tools
    want = {str(n).strip() for n in allowlist if str(n).strip()}
    keep = always_keep if always_keep is not None else frozenset({"submit_architecture"})
    want |= {str(x) for x in keep}
    out: list[dict] = []
    for t in tools:
        fn = (t.get("function") or {}) if isinstance(t, dict) else {}
        name = fn.get("name") if isinstance(fn, dict) else None
        if name and name in want:
            out.append(t)
    return out or tools


# Hunt stage must always be able to finish the task.
HUNT_ALWAYS_KEEP_TOOLS = frozenset(
    {
        "submit_candidate",
        "submit_none",
        "list_hunt_profiles",
        "request_hunt",
    }
)
RECON_ALWAYS_KEEP_TOOLS = frozenset({"submit_architecture"})


def pack_recon(
    cfg: dict,
    prompts_root: Path,
    inventory: dict,
    architecture_so_far: str = "",
    operator_brief: str = "",
    focus_paths: list | None = None,
) -> Packet:
    """Legacy single-packet recon using prompts/v1/recon.md (default-map equivalent)."""
    try:
        recon = load_prompt_slice(prompts_root, "recon.md")
    except FileNotFoundError:
        recon = (
            "# Recon\n\nMap architecture. Finish with submit_architecture.\n"
        )
    return pack_recon_agent(
        cfg,
        prompts_root,
        agent_body=recon,
        inventory=inventory,
        architecture_so_far=architecture_so_far,
        operator_brief=operator_brief,
        focus_paths=focus_paths,
        tools_allowlist=None,
        agent_id="legacy-recon",
    )


def pack_recon_agent(
    cfg: dict,
    prompts_root: Path,
    agent_body: str,
    inventory: dict,
    architecture_so_far: str = "",
    operator_brief: str = "",
    focus_paths: list | None = None,
    tools_allowlist: list[str] | None = None,
    agent_id: str = "",
) -> Packet:
    """Recon packet for one configurable recon agent body."""
    # Recon-focused system: shared preamble only — no hunt PRINCIPLES / submit tools.
    try:
        preamble = load_prompt_slice(prompts_root, "preamble.md")
    except FileNotFoundError:
        preamble = (
            "Authorized defensive review of the provided codebase only.\n"
            "Target is read-only. Use only provided tools.\n"
        )
    agent_label = (agent_id or "recon").strip() or "recon"
    tool_hint = (
        "Tools: prefer file_inventory over many list_dir; grep to find symbols; "
        "read_file with 1-based line ranges for long files; paths are relative to "
        "the target root. Call submit_architecture once when done.\n"
    )
    system = (
        preamble
        + "\n## Stage: recon\n"
        + f"Recon agent: **{agent_label}**. "
        + "Map architecture only. Do **not** file vulnerability candidates. "
        + "Do not call submit_candidate or submit_none. Finish with submit_architecture.\n"
        + tool_hint
    )
    recon = (agent_body or "").strip() + "\n"
    run_cfg = cfg.get("run") if isinstance(cfg.get("run"), dict) else {}
    skill_mode = run_cfg.get("hunt_skill_mode")
    skill_ids = run_cfg.get("hunt_skill_ids")
    if skill_mode is not None or skill_ids is not None:
        registry_section = format_hunt_class_registry_section(
            mode=str(skill_mode or "all_active"),
            skill_ids=skill_ids if isinstance(skill_ids, list) else None,
        )
    else:
        registry_section = format_hunt_class_registry_section()
    inv = {
        "file_count": inventory.get("file_count"),
        "extensions": inventory.get("extensions"),
        "entrypoints": inventory.get("entrypoints"),
        "sample_paths": (inventory.get("sample_paths") or [])[:80],
    }
    user = (
        recon
        + registry_section
        + "\n\n## Mechanical inventory\n```json\n"
        + json.dumps(inv, indent=2)
        + "\n```\n"
        + "Use tools to inspect paths. Finish with submit_architecture.\n"
    )
    if architecture_so_far:
        user += (
            "\n## Prior architecture (refine, correct, deepen — do not drop solid prior detail)\n"
            + truncate(architecture_so_far, 3500, "arch")
            + "\n"
        )
    if focus_paths:
        paths = [str(p) for p in focus_paths if p][:40]
        if paths:
            user += (
                "\n## Operator focus paths (inspect these carefully)\n"
                + "\n".join(f"- `{p}`" for p in paths)
                + "\n"
            )
    brief = (operator_brief or "").strip()
    if brief:
        user += (
            "\n## Operator brief (authoritative guidance for this recon)\n"
            + truncate(brief, 8000, "operator_brief")
            + "\n"
            + "Incorporate this guidance into hunt_focus path_hints and architecture summary.\n"
        )
    run_profile = str((cfg.get("run") or {}).get("profile") or "code_static")
    tools = tool_schemas_for(run_profile, "recon")
    tools = _filter_tools_by_allowlist(
        tools, tools_allowlist, always_keep=RECON_ALWAYS_KEEP_TOOLS
    )
    budget = _budget_chars(cfg)
    total = len(system) + len(user)
    over = total > budget
    return Packet(
        system=system,
        user=user if not over else truncate(user, max(1000, budget - len(system)), "user"),
        tools_schema=tools,
        meta={
            "chars": total,
            "budget": budget,
            "stage": "recon",
            "recon_agent_id": agent_label,
            "profile": run_profile,
        },
        over_budget=over and total > budget * 1.5,
    )


def _select_angles(angles_md: str, cls: str, max_angles: int = 4) -> str:
    """Pick 2–4 class-relevant angles from hunting_angles.md (slim packet)."""
    if not angles_md or max_angles <= 0:
        return ""
    # Prefer hunt profile metadata; fall back to hard-coded map.
    class_angles: dict[str, list[int]] = {
        "injection": [1, 3, 6, 7],
        "ai-llm": [3, 9, 11, 12],
        "access-control": [4, 5, 9, 12],
        "business-logic": [1, 4, 5, 9],
        "cryptography": [6, 8, 11, 12],
        "web-protocol-auth": [2, 6, 9, 12],
        "client-side": [3, 6, 7, 10],
        "memory-safety": [1, 2, 6, 7],
        "feature-abuse": [8, 9, 11, 12],
        "chains": [3, 4, 7, 9],
        "obvious": [1, 9, 10, 11],
        "supply-chain": [3, 8, 11, 12],
        "graphql": [3, 4, 9, 12],
        "wildcard": [1, 3, 9, 12],
    }
    want: list[int] = []
    try:
        from vulnforge.hunt_profiles import angle_ids_for_class

        want = list(angle_ids_for_class(str(cls)))[:max_angles]
    except Exception:
        want = []
    if not want:
        want = class_angles.get(cls, class_angles["wildcard"])[:max_angles]
    # Parse numbered items "N. **title**" blocks
    lines = angles_md.splitlines()
    blocks: dict[int, list[str]] = {}
    cur: int | None = None
    header: list[str] = []
    for line in lines:
        m = None
        stripped = line.strip()
        if stripped and stripped[0].isdigit() and ". " in stripped[:4]:
            try:
                num = int(stripped.split(".", 1)[0])
                if 1 <= num <= 12:
                    cur = num
                    blocks[cur] = [line]
                    continue
            except ValueError:
                pass
        if cur is not None:
            # stop at next section header
            if stripped.startswith("## ") and not stripped.startswith("## Prove"):
                cur = None
                continue
            blocks[cur].append(line)
        else:
            if stripped.startswith("#") or not blocks:
                header.append(line)
    picked: list[str] = []
    for n in want:
        if n in blocks:
            picked.extend(blocks[n])
            picked.append("")
    if not picked:
        # fallback: first max_angles numbered blocks
        for n in range(1, max_angles + 1):
            if n in blocks:
                picked.extend(blocks[n])
                picked.append("")
    intro = "\n".join(header[:6]).strip()
    body = "\n".join(picked).strip()
    if not body:
        return truncate(angles_md, 1200, "angles")
    return (intro + "\n\n" + body).strip() + "\n"


def pack_hunt(
    cfg: dict,
    prompts_root: Path,
    task_payload: dict,
    architecture: str,
    known_keys: list[str],
    codemap_notes: list[str],
    seed_sinks: list | None = None,
    known_findings: list[str] | None = None,
) -> Packet:
    system = load_prompt_slice(prompts_root, "PRINCIPLES.md")
    cls = task_payload.get("class") or "wildcard"
    # One-shot / generated hunts may pass the class body inline so the packet
    # does not depend on collection root timing. Prefer override when non-empty.
    override = task_payload.get("class_body_override")
    if override is not None and str(override).strip():
        class_md = str(override)
    else:
        class_md = _load_hunt_class_body(str(cls))
    try:
        angles_full = load_prompt_slice(prompts_root, "hunting_angles.md")
    except FileNotFoundError:
        angles_full = ""
    pkt = cfg.get("packet") or {}
    max_angles = int(pkt.get("max_hunt_angles", 4))
    angles = _select_angles(angles_full, cls, max_angles=max_angles)
    # P1.2: slim architecture (caller should already slice; still hard-cap low)
    arch = truncate(
        architecture or "(none)",
        int(pkt.get("max_architecture_chars", 1800)),
        "architecture",
    )
    keys = known_keys[: int(pkt.get("max_known_keys", 20))]
    notes = codemap_notes[: int(pkt.get("max_codemap_entries", 12))]
    sinks = (seed_sinks or [])[: int(pkt.get("max_seed_sinks", 12))]
    known_human = (known_findings or [])[: int(pkt.get("max_known_findings", 20))]
    force = bool(task_payload.get("force_depth"))
    angles_block = f"\n## Hunt angles (selected)\n{angles}\n" if angles else "\n"
    sinks_block = ""
    if sinks:
        sinks_block = (
            "\n## Seed sinks (mechanical preindex)\n```json\n"
            + json.dumps(sinks, indent=2)[:3000]
            + "\n```\n"
        )
    known_block = ""
    if known_human:
        known_block = (
            "\n## Known findings (path|class|state|title — skip re-file)\n"
            + "\n".join(f"- {x}" for x in known_human)
            + "\n"
        )
    elif keys:
        known_block = f"\n## Known finding keys (skip re-find)\n{keys}\n"
    scope_note = (
        "Tools prefer path_hints (soft jail). list_dir/read_file/file_inventory: first "
        "out-of-scope call soft-blocks (widen_available); retry widens once. "
        "grep is silently limited to path_hints roots until widened via list/read/inventory. "
        "Use file_inventory once for tree structure (not dozens of list_dir). "
        "grep: extension/glob for file type; files_only / match_path for path discovery; "
        "do not thrash empty greps — change pattern or call file_inventory. "
        "Hard deny only outside the target tree. force_depth does not lift the soft jail.\n"
    )
    if force:
        prof = str(
            (cfg.get("run") or {}).get("profile")
            or cfg.get("profile")
            or ""
        ).strip().lower()
        scope_note += (
            "force_depth=true: must use read_file/grep before submit_none "
            "(deeper tools required; soft path_hints jail still applies).\n"
        )
    op_notes = str(
        task_payload.get("operator_notes")
        or task_payload.get("operator_brief")
        or task_payload.get("operator_reason")
        or ""
    ).strip()
    op_block = ""
    if op_notes:
        op_block = (
            "\n## Operator brief (authoritative for this hunt)\n"
            + truncate(op_notes, 2500, "operator_notes")
            + "\n"
        )
    sel = task_payload.get("selection") if isinstance(task_payload.get("selection"), dict) else None
    sel_block = ""
    if sel:
        sel_block = (
            "\n## Operator selection (focus here)\n```json\n"
            + json.dumps(sel, indent=2)[:2500]
            + "\n```\n"
        )
    user = (
        f"## Hunt task\narea={task_payload.get('area')!r} class={cls!r}\n"
        f"path_hints={task_payload.get('path_hints')}\n"
        f"{scope_note}\n"
        f"{class_md}{angles_block}"
        f"{op_block}{sel_block}"
        f"## Architecture (area slice)\n{arch}\n"
        f"{sinks_block}"
        f"{known_block}\n"
        f"## Codemap notes\n{notes}\n\n"
        "Use tools. End with submit_candidate or submit_none.\n"
        "Do not re-file issues already listed under Known findings.\n"
        "If another hunt skill is needed, list_hunt_profiles then request_hunt "
        "(one profile per call). If the tool says that profile is already under way "
        "or circular, do not retry the same profile — finish this task instead.\n"
    )
    run_profile = str((cfg.get("run") or {}).get("profile") or "code_static")
    tools = tool_schemas_for(run_profile, "hunt")
    # Optional per-hunt-profile tools allowlist (null = full hunt set).
    tools_allowlist = None
    try:
        from vulnforge.hunt_profiles import get_profile

        prof = get_profile(str(cls), include_body=False)
        raw_tools = prof.get("tools") if isinstance(prof, dict) else None
        if isinstance(raw_tools, list) and raw_tools:
            tools_allowlist = [str(x).strip() for x in raw_tools if str(x).strip()]
    except Exception:
        tools_allowlist = None
    # Task payload can override for one-shot hunts.
    payload_tools = task_payload.get("tools")
    if isinstance(payload_tools, list) and payload_tools:
        tools_allowlist = [str(x).strip() for x in payload_tools if str(x).strip()]
    tools = _filter_tools_by_allowlist(
        tools, tools_allowlist, always_keep=HUNT_ALWAYS_KEEP_TOOLS
    )
    budget = _budget_chars(cfg)
    total = len(system) + len(user)
    over = total > budget
    return Packet(
        system=system,
        user=truncate(user, budget - len(system), "hunt") if over else user,
        tools_schema=tools,
        meta={
            "chars": total,
            "budget": budget,
            "stage": "hunt",
            "class": cls,
            "seed_sinks": len(sinks),
            "tools_allowlist": tools_allowlist,
        },
        over_budget=total > budget * 1.5,
    )


def pack_disprove(
    cfg: dict,
    prompts_root: Path,
    finding_body: dict,
    file_slices: list[dict],
    *,
    perspective: str | None = None,
    verifier_id: str | None = None,
) -> Packet:
    """Build adversarial disprove packet.

    ``perspective`` is a prompts/v1-relative path (e.g. ``disprove_threat.md``)
    appended after the shared ``disprove.md`` contract. Omitted when missing.
    """
    # Severity + exclusion gates without hunt Evidence/Tools sections.
    try:
        preamble = load_prompt_slice(prompts_root, "preamble.md")
    except FileNotFoundError:
        preamble = ""
    system = (
        (preamble + "\n" if preamble else "")
        + "## Stage: disprove\n"
        + "You are an independent adversarial validator. Try to kill the finding; "
        + "do not hunt for new bugs or call hunt tools.\n\n"
        + _principles_without_hunt_tools(prompts_root)
    )
    disprove = load_prompt_slice(prompts_root, "disprove.md")
    perspective_txt = ""
    if perspective:
        rel = str(perspective).replace("\\", "/").lstrip("/")
        if ".." in rel.split("/"):
            raise PermissionError(f"path escape: {perspective}")
        try:
            perspective_txt = "\n\n" + load_prompt_slice(prompts_root, rel)
        except FileNotFoundError:
            perspective_txt = (
                f"\n\n# Perspective: {verifier_id or rel}\n"
                f"(Perspective prompt missing: {rel}. Follow shared disprove contract only.)\n"
            )
    pkt = cfg.get("packet") or {}
    max_slice = int(pkt.get("max_file_slice_chars", 4000))
    slices_txt = []
    for s in file_slices:
        # load_citation_slices uses "text"; allow "content" for callers
        body = s.get("content") if s.get("content") is not None else s.get("text")
        err = s.get("error")
        head = f"### {s.get('path')}"
        if s.get("start_line") is not None:
            head += f" (L{s.get('start_line')}-{s.get('end_line')})"
        if err:
            slices_txt.append(f"{head}\n_error: {err}_\n")
            continue
        slices_txt.append(
            f"{head}\n```\n"
            + truncate(str(body or ""), max_slice, "slice")
            + "\n```\n"
        )
    user = (
        disprove
        + perspective_txt
        + "\n\n## Finding JSON\n```json\n"
        + json.dumps(finding_body, indent=2)[:12000]
        + "\n```\n\n## Cited slices\n"
        + "\n".join(slices_txt)
    )
    return Packet(
        system=system,
        user=user,
        tools_schema=[],
        meta={
            "stage": "disprove",
            "verifier_id": verifier_id,
            "perspective": perspective,
        },
        over_budget=False,
    )


def pack_develop_poc(
    cfg: dict,
    prompts_root: Path,
    finding_body: dict,
    file_slices: list[dict],
    *,
    evidence_id: str | None = None,
    existing_poc: str = "",
    operator_notes: str = "",
) -> Packet:
    """Packet for operator-queued working-code PoC pass (tools: read + write_evidence)."""
    try:
        preamble = load_prompt_slice(prompts_root, "preamble.md")
    except FileNotFoundError:
        preamble = ""
    system = (
        (preamble + "\n" if preamble else "")
        + "## Stage: develop_poc\n"
        + "Write working PoC **code** (poc.py / poc.sh / poc.ps1 / poc.c) into the "
        + "evidence pack via write_evidence. Prefer runnable scripts over rewriting "
        + "markdown narrative. Hub file poc_develop.md is run instructions only. "
        + "Never claim confirmed; never edit the target.\n\n"
        + _principles_without_hunt_tools(prompts_root)
    )
    try:
        stage_md = load_prompt_slice(prompts_root, "develop_poc.md")
    except FileNotFoundError:
        stage_md = (
            "Write a runnable PoC script (poc.py/sh/ps1/c) via write_evidence, "
            "plus a thin poc_develop.md run hub.\n"
        )
    pkt = cfg.get("packet") or {}
    max_slice = int(pkt.get("max_file_slice_chars", 4000))
    slices_txt: list[str] = []
    for s in file_slices:
        body = s.get("content") if s.get("content") is not None else s.get("text")
        err = s.get("error")
        head = f"### {s.get('path')}"
        if s.get("start_line") is not None:
            head += f" (L{s.get('start_line')}-{s.get('end_line')})"
        if err:
            slices_txt.append(f"{head}\n_error: {err}_\n")
            continue
        slices_txt.append(
            f"{head}\n```\n"
            + truncate(str(body or ""), max_slice, "slice")
            + "\n```\n"
        )
    eid = evidence_id or finding_body.get("evidence_id") or ""
    user = (
        stage_md
        + f"\n\n## Evidence pack id\n`{eid or 'unknown'}`\n"
        + "Always pass this as evidence_id when calling write_evidence.\n"
        + "\n## Finding JSON\n```json\n"
        + json.dumps(finding_body, indent=2)[:12000]
        + "\n```\n\n## Cited slices\n"
        + ("\n".join(slices_txt) if slices_txt else "_(none)_")
    )
    if existing_poc.strip():
        user += (
            "\n\n## Current poc_develop.md "
            "(preserve operator content; add/improve runnable code)\n```markdown\n"
            + truncate(existing_poc, 10000, "poc")
            + "\n```\n"
        )
    notes = (operator_notes or "").strip()
    if notes:
        user += (
            "\n\n## Operator notes\n"
            + truncate(notes, 4000, "op_notes")
            + "\n"
        )
    tools = tool_schemas_for("code_static", "develop_poc")
    budget = _budget_chars(cfg)
    total = len(system) + len(user)
    over = total > budget
    return Packet(
        system=system,
        user=truncate(user, budget - len(system), "develop_poc") if over else user,
        tools_schema=tools,
        meta={
            "chars": total,
            "budget": budget,
            "stage": "develop_poc",
            "evidence_id": eid,
        },
        over_budget=total > budget * 1.5,
    )
