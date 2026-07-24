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

    Schemas live on tool SPECs under ``vulnforge.tools.agent`` (registry).
    When apply_defaults is True (runtime packets), operator global defaults from
    config/default_tools.json may narrow the set. Catalog / Dev UI should pass
    apply_defaults=False to list the full integrated surface.
    """
    from vulnforge.tools.registry import critical_tools_for, openai_schemas_for_stage

    # profile reserved for future multi-profile; code_static is the only surface.
    _ = profile
    tools = openai_schemas_for_stage(stage, include_extras=True)

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
        always = critical_tools_for(stage) or _always_keep_for_stage(stage)
        return _filter_tools_by_allowlist(tools, resolved, always_keep=always)
    except Exception:
        return tools


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


def _always_keep_for_stage(stage: str) -> frozenset[str]:
    """Compat helper: stage-critical tools from SPECs (with static fallback)."""
    try:
        from vulnforge.tools.registry import critical_tools_for

        crit = critical_tools_for(stage)
        if crit:
            return crit
    except Exception:
        pass
    if stage == "hunt":
        return frozenset(
            {
                "submit_candidate",
                "submit_none",
                "list_hunt_profiles",
                "request_hunt",
            }
        )
    if stage == "recon":
        return frozenset({"submit_architecture"})
    if stage == "develop_poc":
        return frozenset({"write_evidence"})
    return frozenset()


# Compat shims — prefer ToolSpec.critical_for / registry.critical_tools_for.
HUNT_ALWAYS_KEEP_TOOLS = _always_keep_for_stage("hunt")
RECON_ALWAYS_KEEP_TOOLS = _always_keep_for_stage("recon")


def pack_recon(
    cfg: dict,
    prompts_root: Path,
    inventory: dict,
    architecture_so_far: str = "",
    operator_brief: str = "",
    focus_paths: list | None = None,
    codemap: dict | None = None,
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
        codemap=codemap,
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
    codemap: dict | None = None,
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
    pkt = cfg.get("packet") or {}
    max_cm = int(pkt.get("max_codemap_chars", 2500))
    cm_block = ""
    if codemap:
        try:
            from vulnforge.tools.codemap import format_codemap_for_packet

            cm_txt = format_codemap_for_packet(codemap, max_chars=max_cm)
            if cm_txt and cm_txt != "(no codemap)":
                cm_block = (
                    "\n## Mechanical codemap (ground truth for modules/paths)\n"
                    "Prefer these paths for components and hunt_focus path_hints; "
                    "do not invent modules outside this map without tool evidence.\n"
                    "Annotate high-value paths/symbols with note(kind=codemap).\n```json\n"
                    + cm_txt
                    + "\n```\n"
                )
        except Exception:
            cm_block = ""
    user = (
        recon
        + registry_section
        + "\n\n## Mechanical inventory\n```json\n"
        + json.dumps(inv, indent=2)
        + "\n```\n"
        + cm_block
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
    codemap: dict | None = None,
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
    cm_struct_block = ""
    max_cm = int(pkt.get("max_codemap_chars", 2500))
    if codemap:
        try:
            from vulnforge.tools.codemap import format_codemap_for_packet

            cm_txt = format_codemap_for_packet(
                codemap,
                max_chars=max_cm,
                path_hints=list(task_payload.get("path_hints") or []),
                area=str(task_payload.get("area") or ""),
                sliced=True,
            )
            if cm_txt and cm_txt != "(no codemap)":
                cm_struct_block = (
                    "\n## Codemap (area slice — modules near path_hints)\n```json\n"
                    + cm_txt
                    + "\n```\n"
                )
        except Exception:
            cm_struct_block = ""
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
        f"{cm_struct_block}"
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
