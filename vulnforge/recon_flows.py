"""Recon R3 flow tracing helpers (``flow-tracer`` agent, ``submit_flow``).

Pure helpers used by ``stages/recon.py``: settings, entrypoint selection,
submitted-flow normalization (registered class ids, component resolution,
stable ids, citation check) and the merge of flows into the stored map.
Spec: ``docs/harness/recon/FLOWS.md``.

Honesty: a flow steers hunts. It is never a finding, never evidence, and a
missing flow never means the code is safe. Nothing here touches findings.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Optional

from vulnforge.architecture_schema import (
    SCHEMA_V2,
    ZONE_KINDS,
    _Resolver,
    merge_v2,
    normalize_architecture_v2,
    slugify,
    validate_citations,
)

FLOW_AGENT_ID = "flow-tracer"
FLOW_PHASE = "flows"
DEFAULT_MAX_FLOWS = 8
MAX_FLOWS_CAP = 32
MAX_FLOWS_PER_SUBMIT = 8


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def flow_tracer_settings(
    cfg: Optional[dict[str, Any]],
    payload: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """``recon.flow_tracer`` config: enabled (default True), max_flows (8).

    A task payload ``flow_tracer: false`` (operator brief / re-run) turns R3 off
    for that recon only.
    """
    recon = (cfg or {}).get("recon") if isinstance(cfg, dict) else None
    ft = recon.get("flow_tracer") if isinstance(recon, dict) else None
    if isinstance(ft, bool):
        ft = {"enabled": ft}
    if not isinstance(ft, dict):
        ft = {}
    enabled = ft.get("enabled")
    enabled = True if enabled is None else bool(enabled)
    try:
        max_flows = int(ft.get("max_flows", DEFAULT_MAX_FLOWS))
    except (TypeError, ValueError):
        max_flows = DEFAULT_MAX_FLOWS
    max_flows = max(0, min(max_flows, MAX_FLOWS_CAP))
    rounds = ft.get("max_tool_rounds")
    try:
        rounds = int(rounds) if rounds not in (None, "") else None
    except (TypeError, ValueError):
        rounds = None
    pl = payload if isinstance(payload, dict) else {}
    if pl.get("flow_tracer") is False:
        enabled = False
    return {
        "enabled": bool(enabled and max_flows > 0),
        "max_flows": max_flows,
        "max_tool_rounds": rounds,
    }


# ---------------------------------------------------------------------------
# Entrypoint selection
# ---------------------------------------------------------------------------


def _zone_kinds(arch: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {k: k for k in ZONE_KINDS}
    for z in arch.get("zones") or []:
        if isinstance(z, dict) and z.get("id"):
            out[str(z["id"])] = str(z.get("kind") or "internal")
    return out


def select_flow_entrypoints(
    arch: Any,
    max_flows: int = DEFAULT_MAX_FLOWS,
) -> list[dict[str, Any]]:
    """Pick entrypoints to trace, best first, deduped by ``path:line``.

    Order: internet-zone components first, then components that have sinks,
    then the rest (stable map order inside each band). A file-level
    entrypoint (no line) is dropped when the same file has a lined one.
    """
    a = normalize_architecture_v2(arch)
    kinds = _zone_kinds(a)
    cands: list[tuple[tuple[int, int, int], dict[str, Any]]] = []
    order = 0
    for c in a["components"]:
        zone_kind = kinds.get(c.get("zone") or "", "")
        has_sinks = bool(c.get("sinks"))
        for ep in c.get("entrypoints") or []:
            if not ep.get("path") and not ep.get("label"):
                continue
            item: dict[str, Any] = {
                "component": c["id"],
                "component_name": c.get("name") or c["id"],
                "zone": c.get("zone") or "",
                "label": ep.get("label") or ep.get("path") or "",
            }
            if ep.get("path"):
                item["path"] = ep["path"]
            if ep.get("line"):
                item["line"] = ep["line"]
            if has_sinks:
                item["component_sinks"] = [
                    {k: s[k] for k in ("kind", "path", "line") if s.get(k)}
                    for s in (c.get("sinks") or [])[:6]
                ]
            rank = (
                0 if zone_kind == "internet" else 1,
                0 if has_sinks else 1,
                order,
            )
            order += 1
            cands.append((rank, item))
    cands.sort(key=lambda x: x[0])
    lined_paths = {i.get("path") for _, i in cands if i.get("path") and i.get("line")}
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for _, item in cands:
        path = item.get("path") or ""
        if path and not item.get("line") and path in lined_paths:
            continue
        key = f"{path}:{item.get('line') or ''}" if path else "label:" + item["label"].lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= max(0, int(max_flows)):
            break
    return out


# ---------------------------------------------------------------------------
# Submitted flows
# ---------------------------------------------------------------------------


def registered_class_ids() -> tuple[set[str], dict[str, str]]:
    try:
        from vulnforge.hunt_profiles import all_class_ids
        from vulnforge.hunt_profiles.store import CLASS_ALIASES

        return set(all_class_ids()), dict(CLASS_ALIASES)
    except Exception:  # pragma: no cover — registry unavailable
        return set(), {}


def filter_class_ids(
    raw: Any,
    allowed: Optional[set[str]] = None,
    aliases: Optional[dict[str, str]] = None,
) -> tuple[list[str], list[str]]:
    """Keep registered hunt class ids only (aliases mapped). Returns (kept, dropped).

    Unlike ``normalize_class`` this never maps an unknown id onto ``wildcard``.
    """
    if allowed is None or aliases is None:
        allowed, aliases = registered_class_ids()
    items = raw if isinstance(raw, list) else ([raw] if isinstance(raw, str) else [])
    kept: list[str] = []
    dropped: list[str] = []
    for c in items:
        s = str(c or "").strip().lower().replace("_", "-").replace(" ", "-")
        if not s:
            continue
        cid = s if s in allowed else aliases.get(s, "")
        if cid and cid in allowed:
            if cid not in kept:
                kept.append(cid)
        else:
            dropped.append(str(c)[:60])
    return kept[:12], dropped[:12]


def _path_owner(path: str, comps: list[dict[str, Any]]) -> Optional[str]:
    """Component whose path_hints best cover *path* (longest prefix wins)."""
    p = str(path or "").strip().lstrip("./")
    if not p:
        return None
    best: tuple[int, Optional[str]] = (0, None)
    for c in comps:
        for h in c.get("path_hints") or []:
            hint = str(h or "").strip().rstrip("/")
            if not hint or hint == ".":
                continue
            if p == hint or p.startswith(hint + "/"):
                if len(hint) > best[0]:
                    best = (len(hint), c["id"])
    return best[1]


def attach_flow_components(flow: dict[str, Any], comps: list[dict[str, Any]]) -> None:
    """Resolve source/sink/step component refs; infer from path; drop unknowns.

    merge_v2 drops a flow whose endpoint names an unknown component, so a
    model typo must not cost the whole flow: unknown refs become the
    component that owns the cited path, or are removed.
    """
    res = _Resolver(comps)
    ends = [flow.get("source"), flow.get("sink")] + list(flow.get("steps") or [])
    for end in ends:
        if not isinstance(end, dict):
            continue
        ref = end.get("component")
        hit = res.resolve(ref) if ref else None
        if not hit and end.get("path"):
            hit = _path_owner(str(end.get("path")), comps)
        if hit:
            end["component"] = hit
        else:
            end.pop("component", None)


def flow_id_for(flow: dict[str, Any]) -> str:
    """Stable id from source + sink locations (same flow from two tracers dedupes)."""
    src = flow.get("source") or {}
    snk = flow.get("sink") or {}
    key = json.dumps(
        [
            src.get("path"),
            src.get("line"),
            src.get("label") if not src.get("path") else None,
            snk.get("kind"),
            snk.get("path"),
            snk.get("line"),
            [(s.get("path"), s.get("line")) for s in (flow.get("steps") or [])][:3]
            if not (src.get("path") or snk.get("path"))
            else None,
        ],
        default=str,
    )
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:8]
    stem_src = Path(str(snk.get("path") or src.get("path") or "flow")).name
    stem = slugify(f"{stem_src}-{snk.get('line') or src.get('line') or ''}", limit=30)
    return f"f-{stem}-{digest}" if stem else f"f-{digest}"


def _raw_flows(args: Any) -> list[Any]:
    if not isinstance(args, dict):
        return []
    flows = args.get("flows")
    if isinstance(flows, str):
        try:
            flows = json.loads(flows)
        except (json.JSONDecodeError, TypeError, ValueError):
            flows = []
    if isinstance(flows, dict):
        flows = [flows]
    if not isinstance(flows, list):
        flows = []
    if not flows and (args.get("source") or args.get("sink")):
        # Small-model shortcut: one flow given as top-level fields.
        flows = [{k: args.get(k) for k in ("title", "source", "steps", "sink", "classes", "crosses")}]
    return [f for f in flows if isinstance(f, dict)][:MAX_FLOWS_PER_SUBMIT]


def normalize_submitted_flows(
    args: Any,
    *,
    arch: Any,
    target_root: Optional[Path] = None,
    entrypoint: Optional[dict[str, Any]] = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Normalize ``submit_flow`` args into v2 flows + a small report.

    - classes: registered hunt class ids only (unknown dropped, reported)
    - component refs resolved against *arch* (by id/name, else by path)
    - missing source falls back to the task entrypoint (marked, not cited)
    - stable ids; citations checked against *target_root* (bad -> inferred)
    """
    base = normalize_architecture_v2(arch)
    comps = base["components"]
    allowed, aliases = registered_class_ids()
    dropped_classes: list[str] = []
    prepared: list[dict[str, Any]] = []
    for raw in _raw_flows(args):
        f = dict(raw)
        kept, dropped = filter_class_ids(f.get("classes"), allowed, aliases)
        dropped_classes.extend(dropped)
        f["classes"] = kept
        f.pop("confidence", None)  # the validator decides, never the model
        f.pop("id", None)
        if not f.get("source") and isinstance(entrypoint, dict):
            src = {
                k: entrypoint[k]
                for k in ("component", "label", "path", "line")
                if entrypoint.get(k)
            }
            if src:
                f["source"] = src
        prepared.append(f)
    norm = normalize_architecture_v2({"components": comps, "flows": prepared})["flows"]
    flows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for f in norm:
        attach_flow_components(f, comps)
        fid = flow_id_for(f)
        n = 2
        while fid in seen_ids:
            fid = f"{flow_id_for(f)}-{n}"
            n += 1
        seen_ids.add(fid)
        f["id"] = fid
        f["origin"] = "recon"
        flows.append(f)
    stats = {"checked": 0, "valid": 0, "invalid": 0}
    if target_root is not None and flows:
        checked = validate_citations(
            {"components": comps, "flows": flows}, Path(target_root), report=stats
        )
        by_id = {f["id"]: f for f in checked["flows"]}
        flows = [by_id[f["id"]] for f in flows if f["id"] in by_id]
    for f in flows:
        f["agent"] = FLOW_AGENT_ID
        if isinstance(entrypoint, dict) and entrypoint.get("path"):
            f["entrypoint"] = {
                k: entrypoint[k] for k in ("component", "label", "path", "line") if entrypoint.get(k)
            }
    report = {
        "count": len(flows),
        "cited": sum(1 for f in flows if f.get("confidence") == "cited"),
        "inferred": sum(1 for f in flows if f.get("confidence") != "cited"),
        "dropped_classes": sorted(set(dropped_classes))[:12],
        "citations": stats,
    }
    reason = str((args or {}).get("reason") or "").strip() if isinstance(args, dict) else ""
    if reason:
        report["reason"] = reason[:400]
    return flows, report


# ---------------------------------------------------------------------------
# Merge into the stored map
# ---------------------------------------------------------------------------

_EXTRA_FLOW_KEYS = ("agent", "entrypoint", "origin")


def flow_extras(*archs: Any) -> dict[str, dict[str, Any]]:
    """Non-schema flow keys (agent, entrypoint, origin) by flow id; first wins."""
    out: dict[str, dict[str, Any]] = {}
    for a in archs:
        flows = a.get("flows") if isinstance(a, dict) else a
        for f in flows or []:
            if isinstance(f, dict) and f.get("id") and f["id"] not in out:
                out[f["id"]] = {k: f[k] for k in _EXTRA_FLOW_KEYS if f.get(k)}
    return out


def restore_flow_extras(arch: dict[str, Any], extras: dict[str, dict[str, Any]]) -> None:
    for f in arch.get("flows") or []:
        if isinstance(f, dict):
            f.update(extras.get(str(f.get("id") or "")) or {})


def merge_flows_into_architecture(
    existing: Optional[dict[str, Any]],
    flows: list[dict[str, Any]],
    *,
    target_root: Optional[Path] = None,
) -> dict[str, Any]:
    """Deterministic R5 merge of traced flows into the map (keeps extras).

    Returns the full architecture dict (``schema`` v2) with non-schema keys
    of *existing* preserved (inventory, seed_sinks, recon_agents_run, …).
    """
    prev = dict(existing or {})
    extras_by_id = flow_extras(flows, prev)
    merged = merge_v2(prev, {"flows": flows, "origin": "recon"})
    if target_root is not None:
        merged = validate_citations(merged, Path(target_root))
    restore_flow_extras(merged, extras_by_id)
    summary = prev.get("summary") if isinstance(prev.get("summary"), str) else merged["summary"]
    out = {**prev, **merged, "schema": SCHEMA_V2}
    if summary:
        out["summary"] = summary
    return out


# ---------------------------------------------------------------------------
# Packet text (compact, size-capped)
# ---------------------------------------------------------------------------


def _loc_txt(item: dict[str, Any]) -> str:
    p = item.get("path") or ""
    ln = item.get("line")
    return f"{p}:{ln}" if p and ln else p


def format_skeleton_for_packet(skeleton: Any, max_chars: int = 3000) -> str:
    """Compact text view of a v2 map/skeleton: zones, components, relations."""
    a = normalize_architecture_v2(skeleton)
    if not a["components"]:
        return ""
    lines: list[str] = []
    if a["zones"]:
        lines.append(
            "zones: "
            + ", ".join(f"{z['id']} ({z['kind']})" for z in a["zones"])
        )
    lines.append("components:")
    for c in a["components"]:
        bits = [f"- {c['id']}"]
        if c.get("name") and c["name"] != c["id"]:
            bits.append(f'"{c["name"]}"')
        meta = [x for x in (c.get("kind"), f"zone={c['zone']}" if c.get("zone") else "", c.get("origin")) if x]
        if meta:
            bits.append("[" + ", ".join(meta) + "]")
        if c.get("path_hints"):
            bits.append("paths: " + ", ".join(c["path_hints"][:4]))
        if c.get("entrypoints"):
            bits.append(
                "entry: "
                + ", ".join(
                    (e.get("label") or "") + (f" @{_loc_txt(e)}" if e.get("path") and _loc_txt(e) != e.get("label") else "")
                    for e in c["entrypoints"][:5]
                )
            )
        if c.get("sinks"):
            bits.append(
                "sinks: "
                + ", ".join(f"{s.get('kind') or '?'} {_loc_txt(s)}".strip() for s in c["sinks"][:6])
            )
        lines.append(" ".join(bits))
    if a["relations"]:
        lines.append("relations:")
        for r in a["relations"][:40]:
            ev = r.get("evidence") or {}
            lines.append(
                f"- {r['from']} -> {r['to']} {r['kind']} ({r['confidence']}"
                + (f", {_loc_txt(ev)}" if ev.get("path") else "")
                + ")"
            )
    if a["boundaries"]:
        lines.append("boundaries:")
        for b in a["boundaries"][:12]:
            lines.append(
                f"- {b.get('from_zone') or '?'} -> {b.get('to_zone') or '?'}: "
                f"{b.get('control') or ''} {_loc_txt(b)}".rstrip()
            )
    if a["flows"]:
        lines.append("flows:")
        for f in a["flows"][:12]:
            lines.append(f"- {f['id']}: {f.get('title') or ''} ({f['confidence']})")
    text = "\n".join(lines)
    if len(text) > max_chars:
        text = text[: max(200, max_chars - 30)].rstrip() + "\n...[truncated]"
    return text


def prior_architecture_text(arch: Any, max_chars: int = 6000) -> str:
    """Prior map for refine-mode packets: v1 fields + compact v2 view."""
    if not isinstance(arch, dict) or not arch:
        return ""
    v1 = {
        "summary": arch.get("summary"),
        "trust_boundaries": arch.get("trust_boundaries"),
        "input_surfaces": arch.get("input_surfaces"),
        "hunt_focus": arch.get("hunt_focus"),
    }
    body = json.dumps({k: v for k, v in v1.items() if v}, indent=1, default=str)
    v2 = format_skeleton_for_packet(arch, max_chars=max(1000, max_chars - len(body) - 40))
    text = body + ("\n\nmap (ids, zones, relations):\n" + v2 if v2 else "")
    if len(text) > max_chars:
        text = text[: max_chars - 30] + "\n...[truncated]"
    return text


__all__ = [
    "DEFAULT_MAX_FLOWS",
    "FLOW_AGENT_ID",
    "FLOW_PHASE",
    "attach_flow_components",
    "filter_class_ids",
    "flow_extras",
    "flow_id_for",
    "flow_tracer_settings",
    "format_skeleton_for_packet",
    "merge_flows_into_architecture",
    "normalize_submitted_flows",
    "prior_architecture_text",
    "registered_class_ids",
    "restore_flow_extras",
    "select_flow_entrypoints",
]
