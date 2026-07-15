"""Agent tool: enqueue a sibling hunt from available hunt profiles.

Validates that the requested profile exists, is not already under way
(queued/leased), and does not form a circular spawn chain (A→B→A).
"""

from __future__ import annotations

from typing import Any, Optional

from vulnforge.hunt_profiles import (
    HuntProfileError,
    all_class_ids,
    get_profile,
    list_profiles,
    normalize_class,
)
from vulnforge.util import normalize_relpath

# Active queue states: a hunt with this profile is "under way"
_UNDER_WAY_STATES = frozenset({"queued", "leased"})

# Max length of spawn lineage (root + intermediate parents) before blocking
DEFAULT_MAX_SPAWN_DEPTH = 4

# Max successful request_hunt calls per parent task session
DEFAULT_MAX_SPAWN_PER_TASK = 3


def list_hunt_profiles(ctx: dict) -> dict[str, Any]:
    """Return hunt profiles the agent may request (id, title, active, description)."""
    try:
        rows = list_profiles(include_body=False)
    except HuntProfileError as e:
        return {"ok": False, "error": f"hunt_profiles: {e}"}
    profiles = []
    for p in rows:
        profiles.append(
            {
                "id": p.get("id"),
                "title": p.get("title") or p.get("id"),
                "active": bool(p.get("active")),
                "description": (p.get("description") or "")[:240],
            }
        )
    return {
        "ok": True,
        "profiles": profiles,
        "count": len(profiles),
        "hint": (
            "Use request_hunt with profile=<id>. "
            "Do not re-request a profile that is already under way."
        ),
    }


def _spawn_chain_from_payload(payload: dict[str, Any] | None) -> list[str]:
    if not isinstance(payload, dict):
        return []
    raw = payload.get("spawn_chain")
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for x in raw:
        s = str(x or "").strip().lower()
        if s and s not in out:
            out.append(s)
    return out[:32]


def _find_underway_hunts(
    db,
    *,
    profile: str,
    exclude_task_id: Optional[int] = None,
    area: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Hunts for this profile currently queued or leased."""
    hits: list[dict[str, Any]] = []
    try:
        tasks = db.list_tasks(limit=500)
    except Exception:
        return hits
    area_s = (area or "").strip()
    for t in tasks:
        if getattr(t, "kind", None) != "hunt":
            continue
        st = str(getattr(t, "state", "") or "").lower()
        if st not in _UNDER_WAY_STATES:
            continue
        tid = int(getattr(t, "id", 0) or 0)
        if exclude_task_id is not None and tid == int(exclude_task_id):
            continue
        pl = t.payload if isinstance(getattr(t, "payload", None), dict) else {}
        cls = str(pl.get("class") or "").strip().lower()
        if cls != profile:
            continue
        if area_s:
            if str(pl.get("area") or "").strip() != area_s:
                continue
        hits.append(
            {
                "task_id": tid,
                "state": st,
                "area": pl.get("area"),
                "class": cls,
                "path_hints": (pl.get("path_hints") or [])[:8],
            }
        )
    return hits


def _circular_reason(
    *,
    requested: str,
    current_class: str,
    spawn_chain: list[str],
) -> Optional[str]:
    """
    Detect circular spawn lineage.

    - Requesting the same profile as the current hunt is a self-cycle.
    - Requesting any profile already on the ancestor spawn_chain is A→…→A.
    """
    if requested == current_class:
        return (
            f"circular: this hunt is already profile {requested!r}; "
            f"finish the current task (submit_candidate / submit_none) instead of "
            f"re-queuing the same profile"
        )
    if requested in spawn_chain:
        path = " → ".join(spawn_chain + [current_class, requested])
        return (
            f"circular: profile {requested!r} already appears in the spawn chain "
            f"({path}). Do not re-queue a profile that led to this hunt."
        )
    return None


def request_hunt(
    ctx: dict,
    *,
    profile: str,
    reason: str = "",
    area: Optional[str] = None,
    path_hints: Optional[list[str]] = None,
    force_depth: bool = True,
) -> dict[str, Any]:
    """
    Enqueue a hunt task for an available hunt profile (class).

    Rejects when:
    - profile is unknown
    - a hunt with that profile is already queued/leased
    - the request would circularly re-enter the spawn lineage
    - per-task / depth caps exceeded
    """
    db = ctx.get("db")
    if db is None:
        return {
            "ok": False,
            "error": "request_hunt unavailable (no database in tool context)",
            "code": "no_db",
        }

    reason_s = str(reason or "").strip()
    if not reason_s:
        return {
            "ok": False,
            "error": "reason is required (why this other profile should hunt next)",
            "code": "missing_reason",
        }

    raw_profile = str(profile or "").strip()
    if not raw_profile:
        listed = list_hunt_profiles(ctx)
        return {
            "ok": False,
            "error": "profile is required",
            "code": "missing_profile",
            "available_profiles": listed.get("profiles") or [],
        }

    # Require an explicit registered profile id (do not silently map to wildcard).
    try:
        available = set(all_class_ids())
    except HuntProfileError as e:
        return {"ok": False, "error": f"hunt_profiles: {e}", "code": "profiles_error"}

    candidates = {
        raw_profile.lower(),
        raw_profile.lower().replace("_", "-"),
        raw_profile.lower().replace("-", "_"),
    }
    profile_id = next((c for c in candidates if c in available), None)
    if profile_id is None:
        # Last chance: normalize_class only when it stays a real registered id
        try:
            norm = normalize_class(raw_profile)
        except Exception:
            norm = ""
        if norm in available and norm in candidates:
            profile_id = norm
        else:
            listed = list_hunt_profiles(ctx)
            return {
                "ok": False,
                "error": (
                    f"unknown hunt profile {raw_profile!r}. "
                    f"Call list_hunt_profiles and pick a registered id."
                ),
                "code": "unknown_profile",
                "available_profiles": [
                    p.get("id") for p in (listed.get("profiles") or []) if p.get("id")
                ],
            }

    try:
        meta = get_profile(profile_id, include_body=False)
    except HuntProfileError:
        meta = {"id": profile_id, "title": profile_id}

    parent_payload = ctx.get("task_payload") if isinstance(ctx.get("task_payload"), dict) else {}
    current_class = str(parent_payload.get("class") or "").strip().lower() or "wildcard"
    current_area = str(parent_payload.get("area") or "app").strip() or "app"
    spawn_chain = _spawn_chain_from_payload(parent_payload)

    # Session cap
    session = ctx.setdefault("session", {})
    spawned: list = session.setdefault("spawned_hunts", [])
    cfg = ctx.get("cfg") if isinstance(ctx.get("cfg"), dict) else {}
    run_cfg = cfg.get("run") if isinstance(cfg.get("run"), dict) else {}
    try:
        max_per_task = max(
            0, int(run_cfg.get("max_spawn_hunts_per_task", DEFAULT_MAX_SPAWN_PER_TASK))
        )
    except (TypeError, ValueError):
        max_per_task = DEFAULT_MAX_SPAWN_PER_TASK
    try:
        max_depth = max(
            1, int(run_cfg.get("max_spawn_chain_depth", DEFAULT_MAX_SPAWN_DEPTH))
        )
    except (TypeError, ValueError):
        max_depth = DEFAULT_MAX_SPAWN_DEPTH

    if max_per_task and len(spawned) >= max_per_task:
        return {
            "ok": False,
            "error": (
                f"spawn cap: this hunt already requested {len(spawned)} sibling hunt(s) "
                f"(max {max_per_task}). Finish the current investigation instead."
            ),
            "code": "spawn_cap",
            "spawned": list(spawned),
        }

    # Depth: chain of parents + this current class counts toward depth
    depth_now = len(spawn_chain) + (1 if current_class else 0)
    if depth_now >= max_depth:
        return {
            "ok": False,
            "error": (
                f"spawn depth limit: lineage length {depth_now} ≥ max {max_depth}. "
                f"Chain: {' → '.join(spawn_chain + ([current_class] if current_class else []))}."
            ),
            "code": "spawn_depth",
            "spawn_chain": spawn_chain,
            "current_class": current_class,
        }

    circ = _circular_reason(
        requested=profile_id,
        current_class=current_class,
        spawn_chain=spawn_chain,
    )
    if circ:
        return {
            "ok": False,
            "error": circ,
            "code": "circular",
            "requested": profile_id,
            "current_class": current_class,
            "spawn_chain": spawn_chain,
            "hint": (
                "A hunt with an ancestor profile must not re-queue that profile. "
                "Pick a different profile from list_hunt_profiles, or submit_none / "
                "submit_candidate on the current task."
            ),
        }

    # Same profile already under way (any area unless area forced and we want global)
    parent_id = ctx.get("task_id")
    try:
        parent_id_i = int(parent_id) if parent_id is not None else None
    except (TypeError, ValueError):
        parent_id_i = None

    underway = _find_underway_hunts(
        db, profile=profile_id, exclude_task_id=parent_id_i, area=None
    )
    if underway:
        examples = ", ".join(
            f"#{h['task_id']}({h['state']}, area={h.get('area')!r})" for h in underway[:5]
        )
        return {
            "ok": False,
            "error": (
                f"a hunt with profile {profile_id!r} is already under way "
                f"({examples}). Do not enqueue a duplicate; wait for that task "
                f"or pick a different profile."
            ),
            "code": "already_underway",
            "requested": profile_id,
            "underway": underway[:10],
            "hint": (
                "Continue the current hunt, or request a different available profile. "
                "Use list_hunt_profiles to see options."
            ),
        }

    # Also block if this session already successfully queued this profile
    for s in spawned:
        if isinstance(s, dict) and str(s.get("class") or "").lower() == profile_id:
            return {
                "ok": False,
                "error": (
                    f"this task already queued profile {profile_id!r} as task "
                    f"#{s.get('task_id')}. Do not request it again."
                ),
                "code": "already_requested",
                "task_id": s.get("task_id"),
            }

    area_s = str(area or "").strip() or current_area
    hints_in = path_hints if isinstance(path_hints, list) else []
    if not hints_in:
        hints_in = list(parent_payload.get("path_hints") or [])
    hints = [normalize_relpath(str(p)) for p in hints_in if p][:15]

    child_chain = list(spawn_chain)
    if current_class and current_class not in child_chain:
        child_chain.append(current_class)

    child_payload: dict[str, Any] = {
        "area": area_s,
        "class": profile_id,
        "path_hints": hints,
        "force_depth": bool(force_depth),
        "spawned_from_task_id": parent_id_i,
        "spawn_chain": child_chain,
        "spawn_reason": reason_s[:2000],
        "agent_requested": True,
    }
    # Inherit operator notes lightly
    if parent_payload.get("operator_notes"):
        child_payload["operator_notes"] = (
            f"Spawned from hunt #{parent_id_i} ({current_class}): {reason_s[:800]}"
        )[:4000]
    else:
        child_payload["operator_notes"] = (
            f"Agent-requested hunt for profile {profile_id}: {reason_s[:1500]}"
        )[:4000]

    try:
        tid = db.enqueue_task("hunt", child_payload, priority=48)
        db.upsert_coverage_fact(
            area_s,
            profile_id,
            path=(hints[0] if hints else ""),
            visit_delta=0,
            last_depth="planned",
        )
    except Exception as e:
        return {"ok": False, "error": f"enqueue failed: {e}", "code": "enqueue_error"}

    entry = {
        "task_id": tid,
        "class": profile_id,
        "area": area_s,
    }
    spawned.append(entry)
    session.setdefault("tools_used", []).append("request_hunt")

    run_dir = ctx.get("run_dir")
    if run_dir is not None:
        try:
            from vulnforge.util import append_event

            append_event(
                run_dir,
                {
                    "source": "vf",
                    "event": "agent_request_hunt",
                    "parent_task_id": parent_id_i,
                    "task_id": tid,
                    "class": profile_id,
                    "area": area_s,
                    "reason": reason_s[:500],
                    "spawn_chain": child_chain,
                },
            )
        except OSError:
            pass

    title = (meta.get("title") if isinstance(meta, dict) else None) or profile_id
    return {
        "ok": True,
        "task_id": tid,
        "profile": profile_id,
        "title": title,
        "area": area_s,
        "path_hints": hints,
        "spawn_chain": child_chain,
        "message": (
            f"Queued hunt #{tid} for profile {profile_id!r} ({title}). "
            f"Continue this task; Ralph will run the sibling separately."
        ),
    }
