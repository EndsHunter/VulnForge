"""Enqueue a continuation child for hunt or recon when context is full.

Used by the ``continue_hunt`` / ``continue_recon`` agent tools and by the
mechanical fallback when a loop dies on context-length.
"""

from __future__ import annotations

from typing import Any, Optional

from vulnforge.task_priority import RECON_CHILD_PRIORITY
from vulnforge.util import normalize_relpath

DEFAULT_MAX_CONTINUE_DEPTH = 3
# Ahead of default planned hunts (50); after operator residual (35).
HUNT_CONTINUE_PRIORITY = 42

_UNDER_WAY = frozenset({"queued", "leased"})

_HUNT_INHERIT = (
    "area",
    "class",
    "path_hints",
    "path_prefix",
    "force_depth",
    "seed_sinks",
    "class_body_override",
    "tools",
    "selection",
    "operator_notes",
    "operator_brief",
    "operator_reason",
    "spawn_chain",
    "shallow_requeued",
)

_RECON_INHERIT = (
    "operator_notes",
    "operator_requested",
    "operator_reason",
    "focus_paths",
    "path_hints",
    "enqueue_hunts",
    "batch_enqueue_hunts",
    "docs_digest",
    "target",
    "agent_ids",
    "recon_batch_id",
    "recon_batch_index",
    "recon_batch_size",
    "merge_with_existing",
    "dynamic_skills",
    "dynamic_skill_count",
    "dynamic_skills_activate",
    "strategy",
    "include_prior_architecture",
    "recon_orchestrator",
)


def continue_generation(payload: Optional[dict]) -> int:
    if not isinstance(payload, dict):
        return 0
    try:
        return max(0, int(payload.get("continue_generation") or 0))
    except (TypeError, ValueError):
        return 0


def max_continue_depth(cfg: Optional[dict]) -> int:
    run = (cfg or {}).get("run") if isinstance(cfg, dict) else None
    if not isinstance(run, dict):
        return DEFAULT_MAX_CONTINUE_DEPTH
    try:
        return max(0, int(run.get("max_continue_depth", DEFAULT_MAX_CONTINUE_DEPTH)))
    except (TypeError, ValueError):
        return DEFAULT_MAX_CONTINUE_DEPTH


def _norm_paths(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        if raw:
            raw = [raw]
        else:
            return []
    out: list[str] = []
    seen: set[str] = set()
    for p in raw:
        s = normalize_relpath(str(p)) if p else ""
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= 40:
            break
    return out


def _existing_child(db, *, kind: str, parent_id: int) -> Optional[int]:
    try:
        tasks = db.list_tasks(limit=500)
    except Exception:
        return None
    for t in tasks:
        if getattr(t, "kind", None) != kind:
            continue
        st = str(getattr(t, "state", "") or "").lower()
        if st not in _UNDER_WAY:
            continue
        pl = t.payload if isinstance(getattr(t, "payload", None), dict) else {}
        try:
            src = int(pl.get("continue_from_task_id") or 0)
        except (TypeError, ValueError):
            src = 0
        if src == int(parent_id):
            return int(getattr(t, "id", 0) or 0)
    return None


def handoff_from_transcript(transcript: list | None, *, limit: int = 2500) -> str:
    """Best-effort remaining-work blurb when the model never called continue_*."""
    bits: list[str] = []
    for m in reversed(list(transcript or [])):
        if not isinstance(m, dict):
            continue
        if m.get("role") != "assistant":
            continue
        content = m.get("content")
        if isinstance(content, str) and content.strip():
            bits.append(content.strip()[:1200])
            break
    tools: list[str] = []
    for m in transcript or []:
        if not isinstance(m, dict):
            continue
        if m.get("role") == "tool" and m.get("name"):
            tools.append(str(m.get("name")))
        for tc in m.get("tool_calls") or []:
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function") if isinstance(tc.get("function"), dict) else tc
            name = fn.get("name") if isinstance(fn, dict) else None
            if name:
                tools.append(str(name))
    if tools:
        last = tools[-12:]
        bits.append("Tools used: " + ", ".join(last))
    text = "\n".join(bits).strip()
    if not text:
        return (
            "Parent task hit the context window before a terminal submit. "
            "Continue the same investigation; do not restart from scratch."
        )
    if len(text) > limit:
        return text[: limit - 40] + "\n...[handoff truncated]...\n"
    return text


def enqueue_continuation(
    ctx: dict,
    *,
    kind: str,
    handoff: str,
    explored_paths: Optional[list] = None,
    remaining_paths: Optional[list] = None,
    remaining_work: str = "",
    auto: bool = False,
) -> dict[str, Any]:
    """Enqueue a same-kind child task with a fresh context + handoff.

    ``kind`` is ``hunt`` or ``recon``.
    """
    kind_s = str(kind or "").strip().lower()
    if kind_s not in ("hunt", "recon"):
        return {"ok": False, "error": f"continue not supported for kind {kind!r}", "code": "bad_kind"}

    db = ctx.get("db")
    if db is None:
        return {
            "ok": False,
            "error": "continue unavailable (no database in tool context)",
            "code": "no_db",
        }

    session = ctx.setdefault("session", {})
    if session.get("continued") and session.get("continue_child_task_id"):
        return {
            "ok": True,
            "already": True,
            "task_id": session.get("continue_child_task_id"),
            "message": (
                f"Continuation already queued as task #{session.get('continue_child_task_id')}. "
                "Stop exploring; this task is done."
            ),
        }

    parent_payload = (
        ctx.get("task_payload") if isinstance(ctx.get("task_payload"), dict) else {}
    )
    cfg = ctx.get("cfg") if isinstance(ctx.get("cfg"), dict) else {}
    gen = continue_generation(parent_payload)
    cap = max_continue_depth(cfg)
    if cap <= 0:
        return {
            "ok": False,
            "error": "continuations disabled (run.max_continue_depth=0)",
            "code": "disabled",
        }
    if gen >= cap:
        return {
            "ok": False,
            "error": (
                f"continue depth limit: this task is already generation {gen} "
                f"(max {cap}). Finish with submit_* instead."
            ),
            "code": "continue_depth",
            "continue_generation": gen,
            "max_continue_depth": cap,
        }

    parent_id = ctx.get("task_id")
    try:
        parent_id_i = int(parent_id) if parent_id is not None else None
    except (TypeError, ValueError):
        parent_id_i = None
    if parent_id_i is None:
        return {"ok": False, "error": "no parent task id", "code": "no_task"}

    existing = _existing_child(db, kind=kind_s, parent_id=parent_id_i)
    if existing:
        session["continued"] = True
        session["continue_child_task_id"] = existing
        return {
            "ok": True,
            "already": True,
            "task_id": existing,
            "message": (
                f"Continuation already queued as task #{existing}. "
                "Stop exploring; this task is done."
            ),
        }

    handoff_s = str(handoff or remaining_work or "").strip()
    if not handoff_s:
        return {
            "ok": False,
            "error": (
                "handoff is required: summarize what you already inspected, "
                "what remains, and what the child should do next."
            ),
            "code": "missing_handoff",
        }

    explored = _norm_paths(explored_paths)
    remaining = _norm_paths(remaining_paths)
    if not remaining:
        remaining = _norm_paths(parent_payload.get("path_hints"))

    child: dict[str, Any] = {}
    inherit = _HUNT_INHERIT if kind_s == "hunt" else _RECON_INHERIT
    for key in inherit:
        if key in parent_payload and parent_payload[key] is not None:
            child[key] = parent_payload[key]

    if remaining:
        if kind_s == "hunt":
            child["path_hints"] = remaining
        else:
            child["focus_paths"] = remaining
            child.setdefault("path_hints", remaining)

    child.update(
        {
            "parent_task_id": parent_id_i,
            "continue_from_task_id": parent_id_i,
            "continue_generation": gen + 1,
            "continue_handoff": handoff_s[:8000],
            "explored_paths": explored,
            "remaining_work": str(remaining_work or "")[:4000],
            "continue_auto": bool(auto),
        }
    )
    if kind_s == "recon":
        child["include_prior_architecture"] = True
        child["merge_with_existing"] = True
        if parent_payload.get("recon_batch_id"):
            child["enqueue_hunts"] = False
            child.setdefault(
                "batch_enqueue_hunts",
                parent_payload.get("batch_enqueue_hunts", True),
            )
        child.setdefault("recon_generation", parent_payload.get("recon_generation") or 1)

    notes = str(child.get("operator_notes") or "").strip()
    prefix = (
        f"Continuation of {kind_s} #{parent_id_i} (generation {gen + 1}). "
        "Do not redo already-explored paths. Handoff:\n"
        f"{handoff_s[:2000]}"
    )
    child["operator_notes"] = (prefix if not notes else prefix + "\n\nPrior notes:\n" + notes)[
        :4000
    ]

    priority = (
        int(HUNT_CONTINUE_PRIORITY) if kind_s == "hunt" else int(RECON_CHILD_PRIORITY)
    )
    try:
        tid = db.enqueue_task(kind_s, child, priority=priority)
    except Exception as e:
        return {"ok": False, "error": f"enqueue failed: {e}", "code": "enqueue_error"}

    session["continued"] = True
    session["continue_child_task_id"] = tid
    session["continue_handoff"] = handoff_s[:2000]
    session["continue_auto"] = bool(auto)
    session.setdefault("tools_used", []).append(
        "continue_hunt" if kind_s == "hunt" else "continue_recon"
    )

    run_dir = ctx.get("run_dir")
    if run_dir is not None:
        try:
            from vulnforge.util import append_event

            append_event(
                run_dir,
                {
                    "source": "vf",
                    "event": f"{kind_s}_continue",
                    "task_id": parent_id_i,
                    "child_task_id": tid,
                    "continue_generation": gen + 1,
                    "auto": bool(auto),
                    "handoff": handoff_s[:500],
                },
            )
        except OSError:
            pass

    return {
        "ok": True,
        "task_id": tid,
        "kind": kind_s,
        "continue_generation": gen + 1,
        "path_hints": remaining,
        "explored_paths": explored,
        "auto": bool(auto),
        "message": (
            f"Queued {kind_s} #{tid} as a continuation (generation {gen + 1}). "
            "This task should stop now — Ralph will run the child with a fresh context."
        ),
    }


def maybe_auto_continue(
    ctx: dict,
    *,
    kind: str,
    error: str,
    transcript: list | None = None,
) -> Optional[dict[str, Any]]:
    """Mechanical fallback: enqueue a continuation when the loop overflowed."""
    cfg = ctx.get("cfg") if isinstance(ctx.get("cfg"), dict) else {}
    from vulnforge.agent_runtime.context_watch import (
        continue_enabled,
        is_context_overflow_error,
    )

    if not continue_enabled(cfg):
        return None
    if not is_context_overflow_error(error):
        return None
    session = ctx.get("session") if isinstance(ctx.get("session"), dict) else {}
    if session.get("continued"):
        return {
            "continued": True,
            "child_task_id": session.get("continue_child_task_id"),
            "auto_continued": False,
        }
    handoff = handoff_from_transcript(transcript)
    explored = _norm_paths(session.get("explored_paths") if session else None)
    result = enqueue_continuation(
        ctx,
        kind=kind,
        handoff=handoff,
        explored_paths=explored,
        auto=True,
    )
    if not result.get("ok"):
        return None
    return {
        "continued": True,
        "auto_continued": True,
        "child_task_id": result.get("task_id"),
        "continue_generation": result.get("continue_generation"),
    }
