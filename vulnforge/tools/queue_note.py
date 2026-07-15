"""Non-executing notes: wishlist, sibling seeds, codemap."""

from __future__ import annotations

from typing import Any


ALLOWED_KINDS = frozenset({"wishlist", "sibling_seed", "codemap"})


def note(ctx: dict, kind: str, payload: dict | str) -> dict[str, Any]:
    if kind not in ALLOWED_KINDS:
        return {"ok": False, "error": f"bad kind {kind}"}
    entry = {"kind": kind, "payload": payload, "task_id": ctx.get("task_id")}
    sess = ctx.setdefault("session", {})
    sess.setdefault("notes", []).append(entry)
    return {"ok": True, "stored": True, "kind": kind}


def flush_notes_to_db(ctx: dict, db) -> None:
    notes = (ctx.get("session") or {}).get("notes") or []
    for n in notes:
        db.insert_note(n["kind"], n["payload"], task_id=n.get("task_id"))
