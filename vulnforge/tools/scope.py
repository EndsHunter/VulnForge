"""Soft path jail for hunt tools â€” prefer path_hints; one widen; hard deny only outside target."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnforge.util import normalize_relpath


def scope_enabled(ctx: dict) -> bool:
    scope = ctx.get("scope") or {}
    return bool(scope.get("enabled"))


def scope_hints(ctx: dict) -> list[str]:
    scope = ctx.get("scope") or {}
    hints = scope.get("path_hints") or []
    out: list[str] = []
    for h in hints:
        if not h:
            continue
        n = normalize_relpath(str(h))
        if n and n not in out:
            out.append(n)
    prefix = scope.get("path_prefix")
    if prefix:
        p = normalize_relpath(str(prefix))
        if p and p not in out:
            out.append(p)
    return out


def path_in_soft_scope(rel: str, hints: list[str]) -> bool:
    """True if rel is under any hint (file or directory prefix)."""
    if not hints:
        return True
    rel_n = normalize_relpath(rel or ".")
    if rel_n in ("", "."):
        # root listing: in scope only if a hint is root-ish; prefer deny soft for root
        return any(h in (".", "") for h in hints)
    for h in hints:
        h_n = normalize_relpath(h)
        if not h_n or h_n == ".":
            return True
        if rel_n == h_n:
            return True
        if rel_n.startswith(h_n.rstrip("/") + "/"):
            return True
        # hint is a file under a dir the agent is listing
        if h_n.startswith(rel_n.rstrip("/") + "/"):
            return True
        # parent of a file hint (list parent dir)
        parent = str(Path(h_n).parent).replace("\\", "/")
        if parent in (".", "") and rel_n in (".", ""):
            return True
        if rel_n == parent:
            return True
    return False


def maybe_soft_jail(ctx: dict, rel: str) -> dict[str, Any] | None:
    """
    Soft path jail gate.

    Returns None if the call may proceed (possibly after auto-widen).
    Returns an error dict if blocked (first out-of-scope hit before widen).

    Policy:
    - No scope / empty hints â†’ allow (hard target jail still applies in resolve).
    - Already widened (one soft widen used) â†’ allow.
    - force_depth is *not* a widen: it only requires deeper tools before submit_none.
    - First out-of-scope: block once with widen_available; second attempt auto-widens.
    """
    if not scope_enabled(ctx):
        return None
    scope = ctx.setdefault("scope", {})
    if scope.get("widened"):
        return None
    hints = scope_hints(ctx)
    if not hints:
        return None
    rel_n = normalize_relpath(rel or ".")
    if path_in_soft_scope(rel_n, hints):
        return None
    # First soft violation: block with guidance; mark pending widen
    if not scope.get("widen_pending"):
        scope["widen_pending"] = True
        return {
            "ok": False,
            "error": "out_of_scope",
            "code": "out_of_scope",
            "path": rel_n,
            "path_hints": hints,
            "hint": (
                "Path is outside hunt path_hints. Retry the same call to widen "
                "scope once (soft jail), or stay inside path_hints. "
                "Hard deny only applies outside the target root. "
                "force_depth does not lift this soft jail."
            ),
            "widen_available": True,
        }
    # Second attempt: widen and allow
    scope["widened"] = True
    sess = ctx.setdefault("session", {})
    sess["scope_widened"] = True
    return None


def scope_roots_for_scan(ctx: dict) -> list[str] | None:
    """
    Relative roots to scan for grep when soft-jailed.
    None means scan whole target (no jail or widened).

    force_depth does not lift soft roots â€” only an explicit soft widen
    (scope["widened"]) or disabled/empty hints does.
    """
    if not scope_enabled(ctx):
        return None
    scope = ctx.get("scope") or {}
    if scope.get("widened"):
        return None
    hints = scope_hints(ctx)
    if not hints:
        return None
    # Use unique directory roots from hints
    roots: list[str] = []
    for h in hints:
        h_n = normalize_relpath(h)
        if not h_n or h_n == ".":
            return None  # whole tree
        # if looks like file, use parent + file itself as candidates
        roots.append(h_n)
    return roots or None


def attach_scope_warning(result: dict, ctx: dict) -> dict:
    """Annotate tool result if scope was widened during this session."""
    if not isinstance(result, dict):
        return result
    scope = ctx.get("scope") or {}
    if scope.get("widened") and ctx.get("session", {}).get("scope_widened"):
        result = dict(result)
        result.setdefault("scope_widened", True)
    return result
