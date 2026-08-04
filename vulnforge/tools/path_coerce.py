"""Coerce agent path args onto the audit target (structured scope errors)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnforge.util import normalize_relpath


def _looks_absolute(p: str) -> bool:
    s = (p or "").strip().replace("\\", "/")
    if not s:
        return False
    if s.startswith("/") or s.startswith("//"):
        return True
    if len(s) >= 3 and s[1] == ":" and s[0].isalpha() and s[2] == "/":
        return True
    return Path(p).is_absolute()


def coerce_target_relpath(
    ctx: dict,
    path: str | None,
    *,
    default: str = ".",
    tool: str = "list_dir",
) -> tuple[str | None, dict[str, Any] | None]:
    """Map an agent path onto a target-relative path.

    Returns ``(rel, None)`` on success, or ``(None, error_dict)`` with structured
    codes: ``outside_target``, ``path_escape``. Absolute paths under the target
    are auto-trimmed to relative form.

    Soft path jail is **not** applied here; use ``maybe_soft_jail`` after.
    """
    raw = default if path is None or str(path).strip() == "" else str(path).strip()
    target_raw = ctx.get("target_root")
    if not target_raw:
        return normalize_relpath(raw) or default, None
    target = Path(str(target_raw)).resolve()

    if _looks_absolute(raw):
        try:
            abs_p = Path(raw).resolve()
        except OSError:
            abs_p = Path(raw)
        try:
            rel = normalize_relpath(str(abs_p.relative_to(target)))
            if not rel:
                rel = "."
            return rel, None
        except ValueError:
            return None, {
                "ok": False,
                "error": "outside_target",
                "code": "outside_target",
                "path": raw,
                "hint": (
                    f"{tool}: path is outside the audit target root. "
                    "Use a path relative to the target (e.g. '.', 'src/', 'app.py'), "
                    "not an absolute host path."
                ),
                "target_root": str(target),
            }

    rel = normalize_relpath(raw) or default
    if rel in ("", "."):
        return ".", None
    try:
        cand = (target / rel).resolve()
        if cand != target and target not in cand.parents:
            return None, {
                "ok": False,
                "error": "path_escape",
                "code": "path_escape",
                "path": raw,
                "hint": (
                    f"{tool}: path escapes the audit target (no '..' outside root). "
                    "Stay under the target tree with a relative path."
                ),
            }
    except OSError as e:
        return None, {
            "ok": False,
            "error": "path_error",
            "code": "path_error",
            "path": raw,
            "hint": str(e),
        }
    return rel, None
