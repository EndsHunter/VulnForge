"""Shared helpers for develop_fix / verify_fix (not a leased task kind)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

# Finding states a fix may be developed / verified for (payload.force bypasses).
FIX_ELIGIBLE_STATES = frozenset({"confirmed", "needs_human"})

# Read-only target tools. verify_fix gets exactly these, rooted at the patched tree.
READ_ONLY_TOOLS = ("list_dir", "file_inventory", "read_file", "grep", "find_symbol")
# develop_fix adds pack read + write (write is relpath-gated in the handler).
DEVELOP_FIX_TOOLS = READ_ONLY_TOOLS + ("list_evidence", "read_evidence", "write_evidence")
DEVELOP_FIX_WRITABLE = frozenset({"fix.patch", "fix_notes.md"})

# Body keys that carry a fix author's rationale or earlier fix verdicts. The
# verifier must not see them.
_VERIFY_HIDDEN_PREFIXES = ("fix_", "poc_development", "poc_validation", "verify_")
_VERIFY_HIDDEN_KEYS = frozenset(
    {"remediation", "recommendation", "suggested_fix", "fix", "mitigation", "patch"}
)

_WRITE_EVIDENCE_FIX_DESC = (
    "Write a file into this finding's evidence pack (never the audit target). "
    "In develop_fix only relpath 'fix.patch' (unified diff against the target) "
    "and 'fix_notes.md' (short rationale) are accepted."
)


def parse_finding_id(raw: Any) -> tuple[int | None, str | None]:
    if raw is None:
        return None, "missing_finding_id"
    try:
        return int(raw), None
    except (TypeError, ValueError):
        return None, "invalid_finding_id"


def resolve_evidence_id(payload: dict, finding) -> tuple[str | None, str | None]:
    from vulnforge.tools.evidence_write import InvalidEvidenceId, sanitize_evidence_id

    body = dict(finding.body or {})
    raw = (
        payload.get("evidence_id")
        or finding.evidence_id
        or body.get("evidence_id")
        or f"human-{finding.id}"
    )
    try:
        return sanitize_evidence_id(str(raw)), None
    except InvalidEvidenceId as e:
        return None, f"invalid_evidence_id:{e}"


def eligibility_error(finding, payload: dict) -> str | None:
    if payload.get("force"):
        return None
    if str(finding.state or "") not in FIX_ELIGIBLE_STATES:
        return f"finding_state_not_eligible:{finding.state}"
    return None


def tool_schemas(names: tuple[str, ...], *, stage: str) -> list[dict]:
    """Schemas for exactly ``names`` (develop_poc surface, defaults not applied)."""
    from vulnforge.packet import tool_schemas_for

    by_name: dict[str, dict] = {}
    for t in tool_schemas_for("code_static", "develop_poc", apply_defaults=False):
        fn = (t.get("function") or {}) if isinstance(t, dict) else {}
        n = fn.get("name") if isinstance(fn, dict) else None
        if n in names and n not in by_name:
            by_name[n] = json.loads(json.dumps(t))
    if stage == "develop_fix" and "write_evidence" in by_name:
        by_name["write_evidence"]["function"]["description"] = _WRITE_EVIDENCE_FIX_DESC
    return [by_name[n] for n in names if n in by_name]


def guarded_handler(
    inner: Callable[[str, dict], dict],
    *,
    allowed: tuple[str, ...],
    evidence_id: str | None = None,
    writable: frozenset[str] = frozenset(),
) -> Callable[[str, dict], dict]:
    """Reject any tool not in ``allowed`` before dispatch; gate write relpaths."""
    from vulnforge.util import normalize_relpath

    allowed_set = frozenset(allowed)

    def handler(name: str, args: dict) -> dict[str, Any]:
        args = dict(args or {})
        if name not in allowed_set:
            return {
                "ok": False,
                "error": "tool_not_allowed_in_stage",
                "tool": name,
                "allowed": sorted(allowed_set),
            }
        if name in ("write_evidence", "read_evidence", "list_evidence") and evidence_id:
            args["evidence_id"] = evidence_id
        if name == "write_evidence":
            rel = args.get("relpath") or args.get("path") or args.get("file") or ""
            rel_n = normalize_relpath(str(rel))
            if rel_n not in writable:
                return {
                    "ok": False,
                    "error": "relpath_not_allowed",
                    "relpath": rel,
                    "allowed": sorted(writable),
                }
            args["relpath"] = rel_n
            args.pop("path", None)
            args.pop("file", None)
        return inner(name, args)

    return handler


def verifier_view_of_body(body: dict) -> dict:
    """Finding body without fix rationale, fix history, or prior fix verdicts."""
    out: dict[str, Any] = {}
    for k, v in (body or {}).items():
        lk = str(k).lower()
        if lk in _VERIFY_HIDDEN_KEYS or lk.startswith(_VERIFY_HIDDEN_PREFIXES):
            continue
        out[k] = v
    return out


def update_finding_body(db, finding_id: int, evidence_id: str, mutate: Callable[[dict], None]) -> None:
    """Re-read the row, mutate body, write body/evidence_id/updated_at only.

    Never touches ``state``: fix work is evidence, not a status change.
    """
    from vulnforge.util import utc_now_iso

    fresh = db.get_finding(int(finding_id))
    body = dict((fresh.body if fresh else None) or {})
    body["evidence_id"] = evidence_id
    mutate(body)
    db.conn.execute(
        "UPDATE findings SET body_json=?, evidence_id=?, updated_at=? WHERE id=?",
        (json.dumps(body), evidence_id, utc_now_iso(), int(finding_id)),
    )
    db.conn.commit()


def push_history(body: dict, key: str, entry: dict, *, keep: int = 50) -> None:
    hist = body.get(key)
    if not isinstance(hist, list):
        hist = []
    hist.append(entry)
    body[key] = hist[-keep:]
    body[f"{key}_latest"] = entry


def write_json_atomic(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


def render_slices(file_slices: list[dict], max_slice: int) -> str:
    from vulnforge.packet import truncate

    out: list[str] = []
    for s in file_slices:
        text = s.get("content") if s.get("content") is not None else s.get("text")
        head = f"### {s.get('path')}"
        if s.get("start_line") is not None:
            head += f" (L{s.get('start_line')}-{s.get('end_line')})"
        if s.get("error"):
            out.append(f"{head}\n_error: {s.get('error')}_\n")
            continue
        out.append(f"{head}\n```\n" + truncate(str(text or ""), max_slice, "slice") + "\n```\n")
    return "\n".join(out) if out else "_(none)_"
