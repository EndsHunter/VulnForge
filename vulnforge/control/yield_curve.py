"""Campaign yield curve: gated findings per million tokens over a sliding window.

Advisory read only. Nothing here pauses, stops or steers Ralph; automatic
stopping belongs to the budget cap (#175). A flat curve is not a clean bill of
health: the Campaign tab shows the open-cell count beside it.

Window basis: the last ``window`` **finished hunt tasks**, in finish order.
A hunt is the unit an operator plans and re-queues, so "the last 20 hunts" maps
to something they can act on, and a window never splits one task's tokens.
Tokens are still the denominator, so the rate stays comparable when hunt sizes
vary.

Numerator: findings that are, on read, past the gates (``GATED_STATES``),
attributed to the first finished hunt whose result names them, and counted once
per near-duplicate group (same ``merge_key`` or linked by ``near_dup_of`` /
``superseded_by``). Candidates, ``rejected_mech``, ``rejected_llm`` and
``superseded`` rows never count.

Denominator: total tokens of the hunts in the window, plus the tokens of the
validation tasks (``validate_mech`` / ``validate_llm``) for findings those hunts
filed.

Usage comes from ``llm_usage.jsonl`` (``task_id``); older runs fall back to
``llm_usage_summary.json`` ``by_task``. A window whose hunts have no token
counts is unavailable (``rate_per_mtok`` null), never zero.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Union

SCHEMA = "vulnforge.yield@1"
DEFAULT_WINDOW = 20
MAX_POINTS = 120

# Passed mech gates and not killed by disprove. rejected_human still passed the
# gates; a person decided it afterwards, so it was gated yield at the time.
GATED_STATES = frozenset({"needs_human", "confirmed", "rejected_human"})
# Task states that never ran to an end (or have not yet).
_UNFINISHED_STATES = frozenset({"queued", "leased", "paused", "cancelled", "running"})
VALIDATION_KINDS = frozenset({"validate_mech", "validate_llm"})

ADVISORY_NOTE = (
    "Advisory only: never pauses or stops Ralph. A flat curve is not a clean "
    "bill of health; open cells can still hold findings."
)


def is_hunt_kind(kind: Any) -> bool:
    k = str(kind or "").strip().lower()
    return k == "hunt" or k.startswith("hunt:") or k.startswith("hunt/")


def _is_finished(state: Any) -> bool:
    s = str(state or "").strip().lower()
    return bool(s) and s not in _UNFINISHED_STATES


def _int_or_none(v: Any) -> Optional[int]:
    try:
        if v is None or isinstance(v, bool):
            return None
        return int(v)
    except (TypeError, ValueError):
        return None


def task_tokens(row: Mapping[str, Any] | None) -> int:
    """Total tokens for one usage bucket (total, else prompt + completion)."""
    if not isinstance(row, Mapping):
        return 0
    total = _int_or_none(row.get("total_tokens")) or 0
    if total > 0:
        return total
    return (_int_or_none(row.get("prompt_tokens")) or 0) + (
        _int_or_none(row.get("completion_tokens")) or 0
    )


def format_tokens(n: int) -> str:
    """Same rules as the UI ``formatTokenCount`` (1.4M, 12k, 1.2k, 980)."""
    v = max(0, int(n or 0))
    if v >= 1_000_000:
        return f"{v / 1_000_000:.1f}M"
    if v >= 10_000:
        return f"{round(v / 1000)}k"
    if v >= 1000:
        return f"{v / 1000:.1f}k"
    return str(v)


def yield_sentence(latest: Mapping[str, Any] | None) -> str:
    """Plain sentence for the latest window."""
    if not latest or not int(latest.get("hunts") or 0):
        return "No finished hunts yet."
    hunts = int(latest.get("hunts") or 0)
    hunt_word = "hunt" if hunts == 1 else "hunts"
    if not latest.get("available"):
        return f"Yield unavailable: no token counts recorded for the last {hunts} {hunt_word}."
    gated = int(latest.get("gated") or 0)
    noun = "finding" if gated == 1 else "findings"
    tokens = format_tokens(int(latest.get("tokens") or 0))
    return f"{gated} new gated {noun} in the last {tokens} tokens ({hunts} {hunt_word})"


class _Groups:
    """Union-find over finding ids (near-dup groups)."""

    def __init__(self) -> None:
        self.parent: dict[int, int] = {}

    def find(self, x: int) -> int:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _merge_key(body: Mapping[str, Any]) -> Optional[str]:
    from vulnforge.findings.merge import merge_key

    try:
        return merge_key(dict(body or {}))
    except Exception:  # malformed body: no near-dup identity
        return None


def _sample_ends(n: int, max_points: int) -> list[int]:
    """Indices of window ends to emit, always including the last hunt."""
    if n <= 0:
        return []
    stride = max(1, math.ceil(n / max(1, max_points)))
    ends = list(range(n - 1, -1, -stride))
    ends.reverse()
    return ends


def compute_yield_series(
    tasks: Iterable[Mapping[str, Any]],
    findings: Iterable[Mapping[str, Any]],
    usage_by_task: Mapping[Any, Mapping[str, Any]] | None,
    *,
    window: int = DEFAULT_WINDOW,
    max_points: int = MAX_POINTS,
) -> dict[str, Any]:
    """Pure yield series.

    ``tasks``: dicts with ``id``, ``kind``, ``state``, ``payload`` (dict),
    ``result`` (dict) and ``updated_at`` (finish time for terminal tasks).
    ``findings``: dicts with ``id``, ``state`` and ``body`` (dict).
    ``usage_by_task``: task id (int or str) → usage bucket with token counts.
    """
    window = max(1, int(window or DEFAULT_WINDOW))
    usage: dict[int, int] = {}
    for key, row in (usage_by_task or {}).items():
        tid = _int_or_none(key)
        if tid is None:
            continue
        usage[tid] = usage.get(tid, 0) + task_tokens(row)
    usage_present = any(v > 0 for v in usage.values())

    task_list = [dict(t) for t in tasks or []]
    hunts = [
        t
        for t in task_list
        if is_hunt_kind(t.get("kind")) and _is_finished(t.get("state"))
    ]
    hunts.sort(key=lambda t: (str(t.get("updated_at") or ""), int(t.get("id") or 0)))
    hunt_index = {int(t["id"]): i for i, t in enumerate(hunts)}

    # Finding → first finished hunt (in finish order) whose result names it.
    filed_by: dict[int, int] = {}
    for i, t in enumerate(hunts):
        res = t.get("result") if isinstance(t.get("result"), dict) else {}
        fid = _int_or_none(res.get("finding_id"))
        if fid is not None and fid not in filed_by:
            filed_by[fid] = i

    # Near-dup groups across every non-superseded finding, so a gated row and
    # its merged twin collapse to one count.
    groups = _Groups()
    by_key: dict[str, int] = {}
    finding_rows = [dict(f) for f in findings or []]
    for f in finding_rows:
        fid = _int_or_none(f.get("id"))
        if fid is None:
            continue
        groups.find(fid)
        body = f.get("body") if isinstance(f.get("body"), dict) else {}
        for link in ("near_dup_of", "superseded_by"):
            other = _int_or_none(body.get(link))
            if other is not None:
                groups.union(fid, other)
        if str(f.get("state") or "") == "superseded":
            continue
        mk = _merge_key(body)
        if mk:
            if mk in by_key:
                groups.union(fid, by_key[mk])
            else:
                by_key[mk] = fid

    # Each gated group counts once, at the earliest hunt that filed one of its
    # gated members. A gated group no hunt filed is reported as unattributed.
    group_hunt: dict[int, Optional[int]] = {}
    for f in finding_rows:
        fid = _int_or_none(f.get("id"))
        if fid is None or str(f.get("state") or "") not in GATED_STATES:
            continue
        root = groups.find(fid)
        idx = filed_by.get(fid)
        prev = group_hunt.get(root)
        if idx is not None and (prev is None or idx < prev):
            group_hunt[root] = idx
        else:
            group_hunt.setdefault(root, None)
    gated_at = [0] * len(hunts)
    unattributed = 0
    for idx in group_hunt.values():
        if idx is None:
            unattributed += 1
        else:
            gated_at[idx] += 1

    # Tokens per hunt slot: the hunt itself plus validation of what it filed.
    tokens_at = [usage.get(int(t["id"]), 0) for t in hunts]
    has_usage = [usage.get(int(t["id"]), 0) > 0 for t in hunts]
    for t in task_list:
        if str(t.get("kind") or "") not in VALIDATION_KINDS:
            continue
        tok = usage.get(_int_or_none(t.get("id")) or -1, 0)
        if tok <= 0:
            continue
        payload = t.get("payload") if isinstance(t.get("payload"), dict) else {}
        fid = _int_or_none(payload.get("finding_id"))
        idx = filed_by.get(fid) if fid is not None else None
        if idx is None:
            parent = _int_or_none(payload.get("parent_task_id"))
            idx = hunt_index.get(parent) if parent is not None else None
        if idx is not None:
            tokens_at[idx] += tok

    # A succeeded hunt with no usage means the host reported none: that window
    # cannot be measured. A failed hunt with no usage may genuinely have spent
    # nothing (infra failure before the first call).
    missing_at = [
        (not has_usage[i]) and str(hunts[i].get("state") or "") == "succeeded"
        for i in range(len(hunts))
    ]

    def prefix(xs: list[int]) -> list[int]:
        out = [0]
        for x in xs:
            out.append(out[-1] + int(x))
        return out

    p_tok = prefix(tokens_at)
    p_gated = prefix(gated_at)
    p_miss = prefix([1 if m else 0 for m in missing_at])
    p_used = prefix([1 if u else 0 for u in has_usage])

    def window_at(end: int) -> dict[str, Any]:
        start = max(0, end - window + 1)
        tokens = p_tok[end + 1] - p_tok[start]
        gated = p_gated[end + 1] - p_gated[start]
        missing = p_miss[end + 1] - p_miss[start]
        with_usage = p_used[end + 1] - p_used[start]
        available = tokens > 0 and missing == 0
        reason = None
        if not available:
            reason = "no_usage" if with_usage == 0 else "usage_incomplete"
        return {
            "start_task_id": int(hunts[start]["id"]),
            "end_task_id": int(hunts[end]["id"]),
            "end_at": hunts[end].get("updated_at"),
            "hunts": end - start + 1,
            "tokens": int(tokens),
            "gated": int(gated),
            "hunts_without_usage": int((end - start + 1) - with_usage),
            "available": bool(available),
            "reason": reason,
            "rate_per_mtok": (round(gated * 1_000_000 / tokens, 4) if available else None),
        }

    series = [window_at(e) for e in _sample_ends(len(hunts), max_points)]
    latest = series[-1] if series else None
    if not hunts:
        reason = "no_hunts"
    elif not usage_present:
        reason = "no_usage"
    elif latest and not latest["available"]:
        reason = latest["reason"]
    else:
        reason = None
    return {
        "schema": SCHEMA,
        "advisory": True,
        "window": {"basis": "hunts", "size": window},
        "gated_states": sorted(GATED_STATES),
        "available": bool(latest and latest["available"]),
        "reason": reason,
        "latest": latest,
        "sentence": yield_sentence(latest),
        "series": series,
        "totals": {
            "finished_hunts": len(hunts),
            "gated_findings": len(group_hunt),
            "gated_attributed": sum(gated_at),
            "gated_unattributed": unattributed,
            "tokens": int(p_tok[-1]),
        },
        "note": ADVISORY_NOTE,
    }


# ---------- Read path ----------


def _json_obj(raw: Any) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        val = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return val if isinstance(val, dict) else {}


def load_usage_by_task(run_dir: Union[str, Path]) -> dict[str, Any]:
    """Per-task usage from the ledger, else the summary's ``by_task``."""
    from vulnforge.usage import load_usage_summary, rebuild_by_task_from_jsonl

    by_task = rebuild_by_task_from_jsonl(run_dir)
    if by_task:
        return by_task
    summary = load_usage_summary(run_dir)
    bt = summary.get("by_task")
    return dict(bt) if isinstance(bt, dict) else {}


def load_yield_inputs(db: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Task and finding rows needed by the series (read-only SQL)."""
    conn = db.conn
    task_rows = conn.execute(
        "SELECT id, kind, state, payload_json, result_json, updated_at FROM tasks ORDER BY id"
    ).fetchall()
    tasks: list[dict[str, Any]] = []
    for r in task_rows:
        kind = str(r["kind"] or "")
        if not (is_hunt_kind(kind) or kind in VALIDATION_KINDS):
            continue
        tasks.append(
            {
                "id": int(r["id"]),
                "kind": kind,
                "state": r["state"],
                "payload": _json_obj(r["payload_json"]),
                "result": _json_obj(r["result_json"]),
                "updated_at": r["updated_at"],
            }
        )
    finding_rows = conn.execute(
        "SELECT id, state, body_json FROM findings ORDER BY id"
    ).fetchall()
    findings = [
        {"id": int(r["id"]), "state": r["state"], "body": _json_obj(r["body_json"])}
        for r in finding_rows
    ]
    return tasks, findings


def run_yield(
    run_dir: Union[str, Path],
    db: Any = None,
    *,
    window: int = DEFAULT_WINDOW,
) -> dict[str, Any]:
    """Derive the yield series on read. Opens ``harness.db`` when ``db`` is None."""
    from vulnforge.db import Database

    run_dir = Path(run_dir)
    own = db is None
    if own:
        db = Database.open(run_dir / "harness.db")
    try:
        tasks, findings = load_yield_inputs(db)
    finally:
        if own:
            db.close()
    return compute_yield_series(tasks, findings, load_usage_by_task(run_dir), window=window)
