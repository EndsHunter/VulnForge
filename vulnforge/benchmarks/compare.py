"""Suite aggregates and run-vs-run comparison. Pure: no I/O.

Callers pass loaded BenchmarkRun dicts. A **suite run** is a parent whose
``metrics.members`` lists one row per (case, repeat). ``aggregate`` turns a
set of member rows into headline metrics. ``summarize_repeats`` gives
mean/min/max across repeats. ``compare_runs`` diffs two suite runs: the
fingerprint, the headline metrics, and a per-oracle flip table.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from vulnforge.benchmarks.fingerprint import fingerprint_diff

HEADLINE_KEYS = (
    "recall",
    "recall_raw",
    "unmatched_per_target",
    "tokens_per_hit",
    "wall_s",
)

SCORED_STATUSES = frozenset({"passed", "failed"})


def _parse_iso(raw: Any) -> Optional[datetime]:
    text = str(raw or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def run_duration_s(run: dict[str, Any]) -> Optional[float]:
    """Wall time in seconds from started_at to finished_at, or None."""
    start = _parse_iso(run.get("started_at"))
    end = _parse_iso(run.get("finished_at"))
    if start is None or end is None:
        return None
    delta = (end - start).total_seconds()
    return round(delta, 3) if delta >= 0 else None


def _int(v: Any) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def member_row(child: dict[str, Any], *, repeat: int = 0) -> dict[str, Any]:
    """Compact member row for a suite parent, from a child BenchmarkRun."""
    m = child.get("metrics") if isinstance(child.get("metrics"), dict) else {}
    tok = m.get("tokens") if isinstance(m.get("tokens"), dict) else {}
    return {
        "def_id": child.get("def_id"),
        "run_id": child.get("id"),
        "repeat": int(repeat),
        "status": child.get("status"),
        "oracle_hash": child.get("oracle_hash") or "",
        "oracle_count": m.get("oracle_count"),
        "hit_count": m.get("hit_count"),
        "raw_hit_count": m.get("raw_hit_count", m.get("hit_count")),
        "recall": m.get("recall"),
        "score": m.get("score", m.get("recall")),
        "unmatched": m.get("unmatched"),
        "tokens_total": tok.get("total_tokens"),
        "wall_s": run_duration_s(child),
        "hits": list(m.get("hits") or []),
        "raw_only": list(m.get("raw_only") or []),
        "misses": list(m.get("misses") or []),
        "error": child.get("error"),
    }


def aggregate(members: list[dict[str, Any]]) -> dict[str, Any]:
    """Headline metrics over member rows (one repeat, or any subset)."""
    scored = [r for r in members if r.get("status") in SCORED_STATUSES]
    oracles = sum(_int(r.get("oracle_count")) for r in scored)
    hits = sum(_int(r.get("hit_count")) for r in scored)
    raw = sum(_int(r.get("raw_hit_count")) for r in scored)
    unmatched = sum(_int(r.get("unmatched")) for r in scored)
    has_tokens = any(r.get("tokens_total") is not None for r in scored)
    tokens = sum(_int(r.get("tokens_total")) for r in scored)
    walls = [float(r["wall_s"]) for r in scored if r.get("wall_s") is not None]
    return {
        "cases": len(scored),
        "errors": sum(1 for r in members if r.get("status") == "error"),
        "cancelled": sum(1 for r in members if r.get("status") == "cancelled"),
        "pending": sum(1 for r in members if r.get("status") in ("queued", "running")),
        "oracle_count": oracles,
        "hit_count": hits,
        "raw_hit_count": raw,
        "recall": round(hits / oracles, 4) if oracles else None,
        "recall_raw": round(raw / oracles, 4) if oracles else None,
        "unmatched": unmatched,
        "unmatched_per_target": round(unmatched / len(scored), 3) if scored else None,
        "tokens_total": tokens if has_tokens else None,
        "tokens_per_hit": (round(tokens / hits) if hits else None) if has_tokens else None,
        "wall_s": round(sum(walls), 1) if walls else None,
    }


def summarize_repeats(members: list[dict[str, Any]]) -> dict[str, Any]:
    """Per-repeat aggregates plus mean/min/max of each headline metric."""
    repeats = sorted({_int(r.get("repeat")) for r in members}) or [0]
    per = [aggregate([r for r in members if _int(r.get("repeat")) == i]) for i in repeats]
    total = aggregate(members)
    spread: dict[str, Any] = {}
    for key in HEADLINE_KEYS:
        vals = [p[key] for p in per if p.get(key) is not None]
        if not vals:
            spread[key] = None
            continue
        spread[key] = {
            "mean": round(sum(vals) / len(vals), 4),
            "min": min(vals),
            "max": max(vals),
        }
    headline = {k: (spread[k]["mean"] if spread.get(k) else None) for k in HEADLINE_KEYS}
    return {
        "n_repeats": len(repeats),
        "per_repeat": per,
        "spread": spread,
        "headline": headline,
        "totals": total,
    }


def _oracle_rates(members: list[dict[str, Any]]) -> dict[tuple[str, str], float]:
    """(def_id, oracle_id) → fraction of scored repeats with a gated hit."""
    seen: dict[tuple[str, str], list[int]] = {}
    for r in members:
        if r.get("status") not in SCORED_STATUSES:
            continue
        did = str(r.get("def_id") or "")
        for oid in r.get("hits") or []:
            seen.setdefault((did, str(oid)), []).append(1)
        for oid in list(r.get("raw_only") or []) + list(r.get("misses") or []):
            seen.setdefault((did, str(oid)), []).append(0)
    return {k: sum(v) / len(v) for k, v in seen.items() if v}


def _case_hashes(members: list[dict[str, Any]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for r in members:
        did = str(r.get("def_id") or "")
        if did and r.get("oracle_hash"):
            out[did] = str(r["oracle_hash"])
    return out


def _members(run: dict[str, Any]) -> list[dict[str, Any]]:
    m = run.get("metrics") if isinstance(run.get("metrics"), dict) else {}
    rows = m.get("members")
    if isinstance(rows, list) and rows:
        return [r for r in rows if isinstance(r, dict)]
    # Single-case run: treat itself as one member.
    return [member_row(run)]


def comparability(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Refusal (hard) and warnings (soft) for comparing run ``a`` to ``b``."""
    warnings: list[str] = []
    refusal: Optional[str] = None
    if (a.get("tier") or "") != (b.get("tier") or ""):
        refusal = f"different tiers ({a.get('tier') or '?'} vs {b.get('tier') or '?'}): not comparable"
    elif (a.get("suite_id") or a.get("def_id")) != (b.get("suite_id") or b.get("def_id")):
        refusal = "different suites or cases: not comparable"
    ma, mb = _members(a), _members(b)
    ha, hb = _case_hashes(ma), _case_hashes(mb)
    changed = sorted(d for d in set(ha) & set(hb) if ha[d] != hb[d])
    if refusal is None and changed:
        refusal = "oracle changed for " + ", ".join(changed[:6]) + (
            "…" if len(changed) > 6 else ""
        ) + ": not like-for-like"
    only_a = sorted(set(ha) - set(hb))
    only_b = sorted(set(hb) - set(ha))
    if only_a or only_b:
        warnings.append(
            f"case sets differ ({len(only_a)} only in A, {len(only_b)} only in B); "
            "flips cover shared cases only"
        )
    na = summarize_repeats(ma)["n_repeats"]
    nb = summarize_repeats(mb)["n_repeats"]
    if na == 1 or nb == 1:
        warnings.append("single run on at least one side: LLM variance not measured")
    return {"refusal": refusal, "warnings": warnings, "changed_oracles": changed}


def compare_runs(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Diff run ``b`` against baseline ``a``."""
    gate = comparability(a, b)
    ma, mb = _members(a), _members(b)
    sa, sb = summarize_repeats(ma), summarize_repeats(mb)
    deltas: dict[str, Any] = {}
    for key in HEADLINE_KEYS:
        va, vb = sa["headline"].get(key), sb["headline"].get(key)
        deltas[key] = (
            round(vb - va, 4) if isinstance(va, (int, float)) and isinstance(vb, (int, float)) else None
        )
    ra, rb = _oracle_rates(ma), _oracle_rates(mb)
    shared_cases = set(_case_hashes(ma)) & set(_case_hashes(mb)) or None
    flips: list[dict[str, Any]] = []
    for key in sorted(set(ra) | set(rb)):
        if shared_cases is not None and key[0] not in shared_cases:
            continue
        if key not in ra or key not in rb:
            continue
        x, y = ra[key], rb[key]
        change = "gain" if y > x else "regression" if y < x else ("hit" if y > 0 else "miss")
        flips.append(
            {"def_id": key[0], "oracle_id": key[1], "a_rate": round(x, 3), "b_rate": round(y, 3), "change": change}
        )
    order = {"regression": 0, "gain": 1, "miss": 2, "hit": 3}
    flips.sort(key=lambda f: (order[f["change"]], f["def_id"], f["oracle_id"]))
    return {
        "comparable": gate["refusal"] is None,
        "refusal": gate["refusal"],
        "warnings": gate["warnings"],
        "fingerprint_diff": fingerprint_diff(a.get("fingerprint"), b.get("fingerprint")),
        "a": {"id": a.get("id"), "summary": sa, "fingerprint": a.get("fingerprint") or {}},
        "b": {"id": b.get("id"), "summary": sb, "fingerprint": b.get("fingerprint") or {}},
        "deltas": deltas if gate["refusal"] is None else {},
        "flips": flips if gate["refusal"] is None else [],
        "counts": {
            "regression": sum(1 for f in flips if f["change"] == "regression"),
            "gain": sum(1 for f in flips if f["change"] == "gain"),
        }
        if gate["refusal"] is None
        else {},
    }


__all__ = [
    "HEADLINE_KEYS",
    "aggregate",
    "compare_runs",
    "comparability",
    "member_row",
    "run_duration_s",
    "summarize_repeats",
]
