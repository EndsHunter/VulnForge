"""Score one live benchmark case: state-aware recall, unmatched findings, tokens.

Pure functions over finding rows and a usage summary, so they test without a
harness. ``score_case`` is what a live run stores as its metrics.

Honesty:

- **Gated recall** counts only findings that survived the gates
  (``needs_human`` / ``confirmed``). That is the headline. **Raw recall**
  counts any state, so gate losses are visible.
- **Unmatched** = gated findings that match no oracle. Not proven false
  positives: real-OSS oracles are incomplete.
- ``confirmed`` on the bench record is always ``False``. Only a human confirms.
"""

from __future__ import annotations

from typing import Any, Iterable

from vulnforge.benchmarks.match import finding_matches_oracle

# Findings that passed mechanical gates (and disprove, when it ran).
GATED_STATES = frozenset({"needs_human", "confirmed"})
# Never reached the gates (hunt filed it, validation never ran).
UNGATED_STATES = frozenset({"candidate"})


def _row(f: Any) -> dict[str, Any]:
    """Normalize a Finding / dict to {id, state, body}."""
    if isinstance(f, dict):
        if isinstance(f.get("body"), dict):
            return {"id": f.get("id"), "state": str(f.get("state") or ""), "body": f["body"]}
        return {"id": f.get("id"), "state": str(f.get("state") or ""), "body": f}
    body = getattr(f, "body", None)
    return {
        "id": getattr(f, "id", None),
        "state": str(getattr(f, "state", "") or ""),
        "body": body if isinstance(body, dict) else {},
    }


def _oid(o: dict[str, Any]) -> str:
    return str(o.get("id") or o.get("sink_path") or "?")


def usage_totals(summary: dict[str, Any] | None) -> dict[str, int]:
    s = summary if isinstance(summary, dict) else {}

    def n(key: str) -> int:
        try:
            return int(s.get(key) or 0)
        except (TypeError, ValueError):
            return 0

    return {
        "total_tokens": n("total_tokens"),
        "prompt_tokens": n("prompt_tokens"),
        "completion_tokens": n("completion_tokens"),
        "llm_calls": n("llm_calls"),
    }


def score_case(
    findings: Iterable[Any],
    oracles: list[dict[str, Any]],
    *,
    usage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Metrics for one live case. ``recall`` is gated recall (headline)."""
    rows = [_row(f) for f in (findings or [])]
    oracles = [o for o in (oracles or []) if isinstance(o, dict)]
    by_state: dict[str, int] = {}
    for r in rows:
        by_state[r["state"] or "?"] = by_state.get(r["state"] or "?", 0) + 1

    matches: list[dict[str, Any]] = []
    hits: list[str] = []
    raw_only: list[str] = []
    misses: list[str] = []
    for o in oracles:
        matched = [r for r in rows if finding_matches_oracle(r["body"], o)]
        gated = [r for r in matched if r["state"] in GATED_STATES]
        best = gated[0] if gated else (matched[0] if matched else None)
        if best is not None:
            matches.append(
                {
                    "oracle_id": _oid(o),
                    "finding_id": best["id"],
                    "state": best["state"],
                    "gated": bool(gated),
                }
            )
        if gated:
            hits.append(_oid(o))
        elif matched:
            raw_only.append(_oid(o))
        else:
            misses.append(_oid(o))

    gated_rows = [r for r in rows if r["state"] in GATED_STATES]
    unmatched = [
        r for r in gated_rows if not any(finding_matches_oracle(r["body"], o) for o in oracles)
    ]
    extras = sum(
        1 for r in rows if not any(finding_matches_oracle(r["body"], o) for o in oracles)
    )
    total = len(oracles)
    n_hit = len(hits)
    n_raw = n_hit + len(raw_only)
    tok = usage_totals(usage)
    return {
        "bench_type": "hunt",
        "mode": "live",
        "confirmed": False,
        "oracle_count": total,
        "hit_count": n_hit,
        "recall": (n_hit / total) if total else 1.0,
        "raw_hit_count": n_raw,
        "recall_raw": (n_raw / total) if total else 1.0,
        "hits": hits,
        "raw_only": raw_only,
        "misses": misses,
        "matches": matches,
        "finding_count": len(rows),
        "gated_count": len(gated_rows),
        "ungated_count": sum(1 for r in rows if r["state"] in UNGATED_STATES),
        "unmatched": len(unmatched),
        "unmatched_ids": [r["id"] for r in unmatched],
        "extras": extras,
        "by_state": by_state,
        "tokens": tok,
        "passed": (n_hit > 0) if total else True,
    }


__all__ = ["GATED_STATES", "UNGATED_STATES", "score_case", "usage_totals"]
