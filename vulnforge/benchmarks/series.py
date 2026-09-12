"""Pure series + version-compare helpers for BenchmarkRun metrics.

No I/O — callers pass already-loaded run dicts (from ``list_runs``).
Score is recall when present, else type/top-level ``score``.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Optional


def _as_float(val: Any) -> Optional[float]:
    if val is None or val == "":
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _as_int(val: Any) -> Optional[int]:
    if val is None or val == "":
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _mean(vals: list[float]) -> float:
    if not vals:
        return 0.0
    return round(sum(vals) / len(vals), 6)


def _types_of(run: dict[str, Any]) -> list[str]:
    return [str(t).strip().lower() for t in (run.get("types_run") or []) if str(t).strip()]


def _metrics(run: dict[str, Any]) -> dict[str, Any]:
    m = run.get("metrics")
    return m if isinstance(m, dict) else {}


def _type_metrics(metrics: dict[str, Any], run_type: str) -> Optional[dict[str, Any]]:
    by_type = metrics.get("by_type")
    if not isinstance(by_type, dict):
        return None
    row = by_type.get(run_type)
    return row if isinstance(row, dict) else None


def extract_score(run: dict[str, Any], *, run_type: Optional[str] = None) -> Optional[float]:
    """Chart score: ``by_type[type].score|recall``, else top-level recall|score.

    Returns None when ``run_type`` is set and this run does not include that type
    (and has no matching ``by_type`` row).
    """
    metrics = _metrics(run)
    want = str(run_type or "").strip().lower().replace(" ", "_") or None
    if want:
        typed = _type_metrics(metrics, want)
        if typed is not None:
            score = _as_float(typed.get("score"))
            if score is not None:
                return score
            rec = _as_float(typed.get("recall"))
            if rec is not None:
                return rec
        if want not in _types_of(run):
            return None
    rec = _as_float(metrics.get("recall"))
    if rec is not None:
        return rec
    return _as_float(metrics.get("score"))


def extract_hits(run: dict[str, Any], *, run_type: Optional[str] = None) -> tuple[Optional[int], Optional[int]]:
    """``(hit_count, oracle_count)`` preferring a type slice when asked."""
    metrics = _metrics(run)
    want = str(run_type or "").strip().lower().replace(" ", "_") or None
    if want:
        typed = _type_metrics(metrics, want)
        if typed is not None:
            return _as_int(typed.get("hit_count")), _as_int(typed.get("oracle_count"))
    return _as_int(metrics.get("hit_count")), _as_int(metrics.get("oracle_count"))


def _empty_aggregate() -> dict[str, Any]:
    return {
        "recall": 0.0,
        "score": 0.0,
        "hit_count": 0,
        "oracle_count": 0,
        "by_type": {},
    }


def empty_side(version: int) -> dict[str, Any]:
    """Clear zeros when a version has no matching runs."""
    return {
        "version": int(version),
        "run_count": 0,
        "latest": None,
        "aggregate": _empty_aggregate(),
    }


def _match_run(
    run: dict[str, Any],
    *,
    def_id: Optional[str],
    version: Optional[int] = None,
    run_type: Optional[str] = None,
) -> bool:
    want_def = str(def_id or "").strip().lower()
    if want_def and str(run.get("def_id") or "").strip().lower() != want_def:
        return False
    if version is not None and int(run.get("version") or 0) != int(version):
        return False
    want_type = str(run_type or "").strip().lower().replace(" ", "_") or None
    if want_type and want_type not in _types_of(run):
        return False
    return True


def build_series(
    runs: list[dict[str, Any]],
    *,
    def_id: str,
    run_type: Optional[str] = None,
) -> dict[str, Any]:
    """Score-over-time points, oldest ``started_at`` first."""
    want_def = str(def_id or "").strip().lower()
    want_type = str(run_type or "").strip().lower().replace(" ", "_") or None
    points: list[dict[str, Any]] = []
    for run in runs or []:
        if not isinstance(run, dict):
            continue
        if not _match_run(run, def_id=want_def, run_type=want_type):
            continue
        score = extract_score(run, run_type=want_type)
        if score is None:
            score = 0.0
        metrics = _metrics(run)
        rec = _as_float(metrics.get("recall"))
        if want_type:
            typed = _type_metrics(metrics, want_type)
            if typed is not None and _as_float(typed.get("recall")) is not None:
                rec = _as_float(typed.get("recall"))
        points.append(
            {
                "run_id": str(run.get("id") or ""),
                "started_at": str(run.get("started_at") or ""),
                "score": round(float(score), 6),
                "recall": rec,
                "version": int(run.get("version") or 0),
                "status": str(run.get("status") or ""),
                "types_run": list(_types_of(run)),
            }
        )
    points.sort(key=lambda p: (p["started_at"], p["run_id"]))
    return {"def_id": want_def, "type": want_type, "points": points}


def _flatten_latest(
    run: dict[str, Any],
    *,
    run_type: Optional[str],
) -> dict[str, Any]:
    metrics = _metrics(run)
    score = extract_score(run, run_type=run_type)
    rec = _as_float(metrics.get("recall"))
    if run_type:
        typed = _type_metrics(metrics, run_type)
        if typed is not None and _as_float(typed.get("recall")) is not None:
            rec = _as_float(typed.get("recall"))
    hits, oracles = extract_hits(run, run_type=run_type)
    by_type = metrics.get("by_type")
    return {
        "run_id": str(run.get("id") or ""),
        "started_at": str(run.get("started_at") or ""),
        "status": str(run.get("status") or ""),
        "recall": rec if rec is not None else 0.0,
        "score": float(score) if score is not None else 0.0,
        "hit_count": int(hits or 0),
        "oracle_count": int(oracles or 0),
        "by_type": deepcopy(by_type) if isinstance(by_type, dict) else {},
    }


def summarize_version(
    runs: list[dict[str, Any]],
    version: int,
    *,
    def_id: str,
    run_type: Optional[str] = None,
) -> dict[str, Any]:
    """Latest + mean metrics for one version (zeros when no runs)."""
    ver = int(version)
    want_def = str(def_id or "").strip().lower()
    want_type = str(run_type or "").strip().lower().replace(" ", "_") or None
    matched: list[dict[str, Any]] = []
    for run in runs or []:
        if not isinstance(run, dict):
            continue
        if _match_run(run, def_id=want_def, version=ver, run_type=want_type):
            matched.append(run)
    if not matched:
        return empty_side(ver)

    matched.sort(key=lambda r: (str(r.get("started_at") or ""), str(r.get("id") or "")))
    latest = _flatten_latest(matched[-1], run_type=want_type)

    recalls: list[float] = []
    scores: list[float] = []
    hits: list[float] = []
    oracles: list[float] = []
    by_acc: dict[str, dict[str, list[float]]] = {}
    for run in matched:
        metrics = _metrics(run)
        rec = _as_float(metrics.get("recall"))
        if want_type:
            typed = _type_metrics(metrics, want_type)
            if typed is not None and _as_float(typed.get("recall")) is not None:
                rec = _as_float(typed.get("recall"))
        if rec is not None:
            recalls.append(rec)
        score = extract_score(run, run_type=want_type)
        if score is not None:
            scores.append(float(score))
        h, o = extract_hits(run, run_type=want_type)
        if h is not None:
            hits.append(float(h))
        if o is not None:
            oracles.append(float(o))
        by_type = metrics.get("by_type")
        if isinstance(by_type, dict):
            for t, tm in by_type.items():
                if not isinstance(tm, dict):
                    continue
                key = str(t).strip().lower()
                if want_type and key != want_type:
                    continue
                bucket = by_acc.setdefault(key, {"score": [], "recall": [], "hit_count": []})
                s = _as_float(tm.get("score"))
                if s is not None:
                    bucket["score"].append(s)
                r = _as_float(tm.get("recall"))
                if r is not None:
                    bucket["recall"].append(r)
                hc = _as_int(tm.get("hit_count"))
                if hc is not None:
                    bucket["hit_count"].append(float(hc))

    by_type_out: dict[str, Any] = {}
    for t, bucket in by_acc.items():
        by_type_out[t] = {
            "score": _mean(bucket["score"]),
            "recall": _mean(bucket["recall"]),
            "hit_count": int(round(_mean(bucket["hit_count"]))) if bucket["hit_count"] else 0,
        }

    return {
        "version": ver,
        "run_count": len(matched),
        "latest": latest,
        "aggregate": {
            "recall": _mean(recalls),
            "score": _mean(scores),
            "hit_count": int(round(_mean(hits))) if hits else 0,
            "oracle_count": int(round(_mean(oracles))) if oracles else 0,
            "by_type": by_type_out,
        },
    }


def _side_metric(side: dict[str, Any], key: str) -> float:
    latest = side.get("latest")
    if isinstance(latest, dict) and latest.get(key) is not None:
        try:
            return float(latest[key])
        except (TypeError, ValueError):
            pass
    agg = side.get("aggregate") if isinstance(side.get("aggregate"), dict) else {}
    try:
        return float(agg.get(key) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def compare_versions(
    runs: list[dict[str, Any]],
    *,
    def_id: str,
    version_a: int,
    version_b: int,
    run_type: Optional[str] = None,
) -> dict[str, Any]:
    """Side-by-side latest/aggregate metrics + B−A deltas."""
    want_def = str(def_id or "").strip().lower()
    want_type = str(run_type or "").strip().lower().replace(" ", "_") or None
    side_a = summarize_version(runs, version_a, def_id=want_def, run_type=want_type)
    side_b = summarize_version(runs, version_b, def_id=want_def, run_type=want_type)
    delta = {
        "recall": round(_side_metric(side_b, "recall") - _side_metric(side_a, "recall"), 6),
        "score": round(_side_metric(side_b, "score") - _side_metric(side_a, "score"), 6),
        "hit_count": int(round(_side_metric(side_b, "hit_count") - _side_metric(side_a, "hit_count"))),
        "oracle_count": int(
            round(_side_metric(side_b, "oracle_count") - _side_metric(side_a, "oracle_count"))
        ),
        "run_count": int(side_b.get("run_count") or 0) - int(side_a.get("run_count") or 0),
    }
    return {
        "def_id": want_def,
        "type": want_type,
        "version_a": side_a,
        "version_b": side_b,
        "delta": delta,
    }
