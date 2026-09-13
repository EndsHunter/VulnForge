"""Benchmark runner — mechanical L0 for hunt / recon / finding_report.

Mechanical hunt reuses sink preindex → synthetic findings → ``score_findings``.
Recon / finding_report use ``vulnforge.benchmarks.scorers`` (no live LLM).
``poc_dev`` is refused on the Run path.

Live mode is async: call ``start_live_run`` / ``start_live_suite`` in
``vulnforge.benchmarks.live``. Passing ``mode=live`` here raises.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from vulnforge.benchmarks.runs import (
    RUNNABLE_TYPES,
    BenchmarkRunError,
    create_run,
    update_run,
)
from vulnforge.benchmarks.scorers import score_finding_report, score_recon
from vulnforge.benchmarks.store import (
    BenchmarkLibraryError,
    get_def,
    get_version,
    list_defs,
)
from vulnforge.eval.recall import score_findings
from vulnforge.paths import PROJECT_ROOT
from vulnforge.tools.codemap import build_codemap
from vulnforge.tools.sink_preindex import build_sink_preindex

# Simple pass bar: any positive recall (or empty oracle catalog scores as pass).
PASS_RECALL_BAR = 0.0  # passed when recall > PASS_RECALL_BAR, or oracle_count==0
PASS_SCORE_BAR = 0.0

# Synthetic Run-page ids: one click runs every library def of that type.
SUITE_TYPE_ORDER = ("hunt", "recon", "finding_report")
SUITE_DEF_IDS: dict[str, tuple[str, ...]] = {
    "all-hunt": ("hunt",),
    "all-recon": ("recon",),
    "all-finding_report": ("finding_report",),
    "all-runnable": SUITE_TYPE_ORDER,
}


def _resolve_target(target_ref: str) -> Path:
    ref = str(target_ref or "").strip()
    if not ref:
        raise BenchmarkRunError("benchmark version has empty target_ref")
    candidates = [Path(ref)]
    if not Path(ref).is_absolute():
        candidates.append(PROJECT_ROOT / ref)
    for p in candidates:
        if p.is_dir():
            return p.resolve()
    raise BenchmarkRunError(f"target not found: {ref}")


def mechanical_hunt_score(
    *,
    target: Path,
    oracles: list[dict[str, Any]],
) -> dict[str, Any]:
    """L0 mechanical score: sink hits matching oracles → score_findings.

    Never sets finding ``confirmed``. Does not touch project/ projection.
    """
    sinks = build_sink_preindex(target)
    cm = build_codemap(target)
    synthetic: list[dict[str, Any]] = []
    for o in oracles or []:
        if not isinstance(o, dict):
            continue
        kinds = set(o.get("kinds") or [])
        want = str(o.get("sink_path") or "")
        for s in sinks:
            sp = str(s.get("path") or "").replace("\\", "/")
            if want and (sp == want or sp.endswith(want) or want.endswith(sp)):
                if not kinds or s.get("kind") in kinds:
                    synthetic.append(
                        {
                            "sink_path": sp,
                            "sink_symbol": o.get("sink_symbol"),
                            "citations": [
                                {
                                    "path": sp,
                                    "start_line": s.get("line"),
                                    "symbol": o.get("sink_symbol"),
                                }
                            ],
                        }
                    )
                    break
    sc = score_findings(synthetic, list(oracles or []))
    # Symbol coverage (informational; same as eval_recall.mechanical_score)
    sym_ok = 0
    for o in oracles or []:
        if not isinstance(o, dict):
            continue
        want_sym = str(o.get("sink_symbol") or "")
        if not want_sym:
            sym_ok += 1
            continue
        for sym in cm.get("symbols") or []:
            if isinstance(sym, dict) and str(sym.get("name") or "") == want_sym:
                sym_ok += 1
                break
    sc["symbol_hit_count"] = sym_ok
    sc["sink_count"] = len(sinks)
    sc["symbol_count"] = len(cm.get("symbols") or [])
    sc["target"] = str(target)
    sc["mode"] = "mechanical"
    sc["bench_type"] = "hunt"
    # Explicit: never confirm findings
    sc["confirmed"] = False
    sc["passed"] = _hunt_passed(sc)
    return sc


def _hunt_passed(metrics: dict[str, Any]) -> bool:
    oracle_count = int(metrics.get("oracle_count") or 0)
    recall = float(metrics.get("recall") or 0.0)
    if oracle_count == 0:
        return True
    return recall > PASS_RECALL_BAR


def _terminal_status(metrics: dict[str, Any]) -> str:
    """Map metrics to passed/failed (scoring itself succeeded)."""
    by_type = metrics.get("by_type")
    if isinstance(by_type, dict) and by_type:
        oks = []
        for _t, m in by_type.items():
            if not isinstance(m, dict):
                oks.append(False)
                continue
            if "passed" in m:
                oks.append(bool(m.get("passed")))
            elif m.get("bench_type") == "hunt" or "recall" in m:
                oks.append(_hunt_passed(m))
            else:
                oks.append(float(m.get("score") or 0.0) > PASS_SCORE_BAR)
        return "passed" if oks and all(oks) else "failed"
    if "passed" in metrics:
        return "passed" if metrics.get("passed") else "failed"
    return "passed" if _hunt_passed(metrics) else "failed"


def _normalize_request_types(
    types: Optional[list[str]],
    *,
    snap_types: list[str],
) -> list[str]:
    raw = [str(t).strip().lower().replace(" ", "_") for t in (types or []) if str(t).strip()]
    if not raw:
        # Default: intersection of snap types with runnable, prefer hunt if present
        raw = [t for t in snap_types if t in RUNNABLE_TYPES]
        if not raw:
            raw = ["hunt"]
        elif "hunt" in raw and len(raw) > 1 and types is None:
            # Backward-compat for callers that omit types on multi-type defs:
            # run only the requested subset later; here keep all runnable snap types.
            pass

    if any(t == "poc_dev" for t in raw):
        raise BenchmarkRunError(
            "poc_dev is not supported on the Run path (use POST /api/benchmarks/poc/runs)"
        )

    out: list[str] = []
    seen: set[str] = set()
    for t in raw:
        if t not in RUNNABLE_TYPES:
            raise BenchmarkRunError(
                f"unsupported run type {t!r}; allow recon|hunt|finding_report"
            )
        if t in seen:
            continue
        seen.add(t)
        out.append(t)
    if not out:
        raise BenchmarkRunError("types must include recon, hunt, and/or finding_report")
    return out


def _score_type(
    *,
    bench_type: str,
    target: Path,
    oracle: dict[str, Any],
) -> dict[str, Any]:
    if bench_type == "hunt":
        findings = [f for f in (oracle.get("findings") or []) if isinstance(f, dict)]
        return mechanical_hunt_score(target=target, oracles=findings)
    if bench_type == "recon":
        return score_recon(target, oracle)
    if bench_type == "finding_report":
        return score_finding_report(None, oracle, target=target)
    raise BenchmarkRunError(f"unsupported run type: {bench_type}")


def suite_types_for(def_id: str) -> Optional[tuple[str, ...]]:
    """Return suite types for a synthetic ``all-*`` def id, else None."""
    bid = str(def_id or "").strip().lower()
    return SUITE_DEF_IDS.get(bid)


def defs_for_suite(types: list[str]) -> list[tuple[dict[str, Any], list[str]]]:
    """Library defs that declare at least one of ``types``, with the intersection.

    Sorted by def id. ``poc_dev`` is never included.
    """
    want = [t for t in SUITE_TYPE_ORDER if t in {str(x).strip().lower() for x in types}]
    if not want:
        want = [t for t in types if str(t).strip().lower() in RUNNABLE_TYPES]
        want = [str(t).strip().lower() for t in want]
    out: list[tuple[dict[str, Any], list[str]]] = []
    for d in list_defs():
        declared = [str(t).strip().lower() for t in (d.get("types") or [])]
        match = [t for t in want if t in declared]
        if match:
            out.append((d, match))
    out.sort(key=lambda pair: str(pair[0].get("id") or ""))
    return out


def _suite_def_id(types: list[str]) -> str:
    key = tuple(t for t in SUITE_TYPE_ORDER if t in types)
    for sid, mapped in SUITE_DEF_IDS.items():
        if tuple(mapped) == key:
            return sid
    return "all-runnable"


def _member_score(metrics: dict[str, Any]) -> Optional[float]:
    if not isinstance(metrics, dict):
        return None
    if metrics.get("score") is not None:
        try:
            return float(metrics["score"])
        except (TypeError, ValueError):
            return None
    if metrics.get("recall") is not None:
        try:
            return float(metrics["recall"])
        except (TypeError, ValueError):
            return None
    return None


def run_benchmark_suite(
    *,
    types: Optional[list[str]] = None,
    mode: str = "mechanical",
) -> dict[str, Any]:
    """Run every library def that declares one of ``types`` (mechanical L0).

    Persists one parent BenchmarkRun (``all-hunt`` / ``all-recon`` /
    ``all-finding_report`` / ``all-runnable``) plus a child run per member.
    Parent ``metrics.members`` lists each child id/status/score. Never
    auto-confirms findings. ``poc_dev`` is excluded.
    """
    raw = [str(t).strip().lower().replace(" ", "_") for t in (types or []) if str(t).strip()]
    if any(t == "poc_dev" for t in raw):
        raise BenchmarkRunError(
            "poc_dev is not supported on the Run path (use POST /api/benchmarks/poc/runs)"
        )
    types_n = [t for t in SUITE_TYPE_ORDER if t in set(raw)]
    if not types_n:
        if raw:
            raise BenchmarkRunError(
                f"unsupported suite types {raw!r}; allow recon|hunt|finding_report"
            )
        types_n = list(SUITE_TYPE_ORDER)

    mode_n = str(mode or "mechanical").strip().lower()
    if mode_n not in ("mechanical", "live"):
        raise BenchmarkRunError("mode must be 'mechanical' or 'live'")
    if mode_n == "live":
        raise BenchmarkRunError("live mode is async; call start_live_run")

    members = defs_for_suite(types_n)
    if not members:
        raise BenchmarkRunError(
            "no matching benchmarks for suite types " + ",".join(types_n)
        )

    suite_id = _suite_def_id(types_n)
    parent = create_run(
        def_id=suite_id,
        version=1,
        types_run=types_n,
        mode=mode_n,
        target_ref="",
        oracle_hash="",
        status="running",
    )
    rid = parent["id"]

    rows: list[dict[str, Any]] = []
    for defn, member_types in members:
        bid = str(defn.get("id") or "")
        child = run_benchmark(
            def_id=bid,
            types=member_types,
            mode=mode_n,
        )
        metrics = child.get("metrics") if isinstance(child.get("metrics"), dict) else {}
        rows.append(
            {
                "def_id": bid,
                "run_id": child.get("id"),
                "status": child.get("status"),
                "types_run": list(child.get("types_run") or member_types),
                "score": _member_score(metrics),
                "recall": metrics.get("recall"),
                "error": child.get("error"),
            }
        )

    n = len(rows)
    n_pass = sum(1 for r in rows if r.get("status") == "passed")
    n_fail = sum(1 for r in rows if r.get("status") == "failed")
    n_err = sum(1 for r in rows if r.get("status") == "error")
    scores = [float(r["score"]) for r in rows if r.get("score") is not None]
    if n_pass == n and n > 0:
        status = "passed"
    elif n_err == n:
        status = "error"
    else:
        status = "failed"

    parent_metrics: dict[str, Any] = {
        "suite": True,
        "mode": mode_n,
        "types_run": list(types_n),
        "count": n,
        "passed_count": n_pass,
        "failed_count": n_fail,
        "error_count": n_err,
        "score": round(sum(scores) / len(scores), 4) if scores else 0.0,
        "passed": status == "passed",
        "confirmed": False,
        "members": rows,
        "member_run_ids": [r.get("run_id") for r in rows],
        "by_def": {str(r["def_id"]): r for r in rows if r.get("def_id")},
    }
    err_msg = None
    if n_err:
        sample = [str(r.get("def_id")) for r in rows if r.get("status") == "error"][:8]
        err_msg = f"{n_err}/{n} members error" + (": " + ", ".join(sample) if sample else "")
    return update_run(
        rid,
        status=status,
        metrics=parent_metrics,
        error=err_msg,
        harness_run_dir=None,
    )


def run_benchmark(
    *,
    def_id: str,
    version: Optional[int] = None,
    types: Optional[list[str]] = None,
    mode: str = "mechanical",
) -> dict[str, Any]:
    """Create + execute a BenchmarkRun for recon / hunt / finding_report.

    Parameters
    ----------
    def_id:
        Library BenchmarkDef id.
    version:
        Immutable snapshot version; default ``head_version``.
    types:
        Subset of ``recon`` / ``hunt`` / ``finding_report`` (``poc_dev`` refused).
        Default: all runnable types declared on the snapshot.
    mode:
        ``mechanical`` (default). ``live`` raises; call ``start_live_run``.
    """
    bid = str(def_id or "").strip().lower()
    if not bid:
        raise BenchmarkRunError("def_id is required")

    mode_n = str(mode or "mechanical").strip().lower()
    if mode_n not in ("mechanical", "live"):
        raise BenchmarkRunError("mode must be 'mechanical' or 'live'")
    if mode_n == "live":
        raise BenchmarkRunError("live mode is async; call start_live_run")

    try:
        head = get_def(bid, include_oracle=False)
    except BenchmarkLibraryError as e:
        raise BenchmarkRunError(str(e)) from e

    ver = int(version) if version is not None else int(head.get("head_version") or 1)
    try:
        snap = get_version(bid, ver)
    except BenchmarkLibraryError as e:
        raise BenchmarkRunError(str(e)) from e

    snap_types = [str(t).strip().lower() for t in (snap.get("types") or [])]
    types_n = _normalize_request_types(types, snap_types=snap_types)

    for t in types_n:
        if t not in snap_types:
            raise BenchmarkRunError(f"benchmark {bid}@{ver} does not include {t}")

    oracle = snap.get("oracle") if isinstance(snap.get("oracle"), dict) else {}
    target_ref = str(snap.get("target_ref") or "")
    oracle_hash = str(snap.get("oracle_hash") or "")

    run = create_run(
        def_id=bid,
        version=ver,
        types_run=types_n,
        mode=mode_n,
        target_ref=target_ref,
        oracle_hash=oracle_hash,
        status="running",
    )
    rid = run["id"]

    try:
        target = _resolve_target(target_ref)
        by_type: dict[str, Any] = {}
        for t in types_n:
            # Prefer type-matching oracle body; hunt findings live on hunt oracles.
            type_oracle = oracle
            if str(oracle.get("type") or "").lower() not in ("", t) and t == "hunt":
                # Multi-type defs may store one oracle body; hunt still reads findings.
                type_oracle = oracle
            by_type[t] = _score_type(bench_type=t, target=target, oracle=type_oracle)

        metrics: dict[str, Any] = {
            "mode": "mechanical",
            "types_run": list(types_n),
            "by_type": by_type,
            "confirmed": False,
            "target": str(target),
        }
        # Flatten primary / single-type metrics for Results table compatibility.
        if len(types_n) == 1:
            primary = by_type[types_n[0]]
            for k, v in primary.items():
                if k not in ("by_type",):
                    metrics[k] = v
        else:
            # Aggregate: all-passed + mean score when available
            scores = [
                float(m.get("score") if m.get("score") is not None else m.get("recall") or 0.0)
                for m in by_type.values()
                if isinstance(m, dict)
            ]
            metrics["score"] = round(sum(scores) / len(scores), 4) if scores else 0.0
            metrics["passed"] = all(bool(m.get("passed")) for m in by_type.values() if isinstance(m, dict))

        status = _terminal_status(metrics)
        return update_run(
            rid,
            status=status,
            metrics=metrics,
            error=None,
            harness_run_dir=None,
        )
    except BenchmarkRunError as e:
        return update_run(rid, status="error", error=str(e), metrics={})
    except Exception as e:  # noqa: BLE001 — terminal error on unexpected failure
        return update_run(
            rid,
            status="error",
            error=f"{type(e).__name__}: {e}",
            metrics={},
        )


def run_hunt(
    *,
    def_id: str,
    version: Optional[int] = None,
    types: Optional[list[str]] = None,
    mode: str = "mechanical",
) -> dict[str, Any]:
    """Backward-compatible hunt-only entry (delegates to ``run_benchmark``)."""
    types_n = [str(t).strip().lower() for t in (types or ["hunt"]) if str(t).strip()]
    if not types_n:
        types_n = ["hunt"]
    if "hunt" not in types_n:
        raise BenchmarkRunError("types must include hunt for run_hunt")
    # Preserve prior behavior: run_hunt only executes hunt
    return run_benchmark(
        def_id=def_id,
        version=version,
        types=["hunt"],
        mode=mode,
    )
