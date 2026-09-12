"""Benchmark hunt runner — mechanical L0 path (default) + optional live flag.

Mechanical path reuses ``scripts/eval_recall.mechanical_score`` patterns:
sink preindex → synthetic findings from oracle sink hits → ``score_findings``.
No LLM, no ``vf init``/harness, no finding ``confirmed`` writes.

Live mode (``mode=live``) is opt-in and currently refused with a clear error
until a harness-backed path lands in a later ticket.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from vulnforge.benchmarks.runs import (
    BenchmarkRunError,
    create_run,
    update_run,
)
from vulnforge.benchmarks.store import (
    BenchmarkLibraryError,
    get_def,
    get_version,
)
from vulnforge.eval.recall import score_findings
from vulnforge.paths import PROJECT_ROOT
from vulnforge.tools.codemap import build_codemap
from vulnforge.tools.sink_preindex import build_sink_preindex

# Simple pass bar: any positive recall (or empty oracle catalog scores as pass).
PASS_RECALL_BAR = 0.0  # passed when recall > PASS_RECALL_BAR, or oracle_count==0


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
    # Explicit: never confirm findings
    sc["confirmed"] = False
    return sc


def _terminal_status(metrics: dict[str, Any]) -> str:
    """Map metrics to passed/failed (scoring itself succeeded)."""
    oracle_count = int(metrics.get("oracle_count") or 0)
    recall = float(metrics.get("recall") or 0.0)
    if oracle_count == 0:
        return "passed"
    if recall > PASS_RECALL_BAR:
        return "passed"
    return "failed"


def run_hunt(
    *,
    def_id: str,
    version: Optional[int] = None,
    types: Optional[list[str]] = None,
    mode: str = "mechanical",
) -> dict[str, Any]:
    """Create + execute a hunt BenchmarkRun (sync for mechanical).

    Parameters
    ----------
    def_id:
        Library BenchmarkDef id (e.g. ``toy_sqli``).
    version:
        Immutable snapshot version; default ``head_version``.
    types:
        Must include ``hunt`` (only type supported this ticket).
    mode:
        ``mechanical`` (default) or ``live`` (refused until later ticket).
    """
    bid = str(def_id or "").strip().lower()
    if not bid:
        raise BenchmarkRunError("def_id is required")

    types_n = [str(t).strip().lower() for t in (types or ["hunt"]) if str(t).strip()]
    if not types_n:
        types_n = ["hunt"]
    if "hunt" not in types_n:
        raise BenchmarkRunError("types must include hunt (only hunt supported)")
    # Drop unsupported types for this ticket
    types_n = ["hunt"]

    mode_n = str(mode or "mechanical").strip().lower()
    if mode_n not in ("mechanical", "live"):
        raise BenchmarkRunError("mode must be 'mechanical' or 'live'")

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
    if "hunt" not in snap_types:
        raise BenchmarkRunError(f"benchmark {bid}@{ver} does not include hunt")

    oracle = snap.get("oracle") if isinstance(snap.get("oracle"), dict) else {}
    oracles = [f for f in (oracle.get("findings") or []) if isinstance(f, dict)]
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

    if mode_n == "live":
        return update_run(
            rid,
            status="error",
            error=(
                "live hunt bench is not enabled (ticket 3 uses mechanical L0; "
                "pass mode=mechanical or omit mode)"
            ),
            metrics={},
        )

    try:
        target = _resolve_target(target_ref)
        metrics = mechanical_hunt_score(target=target, oracles=oracles)
        status = _terminal_status(metrics)
        return update_run(
            rid,
            status=status,
            metrics=metrics,
            error=None,
            harness_run_dir=None,  # mechanical path does not use harness
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
