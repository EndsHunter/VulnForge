"""Thin FastAPI router for the benchmark library + bench runs."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from vulnforge.benchmarks.compare import compare_runs, summarize_repeats
from vulnforge.benchmarks.live import (
    LIVE_MAX_REPEAT,
    cancel_live_run,
    find_active_live_run,
    list_active_runs,
    reconcile_live_run,
    start_live_run,
    start_live_suite,
)
from vulnforge.benchmarks.runner import run_benchmark, run_fixture_checks
from vulnforge.benchmarks.runs import (
    BenchmarkRunError,
    baseline_for,
    get_run,
    list_runs,
    load_baselines,
    set_baseline,
)
from vulnforge.benchmarks.store import (
    BenchmarkLibraryError,
    create_def,
    delete_def,
    ensure_library,
    get_def,
    get_version,
    list_defs,
    list_versions,
    seed_from_ground_truth,
    update_def,
)
from vulnforge.benchmarks.suites import SUITES, TIERS, suite_catalog

router = APIRouter(prefix="/api/benchmarks", tags=["benchmarks"])


class BenchmarkBody(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    types: Optional[list[str]] = None
    target_ref: Optional[str] = None
    oracle_ref: Optional[str] = None
    config_overlay: Optional[Any] = None
    tags: Optional[list[str]] = None
    oracle: Optional[dict[str, Any]] = None
    notes: str = ""


class BenchmarkRunBody(BaseModel):
    """Either a suite run (``suite`` + ``tier``) or a single case (``def_id``)."""

    suite: Optional[str] = None
    tier: Optional[str] = None
    repeat: int = 1
    validate_llm: bool = True
    note: str = ""
    only: Optional[list[str]] = None
    def_id: Optional[str] = None
    version: Optional[int] = None
    types: Optional[list[str]] = None
    mode: Optional[str] = "mechanical"


def _http_lib(exc: BenchmarkLibraryError) -> HTTPException:
    msg = str(exc)
    if msg.startswith("unknown benchmark"):
        return HTTPException(404, msg)
    if "already exists" in msg:
        return HTTPException(409, msg)
    return HTTPException(400, msg)


def _http_run(exc: BenchmarkRunError) -> HTTPException:
    msg = str(exc)
    if msg.startswith("unknown run"):
        return HTTPException(404, msg)
    if msg.startswith("unknown benchmark"):
        return HTTPException(404, msg)
    return HTTPException(400, msg)


@router.get("")
def api_benchmarks_list():
    """List BenchmarkDef heads (seeds on first init)."""
    try:
        ensure_library()
        return {"ok": True, "benchmarks": list_defs()}
    except BenchmarkLibraryError as e:
        raise _http_lib(e) from e


@router.post("/seed")
def api_benchmarks_seed():
    """Import missing GT + VulnGym slice + bench-fixture defs — never clobber."""
    try:
        ensure_library()
        return seed_from_ground_truth(missing_only=True)
    except BenchmarkLibraryError as e:
        raise _http_lib(e) from e


# --- Runs (static paths before /{bench_id}) ---------------------------------


def _parse_suite_query(raw: Optional[str]) -> Optional[bool]:
    if raw is None or str(raw).strip() == "":
        return None
    key = str(raw).strip().lower()
    if key in ("1", "true", "yes", "suite"):
        return True
    if key in ("0", "false", "no", "individual"):
        return False
    return None


@router.get("/suites")
def api_benchmark_suites():
    """Suites, tiers, baselines, and the latest finished run per suite × tier."""
    try:
        ensure_library()
        defs = list_defs()
    except BenchmarkLibraryError as e:
        raise _http_lib(e) from e
    baselines = load_baselines()
    suites = suite_catalog(defs)
    for s in suites:
        s["runs"] = {}
        for tier in s["tiers"]:
            rows = list_runs(suite_id=s["id"], tier=tier, suite=True, limit=30)
            finished = [r for r in rows if r["status"] in ("passed", "failed", "error")]
            latest = finished[0] if finished else None
            base_id = baselines.get(f"{s['id']}:{tier}")
            s["runs"][tier] = {
                "baseline_id": base_id,
                "latest": _run_card(latest) if latest else None,
                "baseline": _run_card(_safe_get(base_id)) if base_id else None,
                # Oldest → newest for the trend line.
                "trend": [_trend_point(r) for r in reversed(finished[:20])],
            }
    return {
        "ok": True,
        "suites": suites,
        "tiers": [{"id": k, **v} for k, v in TIERS.items()],
        "max_repeat": LIVE_MAX_REPEAT,
    }


def _safe_get(run_id: Optional[str]) -> Optional[dict[str, Any]]:
    if not run_id:
        return None
    try:
        return get_run(run_id)
    except BenchmarkRunError:
        return None


def _run_card(run: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Compact run row for the scoreboard (no member lists)."""
    if not run:
        return None
    m = run.get("metrics") if isinstance(run.get("metrics"), dict) else {}
    summary = m.get("summary") if isinstance(m.get("summary"), dict) else {}
    return {
        "id": run.get("id"),
        "status": run.get("status"),
        "tier": run.get("tier"),
        "suite_id": run.get("suite_id"),
        "started_at": run.get("started_at"),
        "finished_at": run.get("finished_at"),
        "note": run.get("note"),
        "fingerprint": run.get("fingerprint") or {},
        "headline": summary.get("headline") or {},
        "spread": summary.get("spread") or {},
        "n_repeats": summary.get("n_repeats"),
        "totals": summary.get("totals") or {},
        "passed_count": m.get("passed_count"),
        "count": m.get("count"),
    }


def _trend_point(run: dict[str, Any]) -> dict[str, Any]:
    m = run.get("metrics") if isinstance(run.get("metrics"), dict) else {}
    head = (m.get("summary") or {}).get("headline") or {}
    fp = run.get("fingerprint") or {}
    return {
        "id": run.get("id"),
        "started_at": run.get("started_at"),
        "recall": head.get("recall"),
        "tokens_per_hit": head.get("tokens_per_hit"),
        "model": fp.get("model"),
        "git_sha": (fp.get("git_sha") or "")[:8],
    }


@router.get("/runs")
def api_benchmark_runs_list(
    def_id: Optional[str] = None,
    version: Optional[int] = None,
    status: Optional[str] = None,
    type: Optional[str] = None,
    suite: Optional[str] = None,
    suite_id: Optional[str] = None,
    tier: Optional[str] = None,
    sort: Optional[str] = "started_at",
    order: Optional[str] = "desc",
    limit: int = 200,
):
    """List BenchmarkRun records with filters/sort (default newest first).

    ``suite=true|false`` keeps suite parents / single cases; ``suite_id`` and
    ``tier`` filter by suite and tier.
    """
    try:
        return {
            "ok": True,
            "runs": list_runs(
                def_id=def_id,
                version=version,
                status=status,
                run_type=type,
                suite=_parse_suite_query(suite),
                suite_id=suite_id,
                tier=tier,
                sort=sort or "started_at",
                order=order or "desc",
                limit=limit,
            ),
        }
    except BenchmarkRunError as e:
        raise _http_run(e) from e


def _conflict_if_live_active() -> None:
    active = find_active_live_run()
    if active is not None:
        raise HTTPException(
            status_code=409,
            detail={
                "ok": False,
                "error": "a live benchmark run is already queued or running",
                "run_id": active.get("id"),
                "run": active,
            },
        )


@router.post("/runs")
def api_benchmark_runs_create(body: BenchmarkRunBody):
    """Start a run.

    Suite: ``{"suite": "realworld", "tier": "directed", "repeat": 1,
    "validate_llm": true, "note": ""}`` → async live parent (poll GET by id).
    ``{"suite": "fixtures", "tier": "l0"}`` → sync L0 fixture checks.

    Single case: ``{"def_id": "toy_sqli", "mode": "mechanical"|"live"}``.
    """
    try:
        ensure_library()
        sid = str(body.suite or "").strip().lower()
        if sid:
            tier = str(body.tier or "").strip().lower() or (
                SUITES.get(sid, {}).get("tiers") or ("directed",)
            )[0]
            if tier == "l0":
                if sid != "fixtures":
                    raise HTTPException(400, "L0 runs only as the fixtures suite")
                return {"ok": True, "suite": True, "run": run_fixture_checks(note=body.note)}
            _conflict_if_live_active()
            run = start_live_suite(
                suite_id=sid,
                repeat=body.repeat,
                only=body.only,
                validate_llm=body.validate_llm,
                note=body.note,
            )
            return {"ok": True, "async": True, "suite": True, "run": run}
        if not (body.def_id or "").strip():
            raise HTTPException(400, "suite or def_id is required")
        mode_n = str(body.mode or "mechanical").strip().lower()
        if mode_n == "live":
            _conflict_if_live_active()
            run = start_live_run(
                def_id=body.def_id or "",
                version=body.version,
                types=body.types,
                validate_llm=body.validate_llm,
                note=body.note,
            )
            return {"ok": True, "async": True, "run": run}
        run = run_benchmark(
            def_id=body.def_id or "",
            version=body.version,
            types=body.types,
            mode=mode_n,
        )
        return {"ok": True, "run": run}
    except BenchmarkRunError as e:
        raise _http_run(e) from e
    except BenchmarkLibraryError as e:
        raise _http_lib(e) from e


@router.get("/runs/active")
def api_benchmark_runs_active():
    """Queued and running bench runs (live rows reconciled). Suite parents first."""
    try:
        return {"ok": True, "runs": list_active_runs()}
    except BenchmarkRunError as e:
        raise _http_run(e) from e


@router.post("/runs/{run_id}/stop")
def api_benchmark_run_stop(run_id: str):
    try:
        return {"ok": True, "run": cancel_live_run(run_id)}
    except BenchmarkRunError as e:
        raise _http_run(e) from e


@router.post("/runs/{run_id}/baseline")
def api_benchmark_run_baseline(run_id: str):
    """Pin a finished suite run as the baseline for its suite + tier."""
    try:
        return {"ok": True, **set_baseline(run_id)}
    except BenchmarkRunError as e:
        raise _http_run(e) from e


@router.get("/runs/{run_id}")
def api_benchmark_run_get(run_id: str):
    try:
        run = get_run(run_id)
        if run.get("mode") == "live" and run.get("status") in {"queued", "running"}:
            run = reconcile_live_run(run_id)
        out: dict[str, Any] = {"ok": True, "run": run}
        if run.get("suite_id"):
            out["baseline_id"] = baseline_for(run["suite_id"], run["tier"])
            m = run.get("metrics") if isinstance(run.get("metrics"), dict) else {}
            if not isinstance(m.get("summary"), dict) and isinstance(m.get("members"), list):
                out["summary"] = summarize_repeats(m["members"])
        return out
    except BenchmarkRunError as e:
        raise _http_run(e) from e


@router.get("/compare")
def api_benchmark_compare(a: Optional[str] = None, b: Optional[str] = None):
    """Diff run ``b`` against baseline run ``a``.

    Refuses (``comparable: false`` + ``refusal``) across tiers, suites, or when
    a shared case's oracle changed. Warns on n=1 and differing case sets.
    """
    if not a or not b:
        raise HTTPException(400, "a and b (run ids) are required")
    try:
        ra, rb = get_run(a), get_run(b)
    except BenchmarkRunError as e:
        raise _http_run(e) from e
    return {"ok": True, **compare_runs(ra, rb)}


# --- Library CRUD -----------------------------------------------------------


@router.get("/{bench_id}/versions")
def api_benchmark_versions(bench_id: str):
    try:
        return {"ok": True, "id": bench_id, "versions": list_versions(bench_id)}
    except BenchmarkLibraryError as e:
        raise _http_lib(e) from e


@router.get("/{bench_id}/versions/{ver}")
def api_benchmark_version_get(bench_id: str, ver: int):
    """Immutable snapshot. Mutating the head later must not change this payload."""
    try:
        return {"ok": True, "version": get_version(bench_id, ver)}
    except BenchmarkLibraryError as e:
        raise _http_lib(e) from e


@router.get("/{bench_id}")
def api_benchmark_get(bench_id: str):
    try:
        return {"ok": True, "benchmark": get_def(bench_id, include_oracle=True)}
    except BenchmarkLibraryError as e:
        raise _http_lib(e) from e


@router.post("")
def api_benchmark_create(body: BenchmarkBody):
    bid = (body.id or "").strip()
    if not bid:
        raise HTTPException(400, "id is required")
    if not (body.name or "").strip():
        raise HTTPException(400, "name is required")
    if not body.types:
        raise HTTPException(400, "types is required")
    try:
        bench = create_def(
            bid,
            name=body.name or "",
            types=body.types,
            target_ref=body.target_ref or "",
            oracle_ref=body.oracle_ref or "",
            config_overlay=body.config_overlay,
            tags=body.tags,
            oracle=body.oracle,
            notes=body.notes or "",
            source="custom",
        )
        return {"ok": True, "benchmark": bench}
    except BenchmarkLibraryError as e:
        raise _http_lib(e) from e


@router.put("/{bench_id}")
def api_benchmark_update(bench_id: str, body: BenchmarkBody):
    try:
        bench = update_def(
            bench_id,
            name=body.name,
            types=body.types,
            target_ref=body.target_ref,
            oracle_ref=body.oracle_ref,
            config_overlay=body.config_overlay,
            tags=body.tags,
            oracle=body.oracle,
            notes=body.notes or "",
        )
        return {"ok": True, "benchmark": bench}
    except BenchmarkLibraryError as e:
        raise _http_lib(e) from e


@router.delete("/{bench_id}")
def api_benchmark_delete(bench_id: str):
    try:
        return delete_def(bench_id)
    except BenchmarkLibraryError as e:
        raise _http_lib(e) from e
