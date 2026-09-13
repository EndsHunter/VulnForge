"""Thin FastAPI router for the benchmark library + bench runs."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from vulnforge.benchmarks.live import (
    cancel_live_run,
    find_active_live_run,
    reconcile_live_run,
    start_live_run,
    start_live_suite,
)
from vulnforge.benchmarks.poc_workshop import run_poc_workshop
from vulnforge.benchmarks.runner import (
    SUITE_DEF_IDS,
    run_benchmark,
    run_benchmark_suite,
    suite_types_for,
)
from vulnforge.benchmarks.runs import (
    BenchmarkRunError,
    get_run,
    list_runs,
)
from vulnforge.benchmarks.series import build_series, compare_versions
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
    def_id: Optional[str] = None
    version: Optional[int] = None
    types: Optional[list[str]] = None
    mode: Optional[str] = "mechanical"
    suite: bool = False
    only: Optional[list[str]] = None


class PocWorkshopRunBody(BaseModel):
    def_id: str
    version: Optional[int] = None
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


@router.get("/runs")
def api_benchmark_runs_list(
    def_id: Optional[str] = None,
    version: Optional[int] = None,
    status: Optional[str] = None,
    type: Optional[str] = None,
    sort: Optional[str] = "started_at",
    order: Optional[str] = "desc",
):
    """List BenchmarkRun records with filters/sort (default newest started_at first).

    Query:
      def_id, version, status, type (types_run contains),
      sort=started_at|finished_at|recall|status|def_id,
      order=asc|desc
    """
    try:
        return {
            "ok": True,
            "runs": list_runs(
                def_id=def_id,
                version=version,
                status=status,
                run_type=type,
                sort=sort or "started_at",
                order=order or "desc",
            ),
        }
    except BenchmarkRunError as e:
        raise _http_run(e) from e


@router.post("/runs")
def api_benchmark_runs_create(body: BenchmarkRunBody):
    """Create + execute a bench run (recon|hunt|finding_report).

    Mechanical is sync create+score. Live (hunt only) returns immediately
    with ``async: true`` and the GUI polls GET-by-id.

    ``poc_dev`` is refused. Default types = all runnable types on the snapshot.

    Suite: ``def_id`` of ``all-hunt`` / ``all-recon`` / ``all-finding_report`` /
    ``all-runnable``, or ``suite=true`` with ``types``. Live suites must be
    all-hunt. Optional ``only`` subsets live suite member defs.
    """
    try:
        ensure_library()
        mode_n = str(body.mode or "mechanical").strip().lower()
        suite_types = suite_types_for(body.def_id or "")
        if suite_types is None and body.suite:
            suite_types = tuple(body.types or []) or tuple(SUITE_DEF_IDS["all-runnable"])
        if mode_n == "live":
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
            if suite_types is not None:
                run = start_live_suite(
                    types=list(suite_types),
                    only=body.only,
                )
                return {"ok": True, "async": True, "suite": True, "run": run}
            if not (body.def_id or "").strip():
                raise HTTPException(
                    400,
                    "def_id is required (or suite=true / all-hunt|all-recon|"
                    "all-finding_report|all-runnable)",
                )
            run = start_live_run(
                def_id=body.def_id or "",
                version=body.version,
                types=body.types,
            )
            return {"ok": True, "async": True, "run": run}
        if suite_types is not None:
            run = run_benchmark_suite(
                types=list(suite_types),
                mode=body.mode or "mechanical",
            )
            return {"ok": True, "suite": True, "run": run}
        if not (body.def_id or "").strip():
            raise HTTPException(
                400,
                "def_id is required (or suite=true / all-hunt|all-recon|"
                "all-finding_report|all-runnable)",
            )
        run = run_benchmark(
            def_id=body.def_id or "",
            version=body.version,
            types=body.types,
            mode=body.mode or "mechanical",
        )
        return {"ok": True, "run": run}
    except BenchmarkRunError as e:
        raise _http_run(e) from e
    except BenchmarkLibraryError as e:
        raise _http_lib(e) from e


@router.post("/poc/runs")
def api_benchmark_poc_runs_create(body: PocWorkshopRunBody):
    """POC workshop: create + execute a ``poc_dev`` BenchmarkRun (isolated).

    Sandbox under ``benchmarks/runs/<id>/sandbox/``; ``network: none``.
    Never auto-confirms findings. Separate from Report ``#poc-modal``.
    Run-page ``POST /api/benchmarks/runs`` still refuses ``poc_dev``.
    """
    try:
        ensure_library()
        run = run_poc_workshop(
            def_id=body.def_id,
            version=body.version,
            mode=body.mode or "mechanical",
        )
        return {"ok": True, "run": run}
    except BenchmarkRunError as e:
        raise _http_run(e) from e
    except BenchmarkLibraryError as e:
        raise _http_lib(e) from e


@router.get("/runs/series")
def api_benchmark_runs_series(
    def_id: Optional[str] = None,
    type: Optional[str] = None,
):
    """Score-over-time points for a def (started_at + recall or type score).

    Query:
      def_id (required), type (optional types_run filter; score from by_type)
    """
    bid = (def_id or "").strip()
    if not bid:
        raise HTTPException(400, "def_id is required")
    try:
        ensure_library()
        get_def(bid, include_oracle=False)
    except BenchmarkLibraryError as e:
        raise _http_lib(e) from e
    try:
        runs = list_runs(
            def_id=bid,
            run_type=type,
            sort="started_at",
            order="asc",
            limit=500,
        )
        payload = build_series(runs, def_id=bid, run_type=type)
        return {"ok": True, **payload}
    except BenchmarkRunError as e:
        raise _http_run(e) from e


@router.post("/runs/{run_id}/stop")
def api_benchmark_run_stop(run_id: str):
    try:
        return {"ok": True, "run": cancel_live_run(run_id)}
    except BenchmarkRunError as e:
        raise _http_run(e) from e


@router.get("/runs/{run_id}")
def api_benchmark_run_get(run_id: str):
    try:
        run = get_run(run_id)
        if run.get("mode") == "live" and run.get("status") in {"queued", "running"}:
            run = reconcile_live_run(run_id)
        return {"ok": True, "run": run}
    except BenchmarkRunError as e:
        raise _http_run(e) from e


@router.get("/compare")
def api_benchmark_compare(
    def_id: Optional[str] = None,
    version_a: Optional[int] = None,
    version_b: Optional[int] = None,
    type: Optional[str] = None,
):
    """Side-by-side latest/aggregate metrics for two versions of one def.

    Query:
      def_id, version_a, version_b (required); type (optional types_run filter).
    Missing version → empty/zeros (not 404).
    """
    bid = (def_id or "").strip()
    if not bid:
        raise HTTPException(400, "def_id is required")
    if version_a is None or version_b is None:
        raise HTTPException(400, "version_a and version_b are required")
    try:
        ensure_library()
        get_def(bid, include_oracle=False)
    except BenchmarkLibraryError as e:
        raise _http_lib(e) from e
    try:
        runs = list_runs(
            def_id=bid,
            run_type=type,
            sort="started_at",
            order="asc",
            limit=500,
        )
        payload = compare_versions(
            runs,
            def_id=bid,
            version_a=int(version_a),
            version_b=int(version_b),
            run_type=type,
        )
        return {"ok": True, **payload}
    except BenchmarkRunError as e:
        raise _http_run(e) from e


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
