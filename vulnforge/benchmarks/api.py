"""Thin FastAPI router for the benchmark library."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

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


def _http(exc: BenchmarkLibraryError) -> HTTPException:
    msg = str(exc)
    if msg.startswith("unknown benchmark"):
        return HTTPException(404, msg)
    if "already exists" in msg:
        return HTTPException(409, msg)
    return HTTPException(400, msg)


@router.get("")
def api_benchmarks_list():
    """List BenchmarkDef heads (seeds on first init)."""
    try:
        ensure_library()
        return {"ok": True, "benchmarks": list_defs()}
    except BenchmarkLibraryError as e:
        raise _http(e) from e


@router.post("/seed")
def api_benchmarks_seed():
    """Import missing GT hunt benches only — never clobber existing ids."""
    try:
        ensure_library()
        return seed_from_ground_truth(missing_only=True)
    except BenchmarkLibraryError as e:
        raise _http(e) from e


@router.get("/{bench_id}/versions")
def api_benchmark_versions(bench_id: str):
    try:
        return {"ok": True, "id": bench_id, "versions": list_versions(bench_id)}
    except BenchmarkLibraryError as e:
        raise _http(e) from e


@router.get("/{bench_id}/versions/{ver}")
def api_benchmark_version_get(bench_id: str, ver: int):
    """Immutable snapshot. Mutating the head later must not change this payload."""
    try:
        return {"ok": True, "version": get_version(bench_id, ver)}
    except BenchmarkLibraryError as e:
        raise _http(e) from e


@router.get("/{bench_id}")
def api_benchmark_get(bench_id: str):
    try:
        return {"ok": True, "benchmark": get_def(bench_id, include_oracle=True)}
    except BenchmarkLibraryError as e:
        raise _http(e) from e


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
        raise _http(e) from e


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
        raise _http(e) from e


@router.delete("/{bench_id}")
def api_benchmark_delete(bench_id: str):
    try:
        return delete_def(bench_id)
    except BenchmarkLibraryError as e:
        raise _http(e) from e
