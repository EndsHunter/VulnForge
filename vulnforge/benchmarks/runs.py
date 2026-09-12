"""Filesystem JSON store for BenchmarkRun records.

Durable under ``<project>/benchmarks/runs/<id>/result.json`` (not ``project/``).
Authority for run metrics stays here; Library remains ``benchmarks/library/``.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any, Optional

from vulnforge.paths import PROJECT_ROOT
from vulnforge.util import utc_now_iso

RUNS_FORMAT = "vulnforge.benchmark_run/v1"
DEFAULT_RUNS_ROOT = PROJECT_ROOT / "benchmarks" / "runs"
RUN_STATUSES = frozenset(
    {"queued", "running", "passed", "failed", "error", "cancelled"}
)
TERMINAL_STATUSES = frozenset({"passed", "failed", "error", "cancelled"})
RUN_ID_RE = re.compile(r"^br-[a-z0-9]{8,32}$")

_root_override: Optional[Path] = None


class BenchmarkRunError(ValueError):
    """Invalid benchmark run operation."""


def set_runs_root(root: Path | str | None) -> None:
    """Override runs root (tests). Pass None to clear."""
    global _root_override
    if root is None:
        _root_override = None
    else:
        _root_override = Path(root).resolve()


def reset_runs_root_override() -> None:
    set_runs_root(None)


def runs_root() -> Path:
    if _root_override is not None:
        return _root_override
    env = (os.environ.get("VULNFORGE_BENCHMARKS_RUNS_ROOT") or "").strip()
    if env:
        return Path(env).resolve()
    return DEFAULT_RUNS_ROOT


def new_run_id() -> str:
    return f"br-{uuid.uuid4().hex[:12]}"


def _validate_run_id(raw: str) -> str:
    rid = str(raw or "").strip().lower()
    if not RUN_ID_RE.match(rid):
        raise BenchmarkRunError(f"invalid run id {raw!r}")
    return rid


def _run_dir(run_id: str, root: Optional[Path] = None) -> Path:
    root = root or runs_root()
    rid = _validate_run_id(run_id)
    base = root.resolve()
    path = (base / rid).resolve()
    try:
        path.relative_to(base)
    except ValueError as e:
        raise BenchmarkRunError(f"path escape for run: {rid}") from e
    return path


def _result_path(run_id: str, root: Optional[Path] = None) -> Path:
    return _run_dir(run_id, root) / "result.json"


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2) + "\n"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


# Run-page runnable types (poc_dev refused on Run path — use POC workshop).
RUNNABLE_TYPES = frozenset({"recon", "hunt", "finding_report"})
# Types allowed on BenchmarkRun.types_run (includes workshop poc_dev).
PERSISTED_TYPES = frozenset({"recon", "hunt", "finding_report", "poc_dev"})


def _normalize_types_run(raw: object) -> list[str]:
    if raw is None:
        return ["hunt"]
    if isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, (list, tuple)):
        items = list(raw)
    else:
        items = []
    out: list[str] = []
    seen: set[str] = set()
    for t in items:
        key = str(t or "").strip().lower().replace(" ", "_")
        if not key or key in seen:
            continue
        # Unknown types dropped; poc_dev allowed for workshop runs only
        # (Run path still refuses poc_dev before create_run).
        if key not in PERSISTED_TYPES:
            continue
        seen.add(key)
        out.append(key)
    return out or ["hunt"]


def _public_run(raw: dict[str, Any]) -> dict[str, Any]:
    status = str(raw.get("status") or "queued").strip().lower()
    if status not in RUN_STATUSES:
        status = "error"
    metrics = raw.get("metrics")
    if not isinstance(metrics, dict):
        metrics = {}
    return {
        "id": str(raw.get("id") or ""),
        "def_id": str(raw.get("def_id") or ""),
        "version": int(raw.get("version") or 0),
        "types_run": _normalize_types_run(raw.get("types_run")),
        "status": status,
        "mode": str(raw.get("mode") or "mechanical")[:32],
        "started_at": str(raw.get("started_at") or ""),
        "finished_at": str(raw.get("finished_at") or "") or None,
        "harness_run_dir": (
            str(raw["harness_run_dir"]) if raw.get("harness_run_dir") else None
        ),
        "metrics": deepcopy(metrics),
        "events_ref": str(raw["events_ref"]) if raw.get("events_ref") else None,
        "error": str(raw["error"]) if raw.get("error") else None,
        "target_ref": str(raw.get("target_ref") or ""),
        "oracle_hash": str(raw.get("oracle_hash") or ""),
    }


def create_run(
    *,
    def_id: str,
    version: int,
    types_run: list[str] | None = None,
    mode: str = "mechanical",
    target_ref: str = "",
    oracle_hash: str = "",
    status: str = "queued",
    run_id: str | None = None,
) -> dict[str, Any]:
    """Allocate a new BenchmarkRun record (queued/running)."""
    rid = _validate_run_id(run_id) if run_id else new_run_id()
    st = str(status or "queued").strip().lower()
    if st not in RUN_STATUSES:
        raise BenchmarkRunError(f"invalid status: {status}")
    path = _result_path(rid)
    if path.is_file():
        raise BenchmarkRunError(f"run already exists: {rid}")
    now = utc_now_iso()
    row = _public_run(
        {
            "format": RUNS_FORMAT,
            "id": rid,
            "def_id": str(def_id or "").strip().lower(),
            "version": int(version),
            "types_run": types_run or ["hunt"],
            "status": st,
            "mode": (mode or "mechanical")[:32],
            "started_at": now,
            "finished_at": None,
            "harness_run_dir": None,
            "metrics": {},
            "events_ref": None,
            "error": None,
            "target_ref": target_ref,
            "oracle_hash": oracle_hash,
        }
    )
    row["format"] = RUNS_FORMAT
    _atomic_write_json(path, row)
    return get_run(rid)


def update_run(run_id: str, **fields: Any) -> dict[str, Any]:
    """Patch allowed fields on an existing run and persist."""
    rid = _validate_run_id(run_id)
    path = _result_path(rid)
    if not path.is_file():
        raise BenchmarkRunError(f"unknown run: {rid}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise BenchmarkRunError(f"corrupt run {rid}: {e}") from e
    if not isinstance(raw, dict):
        raise BenchmarkRunError(f"run {rid} must be an object")
    allowed = {
        "status",
        "finished_at",
        "harness_run_dir",
        "metrics",
        "events_ref",
        "error",
        "target_ref",
        "oracle_hash",
        "mode",
        "types_run",
    }
    for key, val in fields.items():
        if key not in allowed:
            continue
        if key == "status":
            st = str(val or "").strip().lower()
            if st not in RUN_STATUSES:
                raise BenchmarkRunError(f"invalid status: {val}")
            raw["status"] = st
            if st in TERMINAL_STATUSES and not raw.get("finished_at"):
                raw["finished_at"] = utc_now_iso()
        elif key == "metrics":
            raw["metrics"] = deepcopy(val) if isinstance(val, dict) else {}
        elif key == "types_run":
            raw["types_run"] = _normalize_types_run(val)
        else:
            raw[key] = val
    raw["id"] = rid
    raw["format"] = RUNS_FORMAT
    public = _public_run(raw)
    public["format"] = RUNS_FORMAT
    _atomic_write_json(path, public)
    return get_run(rid)


def get_run(run_id: str) -> dict[str, Any]:
    rid = _validate_run_id(run_id)
    path = _result_path(rid)
    if not path.is_file():
        raise BenchmarkRunError(f"unknown run: {rid}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise BenchmarkRunError(f"corrupt run {rid}: {e}") from e
    if not isinstance(raw, dict):
        raise BenchmarkRunError(f"run {rid} must be an object")
    return _public_run(raw)


SORT_KEYS = frozenset({"started_at", "finished_at", "recall", "status", "def_id"})
ORDER_KEYS = frozenset({"asc", "desc"})


def _sort_key_for(row: dict[str, Any], sort: str) -> Any:
    if sort == "recall":
        metrics = row.get("metrics") if isinstance(row.get("metrics"), dict) else {}
        try:
            return float(metrics.get("recall") or 0.0)
        except (TypeError, ValueError):
            return 0.0
    if sort == "finished_at":
        return str(row.get("finished_at") or "")
    if sort == "status":
        return str(row.get("status") or "")
    if sort == "def_id":
        return str(row.get("def_id") or "")
    # default started_at
    return str(row.get("started_at") or "")


def list_runs(
    *,
    def_id: str | None = None,
    version: int | None = None,
    status: str | None = None,
    run_type: str | None = None,
    sort: str = "started_at",
    order: str = "desc",
    limit: int = 200,
) -> list[dict[str, Any]]:
    """List BenchmarkRun records with optional filters and sort.

    Filters:
      - def_id: exact match
      - version: exact int match
      - status: exact match
      - run_type: types_run contains (query param ``type``)

    Sort: started_at|finished_at|recall|status|def_id (default started_at).
    Order: asc|desc (default desc — newest first for started_at).
    """
    root = runs_root()
    if not root.is_dir():
        return []
    sort_key = str(sort or "started_at").strip().lower()
    if sort_key not in SORT_KEYS:
        sort_key = "started_at"
    order_key = str(order or "desc").strip().lower()
    if order_key not in ORDER_KEYS:
        order_key = "desc"
    reverse = order_key == "desc"

    want_def = str(def_id).strip().lower() if def_id else None
    want_status = str(status).strip().lower() if status else None
    want_type = str(run_type).strip().lower().replace(" ", "_") if run_type else None
    want_ver: int | None = None
    if version is not None:
        try:
            want_ver = int(version)
        except (TypeError, ValueError):
            want_ver = None

    out: list[dict[str, Any]] = []
    for child in root.iterdir():
        if not child.is_dir():
            continue
        result = child / "result.json"
        if not result.is_file():
            continue
        try:
            raw = json.loads(result.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(raw, dict):
            continue
        row = _public_run(raw)
        if want_def and row["def_id"] != want_def:
            continue
        if want_ver is not None and int(row.get("version") or 0) != want_ver:
            continue
        if want_status and row["status"] != want_status:
            continue
        if want_type:
            types = [str(t).lower() for t in (row.get("types_run") or [])]
            if want_type not in types:
                continue
        out.append(row)
    out.sort(key=lambda r: _sort_key_for(r, sort_key), reverse=reverse)
    return out[: max(1, int(limit))]
