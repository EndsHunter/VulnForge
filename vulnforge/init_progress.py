"""Init / long-job progress for CLI and dashboard polling."""

from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Optional

from vulnforge.util import utc_now_iso, write_json

ProgressFn = Callable[[dict[str, Any]], None]

# In-process job registry (dashboard process)
_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()


def new_job_id() -> str:
    return uuid.uuid4().hex[:12]


def _jobs_dir(project_root: Path) -> Path:
    d = project_root / "runs" / ".init_jobs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_job(project_root: Path, job_id: str, payload: dict[str, Any]) -> None:
    payload = {**payload, "job_id": job_id, "updated_at": utc_now_iso()}
    with _JOBS_LOCK:
        _JOBS[job_id] = payload
    try:
        write_json(_jobs_dir(project_root) / f"{job_id}.json", payload)
    except OSError:
        pass


def read_job(project_root: Path, job_id: str) -> Optional[dict[str, Any]]:
    with _JOBS_LOCK:
        if job_id in _JOBS:
            return dict(_JOBS[job_id])
    path = _jobs_dir(project_root) / f"{job_id}.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def make_progress_writer(
    project_root: Path,
    job_id: Optional[str] = None,
    *,
    also_print: bool = False,
) -> ProgressFn:
    """Return a callback that updates job status (and optionally prints to stderr)."""

    def progress(update: dict[str, Any]) -> None:
        phase = str(update.get("phase") or "working")
        message = str(update.get("message") or phase)
        files_seen = update.get("files_seen")
        pct = update.get("percent")
        status = str(update.get("status") or "running")
        if also_print:
            import sys

            extra = ""
            if files_seen is not None:
                extra += f" files={files_seen}"
            if pct is not None:
                extra += f" ~{pct}%"
            print(f"[init {phase}]{extra} {message}", file=sys.stderr, flush=True)
        if not job_id:
            return
        cur = read_job(project_root, job_id) or {
            "job_id": job_id,
            "status": "running",
            "phase": "start",
            "message": "",
            "created_at": utc_now_iso(),
        }
        cur.update(
            {
                "status": status,
                "phase": phase,
                "message": message,
            }
        )
        if files_seen is not None:
            cur["files_seen"] = files_seen
        if pct is not None:
            cur["percent"] = pct
        for k in (
            "dirs_seen",
            "hashed",
            "run_dir",
            "key",
            "target_id",
            "run_id",
            "error",
            "strategy",
            "target",
        ):
            if k in update:
                cur[k] = update[k]
        write_job(project_root, job_id, cur)

    return progress
