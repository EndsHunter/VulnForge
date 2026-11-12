"""Record exceptions that are deliberately swallowed (issue #173).

Many best-effort paths keep the Ralph loop alive by catching ``Exception``.
That is the right call for the loop, but a bare ``pass`` hides bugs. Call
:func:`note_swallowed` in those handlers instead::

    try:
        client.close()
    except Exception as e:
        note_swallowed(e, context="hunt.client_close", level=logging.DEBUG)

What it does:

- Logs the exception with its context. The first occurrence of a context in
  this process logs at ``level`` (default WARNING); later ones log at DEBUG
  so a hot path cannot flood the log.
- Increments an in-process counter keyed by run directory (``""`` when no
  run is known).
- When a run directory is known (explicit ``run_dir=`` or the leased task
  bound by :mod:`vulnforge.live_task`), appends one short JSON line to
  ``{run_dir}/swallowed_errors.jsonl`` so other processes (the dashboard)
  can show a per-run count. Writes stop after ``_MAX_LINES_PER_RUN`` lines
  per process and run; the in-process counter keeps counting.

It never raises and never changes control flow. This module imports only
the standard library at import time so any module can use it.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

logger = logging.getLogger("vulnforge.swallowed")

SWALLOWED_LOG_NAME = "swallowed_errors.jsonl"

_MAX_LINES_PER_RUN = 1000
_MSG_MAX = 300
_CONTEXT_MAX = 120
_READ_MAX_BYTES = 4 * 1024 * 1024

_lock = threading.Lock()
_counts: Counter[str] = Counter()
_lines_written: Counter[str] = Counter()
_seen_contexts: set[str] = set()


def _bound_run_dir() -> Optional[Path]:
    try:
        from vulnforge.live_task import current_bind

        bind = current_bind()
        return Path(bind.run_dir) if bind is not None else None
    except Exception:  # noqa: BLE001 - helper must never raise
        return None


def note_swallowed(
    exc: BaseException,
    context: str = "",
    *,
    run_dir: Optional[Union[str, Path]] = None,
    level: int = logging.WARNING,
) -> None:
    """Log and count an exception that the caller intends to swallow.

    Never raises. Does not re-raise ``exc``.
    """
    try:
        ctx = str(context or "unknown")[:_CONTEXT_MAX]
        rd = Path(run_dir) if run_dir is not None else _bound_run_dir()
        key = str(rd) if rd is not None else ""
        with _lock:
            _counts[key] += 1
            first = ctx not in _seen_contexts
            if first:
                _seen_contexts.add(ctx)
            write_line = rd is not None and _lines_written[key] < _MAX_LINES_PER_RUN
            if write_line:
                _lines_written[key] += 1
        etype = type(exc).__name__
        msg = str(exc)[:_MSG_MAX]
        log_level = level if first else logging.DEBUG
        logger.log(
            log_level,
            "swallowed %s in %s: %s",
            etype,
            ctx,
            msg,
            exc_info=(type(exc), exc, exc.__traceback__) if log_level <= logging.DEBUG else None,
        )
        if write_line and rd is not None:
            line = json.dumps(
                {
                    "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "context": ctx,
                    "type": etype,
                    "message": msg,
                    "pid": os.getpid(),
                },
                ensure_ascii=False,
            )
            with (rd / SWALLOWED_LOG_NAME).open("a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:  # noqa: BLE001 - the one handler allowed to stay silent
        pass


def swallowed_count(run_dir: Optional[Union[str, Path]] = None) -> int:
    """In-process count for ``run_dir`` (``None`` = not attributed to a run)."""
    key = str(Path(run_dir)) if run_dir is not None else ""
    with _lock:
        return int(_counts.get(key, 0))


def swallowed_counts() -> dict[str, int]:
    """Snapshot of all in-process counters keyed by run dir (``""`` = none)."""
    with _lock:
        return dict(_counts)


def reset_swallowed_counts() -> None:
    """Clear in-process counters and first-seen state (tests)."""
    with _lock:
        _counts.clear()
        _lines_written.clear()
        _seen_contexts.clear()


def read_swallowed_summary(run_dir: Union[str, Path], *, top: int = 5) -> dict[str, Any]:
    """Summarize ``{run_dir}/swallowed_errors.jsonl`` for the dashboard.

    Returns ``{"count": int, "by_context": [{"context", "count"}...],
    "last_ts": str | None, "truncated": bool}``. A missing or unreadable file
    is a zero count. Malformed lines still count.
    """
    out: dict[str, Any] = {"count": 0, "by_context": [], "last_ts": None, "truncated": False}
    path = Path(run_dir) / SWALLOWED_LOG_NAME
    try:
        size = path.stat().st_size
    except OSError:
        return out
    try:
        with path.open("rb") as f:
            raw = f.read(_READ_MAX_BYTES)
    except OSError:
        return out
    out["truncated"] = size > _READ_MAX_BYTES
    by_ctx: Counter[str] = Counter()
    count = 0
    last_ts: Optional[str] = None
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        count += 1
        try:
            row = json.loads(line)
        except ValueError:
            by_ctx["?"] += 1
            continue
        if not isinstance(row, dict):
            by_ctx["?"] += 1
            continue
        by_ctx[str(row.get("context") or "?")] += 1
        if row.get("ts"):
            last_ts = str(row["ts"])
    out["count"] = count
    out["last_ts"] = last_ts
    out["by_context"] = [{"context": c, "count": n} for c, n in by_ctx.most_common(max(0, top))]
    return out
