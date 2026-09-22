"""
Durable LLM token usage rollups per run.

Layout:
  <run_dir>/llm_usage.jsonl          — append-only call records
  <run_dir>/llm_usage_summary.json   — aggregated totals for UI
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Optional, Union

from vulnforge.llm import cache_hit_rate, merge_cache_source
from vulnforge.util import utc_now_iso

_lock = threading.Lock()

SUMMARY_NAME = "llm_usage_summary.json"
JSONL_NAME = "llm_usage.jsonl"


_COUNT_KEYS = (
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "reasoning_tokens",
    "cache_read_tokens",
    "cache_creation_tokens",
)


def _empty_counts() -> dict[str, Any]:
    row: dict[str, Any] = {k: 0 for k in _COUNT_KEYS}
    row["llm_calls"] = 0
    row["source"] = "none"
    row["cache_source"] = "none"
    row["cache_hit_rate"] = None
    return row


def _apply_cache_hit_rate(row: dict[str, Any]) -> None:
    row["cache_hit_rate"] = cache_hit_rate(
        int(row.get("prompt_tokens") or 0),
        int(row.get("cache_read_tokens") or 0),
        int(row.get("cache_creation_tokens") or 0),
        cache_source=str(row.get("cache_source") or "none"),
    )


def _empty_summary() -> dict[str, Any]:
    summary = _empty_counts()
    summary["by_kind"] = {}
    summary["by_model"] = {}
    # task_id → bucket + optional kind label (for UI “per hunt” rows)
    summary["by_task"] = {}
    summary["updated_at"] = None
    return summary


def _usage_to_parts(usage: Any) -> dict[str, Any]:
    if usage is None:
        return _empty_counts()
    if hasattr(usage, "to_dict"):
        d = usage.to_dict()
    elif isinstance(usage, dict):
        d = dict(usage)
    else:
        return _empty_counts()
    parts = _empty_counts()
    for key in _COUNT_KEYS:
        parts[key] = int(d.get(key) or 0)
    parts["source"] = str(d.get("source") or "none")
    parts["cache_source"] = str(d.get("cache_source") or "none")
    parts["llm_calls"] = int(d.get("llm_calls") or 1)
    _apply_cache_hit_rate(parts)
    return parts


def _merge_source(a: str, b: str) -> str:
    if not a or a == "none":
        return b or "none"
    if not b or b == "none":
        return a
    if a == b:
        return a
    return "mixed"


def _fold_cache_source(prior_calls: int, current: str, incoming: str) -> str:
    """First observation replaces the empty ``none``. Later omissions stay visible."""
    if prior_calls <= 0:
        return incoming or "none"
    return merge_cache_source(current or "none", incoming or "none")


def _bump_bucket(bucket: dict[str, Any], key: str, parts: dict[str, Any]) -> None:
    existing = bucket.get(key)
    row = dict(existing) if isinstance(existing, dict) else {}
    prior_calls = int(row.get("llm_calls") or 0)
    for count_key in _COUNT_KEYS:
        row[count_key] = int(row.get(count_key) or 0) + int(parts.get(count_key) or 0)
    row["llm_calls"] = prior_calls + int(parts.get("llm_calls") or 0)
    row["source"] = _merge_source(
        str(row.get("source") or "none"), str(parts.get("source") or "none")
    )
    row["cache_source"] = _fold_cache_source(
        prior_calls,
        str(row.get("cache_source") or "none"),
        str(parts.get("cache_source") or "none"),
    )
    _apply_cache_hit_rate(row)
    bucket[key] = row


def load_usage_summary(run_dir: Union[str, Path]) -> dict[str, Any]:
    path = Path(run_dir) / SUMMARY_NAME
    if not path.is_file():
        return _empty_summary()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty_summary()
    if not isinstance(data, dict):
        return _empty_summary()
    base = _empty_summary()
    base.update({k: data.get(k, base[k]) for k in base})
    if not isinstance(base.get("by_kind"), dict):
        base["by_kind"] = {}
    if not isinstance(base.get("by_model"), dict):
        base["by_model"] = {}
    if not isinstance(base.get("by_task"), dict):
        base["by_task"] = {}
    return base


def record_usage(
    run_dir: Union[str, Path],
    *,
    task_id: Optional[int] = None,
    kind: str = "unknown",
    model_id: Optional[str] = None,
    usage: Any = None,
    rounds: Optional[int] = None,
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Append one usage event and update the run summary. Never raises to callers."""
    run_dir = Path(run_dir)
    parts = _usage_to_parts(usage)
    if rounds is not None and parts["llm_calls"] <= 0:
        parts["llm_calls"] = max(1, int(rounds))
    if parts["llm_calls"] <= 0 and (
        parts["prompt_tokens"] or parts["completion_tokens"] or parts["total_tokens"]
    ):
        parts["llm_calls"] = 1
    if (
        parts["prompt_tokens"] == 0
        and parts["completion_tokens"] == 0
        and parts["total_tokens"] == 0
        and parts["llm_calls"] == 0
    ):
        return load_usage_summary(run_dir)

    event = {
        "ts": utc_now_iso(),
        "task_id": int(task_id) if task_id is not None else None,
        "kind": str(kind or "unknown"),
        "model_id": model_id,
        **parts,
    }
    if extra:
        event["extra"] = extra

    jsonl_path = run_dir / JSONL_NAME
    summary_path = run_dir / SUMMARY_NAME

    with _lock:
        try:
            run_dir.mkdir(parents=True, exist_ok=True)
            with jsonl_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except OSError:
            pass

        summary = load_usage_summary(run_dir)
        prior_calls = int(summary.get("llm_calls") or 0)
        for count_key in _COUNT_KEYS:
            summary[count_key] = int(summary.get(count_key) or 0) + int(
                parts.get(count_key) or 0
            )
        summary["llm_calls"] = prior_calls + int(parts.get("llm_calls") or 0)
        summary["source"] = _merge_source(
            str(summary.get("source") or "none"), str(parts.get("source") or "none")
        )
        summary["cache_source"] = _fold_cache_source(
            prior_calls,
            str(summary.get("cache_source") or "none"),
            str(parts.get("cache_source") or "none"),
        )
        _apply_cache_hit_rate(summary)
        kind_s = str(kind or "unknown")
        _bump_bucket(summary["by_kind"], kind_s, parts)
        if model_id:
            _bump_bucket(summary["by_model"], str(model_id), parts)
        if task_id is not None:
            tid_key = str(int(task_id))
            _bump_bucket(summary["by_task"], tid_key, parts)
            # Keep last kind on the row so UI can label hunts without a DB join
            row = summary["by_task"].get(tid_key) or {}
            row["kind"] = kind_s
            if extra and isinstance(extra, dict):
                for ek in ("area", "class", "profile"):
                    if extra.get(ek) is not None:
                        row[ek] = extra.get(ek)
            summary["by_task"][tid_key] = row
        summary["updated_at"] = event["ts"]
        try:
            tmp = summary_path.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            tmp.replace(summary_path)
        except OSError:
            pass
        return summary


def usage_fields_for_result(usage: Any) -> dict[str, Any]:
    """Compact fields to merge into stage task results and transcript result dicts."""
    parts = _usage_to_parts(usage)
    if not parts["llm_calls"] and not parts["total_tokens"]:
        return {}
    return {
        "prompt_tokens": parts["prompt_tokens"],
        "completion_tokens": parts["completion_tokens"],
        "total_tokens": parts["total_tokens"],
        "reasoning_tokens": parts["reasoning_tokens"],
        "llm_calls": parts["llm_calls"],
        "usage_source": parts["source"],
        "cache_read_tokens": parts["cache_read_tokens"],
        "cache_creation_tokens": parts["cache_creation_tokens"],
        "cache_source": parts["cache_source"],
        "cache_hit_rate": parts["cache_hit_rate"],
    }


def load_usage_for_task(
    run_dir: Union[str, Path], task_id: int, *, limit: int = 500
) -> list[dict[str, Any]]:
    """Return usage jsonl events for a single task_id (oldest first)."""
    path = Path(run_dir) / JSONL_NAME
    if not path.is_file():
        return []
    want = int(task_id)
    out: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict):
                    continue
                tid = row.get("task_id")
                try:
                    if tid is None or int(tid) != want:
                        continue
                except (TypeError, ValueError):
                    continue
                out.append(row)
                if len(out) >= limit:
                    break
    except OSError:
        return []
    return out


def llm_usage_for_card(run_dir: Union[str, Path]) -> dict[str, Any]:
    """Compact usage blob for home/run cards."""
    s = load_usage_summary(run_dir)
    return {
        "prompt_tokens": int(s.get("prompt_tokens") or 0),
        "completion_tokens": int(s.get("completion_tokens") or 0),
        "total_tokens": int(s.get("total_tokens") or 0),
        "reasoning_tokens": int(s.get("reasoning_tokens") or 0),
        "llm_calls": int(s.get("llm_calls") or 0),
        "source": s.get("source") or "none",
        "cache_read_tokens": int(s.get("cache_read_tokens") or 0),
        "cache_creation_tokens": int(s.get("cache_creation_tokens") or 0),
        "cache_source": s.get("cache_source") or "none",
        "cache_hit_rate": s.get("cache_hit_rate"),
    }


def hunt_class_from_kind(kind: str | None) -> str | None:
    """Extract hunt profile id from kinds like ``hunt:injection``."""
    if not kind or not isinstance(kind, str):
        return None
    k = kind.strip()
    if k.startswith("hunt:") and len(k) > 5:
        return k[5:].strip() or None
    if k == "hunt":
        return "hunt"
    return None


def rebuild_by_task_from_jsonl(run_dir: Union[str, Path]) -> dict[str, Any]:
    """Rebuild by_task (and refresh by_kind hunt rows) from jsonl for older runs.

    Used when summary lacks by_task but llm_usage.jsonl has per-task events.
    Does not rewrite the summary file (read-path enrichment only).
    """
    path = Path(run_dir) / JSONL_NAME
    by_task: dict[str, Any] = {}
    if not path.is_file():
        return by_task
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict):
                    continue
                tid = row.get("task_id")
                if tid is None:
                    continue
                try:
                    tid_key = str(int(tid))
                except (TypeError, ValueError):
                    continue
                parts = {
                    "prompt_tokens": int(row.get("prompt_tokens") or 0),
                    "completion_tokens": int(row.get("completion_tokens") or 0),
                    "total_tokens": int(row.get("total_tokens") or 0),
                    "reasoning_tokens": int(row.get("reasoning_tokens") or 0),
                    "cache_read_tokens": int(row.get("cache_read_tokens") or 0),
                    "cache_creation_tokens": int(row.get("cache_creation_tokens") or 0),
                    "source": str(row.get("source") or "none"),
                    "cache_source": str(row.get("cache_source") or "none"),
                    "llm_calls": int(row.get("llm_calls") or 1),
                }
                _bump_bucket(by_task, tid_key, parts)
                kind_s = str(row.get("kind") or "unknown")
                by_task[tid_key]["kind"] = kind_s
                extra = row.get("extra") if isinstance(row.get("extra"), dict) else {}
                for ek in ("area", "class", "profile"):
                    if extra.get(ek) is not None:
                        by_task[tid_key][ek] = extra.get(ek)
                    elif ek == "class":
                        hc = hunt_class_from_kind(kind_s)
                        if hc and hc != "hunt":
                            by_task[tid_key]["class"] = hc
    except OSError:
        return by_task
    return by_task


def record_llm_result(
    run_dir: Union[str, Path],
    *,
    task_id: Optional[int],
    kind: str,
    model_id: Optional[str],
    result: Any,
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Record usage from an LLMResult (or similar) and return fields for task results."""
    usage = getattr(result, "usage", None)
    record_usage(
        run_dir,
        task_id=task_id,
        kind=kind,
        model_id=model_id or getattr(result, "model_id", None),
        usage=usage,
        extra=extra,
    )
    return usage_fields_for_result(usage)
