"""Read ``python -m bench`` result directories for the Benchmarks desk.

A results directory is a folder of run directories (the layout
``emit_results`` writes under ``bench/results/<timestamp>/``). This module
never writes that tree.

Each run directory is one of:

- ``scorecard.json`` — a scored or partial scorecard. Leaderboard rows stay
  visible when ``excluded`` is true. ``attempt_errors`` and those excluded
  rows are the error rows.
- ``error.json`` — a failed run that never wrote a scorecard. ``rows`` are
  the error rows.
- ``run.json`` — an unscored run. Same row shape.
- anything else with no scorecard — unscored, with ``error.txt`` or
  ``errors.json`` when those files exist.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

_MAX_BYTES = 8_000_000
_STATUSES = ("scored", "partial", "failed", "unscored")
_STATUS_ORDER = {"scored": 0, "partial": 1, "failed": 2, "unscored": 3}
_BADGE = {
    "scored": "succeeded",
    "partial": "incomplete",
    "failed": "failed_task",
    "unscored": "cancelled",
}


def resolve_bench_results(project_root: Path, explicit: Path | None = None) -> Path:
    """Flag, then ``VF_BENCH_RESULTS``, then ``<project>/bench/results``."""
    if explicit is not None:
        return Path(explicit).expanduser().resolve()
    env = os.environ.get("VF_BENCH_RESULTS", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    return (Path(project_root) / "bench" / "results").resolve()


def format_metric(value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        text = f"{value:.6f}".rstrip("0").rstrip(".")
        return text or "0"
    return str(value)


def list_runs(root: Path) -> list[dict]:
    if not root.is_dir():
        return []
    children = _child_dirs(root)
    if children:
        runs = [_load_dir(child) for child in children]
    elif _looks_like_run(root):
        runs = [_load_dir(root)]
    else:
        return []
    runs.sort(key=lambda run: run["id"], reverse=True)
    runs.sort(key=lambda run: _STATUS_ORDER.get(run["status"], 9))
    return runs


def get_run(root: Path, run_id: str) -> dict | None:
    if not _safe_id(run_id) or not root.is_dir():
        return None
    direct = root / run_id
    if direct.is_dir() and _inside(root, direct):
        return _load_dir(direct)
    if root.name == run_id and _looks_like_run(root):
        return _load_dir(root)
    return None


def _safe_id(run_id: str) -> bool:
    if not run_id or run_id in {".", ".."}:
        return False
    if "/" in run_id or "\\" in run_id or ".." in run_id:
        return False
    return True


def _inside(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _child_dirs(root: Path) -> list[Path]:
    try:
        entries = list(root.iterdir())
    except OSError:
        return []
    found: list[Path] = []
    for entry in entries:
        if entry.name.startswith(".") or entry.name.startswith("_"):
            continue
        if not _inside(root, entry):
            continue
        try:
            if not entry.is_dir():
                continue
        except OSError:
            continue
        found.append(entry)
    found.sort(key=lambda path: path.name)
    return found


def _looks_like_run(path: Path) -> bool:
    names = ("scorecard.json", "error.json", "run.json", "errors.json", "error.txt")
    return any((path / name).is_file() for name in names)


def _load_dir(path: Path) -> dict:
    run_id = path.name
    scorecard = path / "scorecard.json"
    if scorecard.is_file():
        data, err = _read_json(scorecard)
        if err:
            return _shell(run_id, "failed", error=err, error_rows=_sidecar_rows(path))
        if not isinstance(data, dict):
            return _shell(
                run_id,
                "failed",
                error="scorecard.json is not an object",
                error_rows=_sidecar_rows(path),
            )
        return _from_scorecard(run_id, data)
    for name, default in (("error.json", "failed"), ("run.json", "unscored")):
        file = path / name
        if file.is_file():
            return _from_loose_file(run_id, file, default)
    errors = path / "errors.json"
    if errors.is_file():
        data, err = _read_json(errors)
        if err:
            return _shell(run_id, "unscored", error=err)
        rows = data if isinstance(data, list) else []
        if isinstance(data, dict):
            return _from_loose(run_id, data, "unscored")
        return _shell(run_id, "unscored", error="no scorecard.json", error_rows=_error_rows(rows))
    note = path / "error.txt"
    if note.is_file():
        try:
            text = note.read_text(encoding="utf-8")
        except OSError as exc:
            text = str(exc)
        return _shell(run_id, "failed", error=_clip(text))
    return _shell(run_id, "unscored", error="no scorecard.json")


def _from_loose_file(run_id: str, path: Path, default: str) -> dict:
    data, err = _read_json(path)
    if err:
        return _shell(run_id, default if default in _STATUSES else "failed", error=err)
    if isinstance(data, list):
        return _shell(run_id, default, error=None, error_rows=_error_rows(data))
    if not isinstance(data, dict):
        return _shell(run_id, default, error=f"{path.name} is not an object")
    if "leaderboard" in data or "scorecard_version" in data:
        view = _from_scorecard(run_id, data)
        status = data.get("status")
        if status in {"failed", "unscored"}:
            view["status"] = status
        return view
    return _from_loose(run_id, data, default)


def _from_loose(run_id: str, data: dict, default: str) -> dict:
    status = data.get("status") or default
    if status not in _STATUSES:
        status = default
    rows = data.get("rows")
    if rows is None:
        rows = data.get("error_rows") or []
    if not isinstance(rows, list):
        rows = []
    error = data.get("error") or data.get("message")
    return _shell(
        run_id,
        status,
        error=_clip(str(error)) if error else None,
        error_rows=_error_rows(rows, model=data.get("model"), difficulty=data.get("difficulty")),
        mode=data.get("mode"),
        partial=_as_bool(data.get("partial")),
        cache_coverage=data.get("cache_coverage"),
        stored_failure_count=data.get("stored_failure_count"),
        infra_error_row_count=data.get("infra_error_row_count"),
        infra_error_count=data.get("infra_error_count"),
        scored_row_count=data.get("scored_row_count"),
        fpr_cap=data.get("fpr_cap"),
        headline_metric=data.get("headline_metric"),
        gate_failed=bool((data.get("disprove_gate") or {}).get("failed"))
        if isinstance(data.get("disprove_gate"), dict)
        else False,
        warnings=_warnings(data.get("warnings")),
        scores_are_synthetic=bool(data.get("scores_are_synthetic")),
    )


def _from_scorecard(run_id: str, data: dict) -> dict:
    board = data.get("leaderboard") if isinstance(data.get("leaderboard"), dict) else {}
    raw_rows = board.get("rows") if isinstance(board.get("rows"), list) else []
    models = data.get("models") if isinstance(data.get("models"), dict) else {}
    rows = []
    for row in raw_rows:
        if not isinstance(row, dict):
            continue
        model = row.get("model")
        difficulty = row.get("difficulty")
        rows.append(
            {
                "model": model,
                "difficulty": difficulty,
                "precision": row.get("precision"),
                "recall": _stage_recall(models, model, difficulty),
                "recall_at_fpr_le_0.5pct": row.get("recall_at_fpr_le_0.5pct"),
                "vd_s": row.get("vd_s"),
                "fpr": row.get("fpr"),
                "youden": row.get("youden"),
                "youden_in_ranking": row.get("youden_in_ranking")
                if isinstance(row.get("youden_in_ranking"), bool)
                else None,
                "excluded": bool(row.get("excluded")),
                "exclude_reason": row.get("exclude_reason"),
                "errors": row.get("errors"),
                "rank": row.get("rank"),
                "on_frontier": bool(row.get("on_frontier")),
            }
        )
    error_rows = _attempt_errors(models)
    for row in rows:
        if not row["excluded"]:
            continue
        error_rows.append(
            {
                "model": row["model"],
                "difficulty": row["difficulty"],
                "task_id": "",
                "side": "",
                "error": row["exclude_reason"] or "infra_errors",
                "error_kind": "infra_errors",
            }
        )
    partial = _as_bool(_pick(data, board, "partial"))
    status = "partial" if partial else "scored"
    gate = data.get("disprove_gate") if isinstance(data.get("disprove_gate"), dict) else {}
    return _shell(
        run_id,
        status,
        error=None,
        rows=rows,
        error_rows=_dedupe_errors(error_rows),
        mode=data.get("mode") if isinstance(data.get("mode"), str) else None,
        partial=partial,
        cache_coverage=_pick(data, board, "cache_coverage"),
        stored_failure_count=_pick(data, board, "stored_failure_count"),
        infra_error_row_count=board.get("infra_error_row_count"),
        infra_error_count=board.get("infra_error_count"),
        scored_row_count=board.get("scored_row_count"),
        fpr_cap=data.get("fpr_cap"),
        headline_metric=data.get("headline_metric") or board.get("headline_metric"),
        gate_failed=bool(gate.get("failed")),
        warnings=_warnings(data.get("warnings")),
        scores_are_synthetic=bool(data.get("scores_are_synthetic")),
    )


def _shell(
    run_id: str,
    status: str,
    *,
    error: str | None = None,
    rows: list | None = None,
    error_rows: list | None = None,
    mode: str | None = None,
    partial: bool | None = None,
    cache_coverage: object = None,
    stored_failure_count: object = None,
    infra_error_row_count: object = None,
    infra_error_count: object = None,
    scored_row_count: object = None,
    fpr_cap: object = None,
    headline_metric: object = None,
    gate_failed: bool = False,
    warnings: list | None = None,
    scores_are_synthetic: bool = False,
) -> dict:
    view_rows = rows or []
    status_name = status if status in _STATUSES else "unscored"
    return {
        "id": run_id,
        "status": status_name,
        "badge": _BADGE.get(status_name, "cancelled"),
        "mode": mode,
        "error": error,
        "partial": partial,
        "cache_coverage": cache_coverage,
        "stored_failure_count": stored_failure_count,
        "infra_error_row_count": infra_error_row_count,
        "infra_error_count": infra_error_count,
        "scored_row_count": scored_row_count,
        "fpr_cap": fpr_cap,
        "headline_metric": headline_metric,
        "headline_recall": _headline_recall(view_rows),
        "gate_failed": gate_failed,
        "scores_are_synthetic": scores_are_synthetic,
        "warnings": warnings or [],
        "rows": view_rows,
        "error_rows": error_rows or [],
    }


def _headline_recall(rows: list[dict]) -> object:
    ranked = [row for row in rows if isinstance(row.get("rank"), int) and not row.get("excluded")]
    if ranked:
        top = min(ranked, key=lambda row: row["rank"])
        return top.get("recall_at_fpr_le_0.5pct")
    open_rows = [row for row in rows if not row.get("excluded")]
    if open_rows:
        return open_rows[0].get("recall_at_fpr_le_0.5pct")
    return None


def _stage_recall(models: dict, model: object, difficulty: object) -> float | None:
    try:
        value = models[model]["difficulties"][difficulty]["mean"]["stages"]["disprove"]["recall"]
    except (KeyError, TypeError):
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _attempt_errors(models: dict) -> list[dict]:
    found: list[dict] = []
    for model, body in models.items():
        difficulties = body.get("difficulties") if isinstance(body, dict) else None
        if not isinstance(difficulties, dict):
            continue
        for difficulty, diff in difficulties.items():
            repeats = diff.get("repeats") if isinstance(diff, dict) else None
            if not isinstance(repeats, list):
                continue
            for repeat in repeats:
                items = repeat.get("attempt_errors") if isinstance(repeat, dict) else None
                if not isinstance(items, list):
                    continue
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    found.append(
                        {
                            "model": model,
                            "difficulty": difficulty,
                            "task_id": item.get("task_id") or "",
                            "side": item.get("side") or "",
                            "error": item.get("error") or "",
                            "error_kind": item.get("error_kind") or "",
                        }
                    )
    return found


def _error_rows(rows: list, model: object = None, difficulty: object = None) -> list[dict]:
    found = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        found.append(
            {
                "model": item.get("model", model) or "",
                "difficulty": item.get("difficulty", difficulty) or "",
                "task_id": item.get("task_id") or "",
                "side": item.get("side") or "",
                "error": item.get("error") or item.get("message") or "",
                "error_kind": item.get("error_kind") or "",
            }
        )
    return _dedupe_errors(found)


def _dedupe_errors(rows: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out = []
    for row in rows:
        key = tuple(row.get(name) for name in ("model", "difficulty", "task_id", "side", "error", "error_kind"))
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def _sidecar_rows(path: Path) -> list[dict]:
    file = path / "error.json"
    if not file.is_file():
        return []
    data, err = _read_json(file)
    if err or isinstance(data, list):
        return _error_rows(data if isinstance(data, list) else [])
    if isinstance(data, dict):
        rows = data.get("rows") or data.get("error_rows") or []
        return _error_rows(rows if isinstance(rows, list) else [])
    return []


def _pick(data: dict, board: dict, key: str) -> object:
    if key in data:
        return data[key]
    return board.get(key)


def _as_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def _warnings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    out = []
    for item in value[:8]:
        if isinstance(item, str) and item.strip():
            out.append(_clip(item, 500))
    return out


def _clip(text: str, limit: int = 2000) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _read_json(path: Path) -> tuple[object | None, str | None]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"{path.name}: {exc}"
    if len(raw.encode("utf-8")) > _MAX_BYTES:
        return None, f"{path.name}: file is too large"
    try:
        return json.loads(raw), None
    except json.JSONDecodeError as exc:
        return None, f"{path.name}: {exc.msg}"
