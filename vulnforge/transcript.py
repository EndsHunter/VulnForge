"""
Persist full LLM / agent transcripts per task for the dashboard.

Layouts (both supported):
  <run_dir>/transcripts/task-<id>.json              — single-pass (legacy / simple)
  <run_dir>/transcripts/task-<id>/                  — multi-pass (e.g. multi-agent recon)
      index.json
      pass-<slug>.json
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from vulnforge.util import utc_now_iso

_SLUG_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def transcripts_dir(run_dir: Path) -> Path:
    d = Path(run_dir) / "transcripts"
    d.mkdir(parents=True, exist_ok=True)
    return d


def transcript_path(run_dir: Path, task_id: int) -> Path:
    """Legacy single-file path (still written when pass_key is omitted)."""
    return transcripts_dir(run_dir) / f"task-{int(task_id)}.json"


def task_transcript_dir(run_dir: Path, task_id: int) -> Path:
    return transcripts_dir(run_dir) / f"task-{int(task_id)}"


def _safe_pass_slug(pass_key: str) -> str:
    s = (pass_key or "pass").strip()
    s = s.replace(":", "-").replace("/", "-").replace("\\", "-")
    s = _SLUG_RE.sub("-", s).strip("-._")
    return (s[:80] if s else "pass")


def pass_transcript_path(run_dir: Path, task_id: int, pass_key: str) -> Path:
    slug = _safe_pass_slug(pass_key)
    return task_transcript_dir(run_dir, task_id) / f"pass-{slug}.json"


def index_path(run_dir: Path, task_id: int) -> Path:
    return task_transcript_dir(run_dir, task_id) / "index.json"


def _write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)
    return path


def _read_json(path: Path) -> Optional[dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def save_transcript(
    run_dir: Path,
    task_id: int,
    *,
    kind: str,
    model_id: Optional[str],
    messages: list[dict],
    result: Optional[dict] = None,
    meta: Optional[dict] = None,
    pass_key: Optional[str] = None,
) -> Path:
    """
    Write a transcript file. Messages should be a serializable chat log
    (system/user/assistant/tool turns), not huge raw HTTP dumps.

    When pass_key is set (e.g. recon agent id), write under
    transcripts/task-<id>/pass-<slug>.json and update index.json so multi-agent
    runs do not clobber each other. Also mirrors the latest pass to
    task-<id>.json for backward-compatible loaders.
    """
    safe_messages = [_cap_message(m) for m in messages]
    meta_out = dict(meta or {})
    if pass_key:
        meta_out.setdefault("pass_key", pass_key)
    payload: dict[str, Any] = {
        "task_id": int(task_id),
        "kind": kind,
        "model_id": model_id,
        "saved_at": utc_now_iso(),
        "message_count": len(safe_messages),
        "messages": safe_messages,
        "result": result or {},
        "meta": meta_out,
    }
    if pass_key:
        payload["pass_key"] = pass_key

    if pass_key:
        path = pass_transcript_path(run_dir, task_id, pass_key)
        _write_json(path, payload)
        _update_index(run_dir, task_id, pass_key=pass_key, payload=payload, path=path)
        # Mirror latest for legacy single-file consumers
        try:
            _write_json(transcript_path(run_dir, task_id), payload)
        except OSError:
            pass
        return path

    path = transcript_path(run_dir, task_id)
    _write_json(path, payload)
    return path


def _update_index(
    run_dir: Path,
    task_id: int,
    *,
    pass_key: str,
    payload: dict[str, Any],
    path: Path,
) -> None:
    idx_path = index_path(run_dir, task_id)
    idx = _read_json(idx_path) or {
        "task_id": int(task_id),
        "passes": [],
        "primary_pass_key": None,
        "updated_at": None,
    }
    passes = list(idx.get("passes") or [])
    rel = path.name
    entry = {
        "pass_key": pass_key,
        "file": rel,
        "kind": payload.get("kind"),
        "model_id": payload.get("model_id"),
        "message_count": payload.get("message_count"),
        "saved_at": payload.get("saved_at"),
    }
    # Replace existing entry for same pass_key
    passes = [p for p in passes if isinstance(p, dict) and p.get("pass_key") != pass_key]
    passes.append(entry)
    idx["passes"] = passes
    idx["primary_pass_key"] = pass_key
    idx["updated_at"] = payload.get("saved_at")
    idx["task_id"] = int(task_id)
    try:
        _write_json(idx_path, idx)
    except OSError:
        pass


def load_transcript(
    run_dir: Path,
    task_id: int,
    *,
    pass_key: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Load a transcript. If pass_key is given, load that multi-pass file.
    Otherwise prefer primary multi-pass, then single-file legacy.
    """
    if pass_key:
        data = _read_json(pass_transcript_path(run_dir, task_id, pass_key))
        if data is not None:
            return data

    # Multi-pass index primary
    idx = _read_json(index_path(run_dir, task_id))
    if idx and isinstance(idx.get("passes"), list) and idx["passes"]:
        primary = pass_key or idx.get("primary_pass_key")
        if primary:
            data = _read_json(pass_transcript_path(run_dir, task_id, str(primary)))
            if data is not None:
                return data
        # Fall back to last listed pass
        last = idx["passes"][-1]
        if isinstance(last, dict) and last.get("file"):
            data = _read_json(task_transcript_dir(run_dir, task_id) / str(last["file"]))
            if data is not None:
                return data

    # Legacy single file
    return _read_json(transcript_path(run_dir, task_id))


def list_transcript_passes(run_dir: Path, task_id: int) -> list[dict[str, Any]]:
    """
    List available passes for a task.
    Returns [{pass_key, file, kind, model_id, message_count, saved_at}, ...].
    Single-file transcripts yield one synthetic pass with pass_key=None.
    """
    idx = _read_json(index_path(run_dir, task_id))
    if idx and isinstance(idx.get("passes"), list) and idx["passes"]:
        out = []
        for p in idx["passes"]:
            if isinstance(p, dict):
                out.append(dict(p))
        return out

    # Discover pass-*.json without index
    tdir = task_transcript_dir(run_dir, task_id)
    if tdir.is_dir():
        found: list[dict[str, Any]] = []
        for p in sorted(tdir.glob("pass-*.json")):
            data = _read_json(p)
            pk = None
            if data:
                pk = data.get("pass_key") or (data.get("meta") or {}).get("pass_key")
            if not pk:
                pk = p.stem[len("pass-") :] if p.stem.startswith("pass-") else p.stem
            found.append(
                {
                    "pass_key": pk,
                    "file": p.name,
                    "kind": (data or {}).get("kind"),
                    "model_id": (data or {}).get("model_id"),
                    "message_count": (data or {}).get("message_count"),
                    "saved_at": (data or {}).get("saved_at"),
                }
            )
        if found:
            return found

    data = _read_json(transcript_path(run_dir, task_id))
    if data:
        return [
            {
                "pass_key": data.get("pass_key") or (data.get("meta") or {}).get("pass_key"),
                "file": f"task-{int(task_id)}.json",
                "kind": data.get("kind"),
                "model_id": data.get("model_id"),
                "message_count": data.get("message_count"),
                "saved_at": data.get("saved_at"),
            }
        ]
    return []


def load_all_transcripts(run_dir: Path, task_id: int) -> list[dict[str, Any]]:
    """Load every pass payload (ordered). Empty list if none."""
    passes = list_transcript_passes(run_dir, task_id)
    if not passes:
        return []
    out: list[dict[str, Any]] = []
    for p in passes:
        pk = p.get("pass_key")
        if pk:
            data = load_transcript(run_dir, task_id, pass_key=str(pk))
        else:
            data = _read_json(transcript_path(run_dir, task_id))
        if data:
            out.append(data)
    return out


def list_transcript_ids(run_dir: Path) -> list[int]:
    d = Path(run_dir) / "transcripts"
    if not d.is_dir():
        return []
    ids: set[int] = set()
    for p in d.glob("task-*.json"):
        try:
            ids.add(int(p.stem.split("-", 1)[1]))
        except (ValueError, IndexError):
            continue
    for p in d.iterdir():
        if p.is_dir() and p.name.startswith("task-"):
            try:
                ids.add(int(p.name.split("-", 1)[1]))
            except (ValueError, IndexError):
                continue
    return sorted(ids)


def _cap_message(m: dict, max_content: int = 200_000) -> dict:
    out = dict(m)
    c = out.get("content")
    if isinstance(c, str) and len(c) > max_content:
        out["content"] = c[:max_content] + f"\n…[truncated {len(c)} chars]…"
        out["_truncated"] = True
    return out
