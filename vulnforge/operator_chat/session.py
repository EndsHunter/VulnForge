"""Persist operator chat sessions on disk."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Optional

from vulnforge.util import utc_now_iso

MAX_MESSAGES = 80


def home_sessions_dir(project_root: Path) -> Path:
    return Path(project_root) / "config" / "operator_chat" / "home"


def run_sessions_dir(run_dir: Path) -> Path:
    return Path(run_dir) / "operator_chat"


def new_session_id() -> str:
    return uuid.uuid4().hex[:16]


def _path_for(scope: str, session_id: str, *, project_root: Path, run_dir: Optional[Path]) -> Path:
    if scope == "run":
        if run_dir is None:
            raise ValueError("run_dir required for run sessions")
        return run_sessions_dir(run_dir) / f"{session_id}.json"
    return home_sessions_dir(project_root) / f"{session_id}.json"


def load_session(
    scope: str,
    session_id: str,
    *,
    project_root: Path,
    run_dir: Optional[Path] = None,
) -> Optional[dict[str, Any]]:
    p = _path_for(scope, session_id, project_root=project_root, run_dir=run_dir)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def save_session(data: dict[str, Any], *, project_root: Path, run_dir: Optional[Path] = None) -> Path:
    scope = str(data.get("scope") or "home")
    sid = str(data.get("id") or new_session_id())
    data["id"] = sid
    data["scope"] = scope
    data["updated_at"] = utc_now_iso()
    msgs = data.get("messages")
    if isinstance(msgs, list) and len(msgs) > MAX_MESSAGES:
        data["messages"] = msgs[-MAX_MESSAGES:]
    p = _path_for(scope, sid, project_root=project_root, run_dir=run_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return p


def create_session(
    scope: str,
    *,
    project_root: Path,
    run_dir: Optional[Path] = None,
    target_id: Optional[str] = None,
    run_id: Optional[str] = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": new_session_id(),
        "scope": scope,
        "created_at": utc_now_iso(),
        "updated_at": utc_now_iso(),
        "messages": [],
        "target_id": target_id,
        "run_id": run_id,
    }
    save_session(data, project_root=project_root, run_dir=run_dir)
    return data


def list_sessions(
    scope: str,
    *,
    project_root: Path,
    run_dir: Optional[Path] = None,
) -> list[dict[str, Any]]:
    if scope == "run":
        if run_dir is None:
            return []
        root = run_sessions_dir(run_dir)
    else:
        root = home_sessions_dir(project_root)
    if not root.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for p in sorted(root.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        msgs = data.get("messages") or []
        preview = ""
        for m in reversed(msgs):
            if isinstance(m, dict) and m.get("role") == "user" and m.get("content"):
                preview = str(m["content"])[:120]
                break
        out.append(
            {
                "id": data.get("id") or p.stem,
                "scope": data.get("scope") or scope,
                "created_at": data.get("created_at"),
                "updated_at": data.get("updated_at"),
                "message_count": len(msgs) if isinstance(msgs, list) else 0,
                "preview": preview,
                "target_id": data.get("target_id"),
                "run_id": data.get("run_id"),
            }
        )
    return out


def delete_session(
    scope: str,
    session_id: str,
    *,
    project_root: Path,
    run_dir: Optional[Path] = None,
) -> bool:
    p = _path_for(scope, session_id, project_root=project_root, run_dir=run_dir)
    if not p.is_file():
        return False
    try:
        p.unlink()
        return True
    except OSError:
        return False
