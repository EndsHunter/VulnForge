"""
Persist full LLM / agent transcripts per task for the dashboard.

Layout:
  <run_dir>/transcripts/task-<id>.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from vulnforge.util import utc_now_iso


def transcripts_dir(run_dir: Path) -> Path:
    d = Path(run_dir) / "transcripts"
    d.mkdir(parents=True, exist_ok=True)
    return d


def transcript_path(run_dir: Path, task_id: int) -> Path:
    return transcripts_dir(run_dir) / f"task-{int(task_id)}.json"


def save_transcript(
    run_dir: Path,
    task_id: int,
    *,
    kind: str,
    model_id: Optional[str],
    messages: list[dict],
    result: Optional[dict] = None,
    meta: Optional[dict] = None,
) -> Path:
    """
    Write a transcript file. Messages should be a serializable chat log
    (system/user/assistant/tool turns), not huge raw HTTP dumps.
    """
    path = transcript_path(run_dir, task_id)
    # Cap tool payloads to keep UI usable
    safe_messages = [_cap_message(m) for m in messages]
    payload = {
        "task_id": int(task_id),
        "kind": kind,
        "model_id": model_id,
        "saved_at": utc_now_iso(),
        "message_count": len(safe_messages),
        "messages": safe_messages,
        "result": result or {},
        "meta": meta or {},
    }
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)
    return path


def load_transcript(run_dir: Path, task_id: int) -> Optional[dict[str, Any]]:
    path = transcript_path(run_dir, task_id)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def list_transcript_ids(run_dir: Path) -> list[int]:
    d = Path(run_dir) / "transcripts"
    if not d.is_dir():
        return []
    ids: list[int] = []
    for p in d.glob("task-*.json"):
        try:
            ids.append(int(p.stem.split("-", 1)[1]))
        except (ValueError, IndexError):
            continue
    return sorted(ids)


def _cap_message(m: dict, max_content: int = 200_000) -> dict:
    out = dict(m)
    c = out.get("content")
    if isinstance(c, str) and len(c) > max_content:
        out["content"] = c[:max_content] + f"\nâ€¦[truncated {len(c)} chars]â€¦"
        out["_truncated"] = True
    return out


def validate_transcript_compliance(messages: list[dict]) -> dict[str, Any]:
    """
    Validate that a transcript contains at least one successful submit_* call.

    Returns a dict with:
        - compliant: bool - whether the transcript has successful submit_* calls
        - submit_calls_found: int - number of submit_* tool calls found
        - successful_submits: int - number of successful submit_* responses
        - issues: list[str] - any compliance issues found

    This is used to pre-validate transcripts before they're considered complete.
    """
    result = {
        "compliant": False,
        "submit_calls_found": 0,
        "successful_submits": 0,
        "issues": [],
    }

    submit_tools = {"submit_candidate", "submit_none", "submit_architecture"}

    for msg in messages:
        if not isinstance(msg, dict):
            continue

        # Check assistant messages for submit_* tool calls
        if msg.get("role") == "assistant":
            tool_calls = msg.get("tool_calls", [])
            for tc in tool_calls:
                func = tc.get("function", {})
                if isinstance(func, dict):
                    name = func.get("name", "")
                    if name in submit_tools:
                        result["submit_calls_found"] += 1

        # Check tool messages for successful submit_* responses
        if msg.get("role") == "tool":
            name = msg.get("name", "")
            if name in submit_tools:
                try:
                    content = json.loads(msg.get("content", "{}"))
                    if isinstance(content, dict) and content.get("ok") is True:
                        result["successful_submits"] += 1
                except (json.JSONDecodeError, TypeError):
                    pass

    # Consider compliant if at least one successful submit was found
    result["compliant"] = result["successful_submits"] > 0

    # Add issues if no submit was attempted
    if result["submit_calls_found"] == 0:
        result["issues"].append("No submit_* tool calls found in transcript")
    elif result["successful_submits"] == 0 and result["submit_calls_found"] > 0:
        result["issues"].append("Submit_* calls found but none were successful")

    return result
