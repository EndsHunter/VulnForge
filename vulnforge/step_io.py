"""
Normalize per-task step I/O for the Harness builder / dashboard.

Builds a structured view from transcripts, task rows, and run artifacts.
Does not re-run models. Target tree is read-only for agents; file ledger
covers run artifacts (evidence, project, drafts) only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from vulnforge.transcript import list_transcript_passes, load_all_transcripts, load_transcript
from vulnforge.usage import load_usage_for_task


SUBMIT_TOOLS = frozenset(
    {"submit_candidate", "submit_none", "submit_architecture", "write_evidence"}
)


def _msg_content(m: dict) -> str:
    c = m.get("content")
    if c is None:
        return ""
    if isinstance(c, str):
        return c
    try:
        return json.dumps(c, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(c)


def _extract_tools_from_messages(messages: list[dict]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for m in messages:
        if not isinstance(m, dict):
            continue
        if m.get("role") == "assistant":
            for tc in m.get("tool_calls") or []:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
                name = str(fn.get("name") or tc.get("name") or "").strip()
                if name and name not in seen:
                    seen.add(name)
                    names.append(name)
        if m.get("role") == "tool":
            name = str(m.get("name") or "").strip()
            if name and name not in seen:
                seen.add(name)
                names.append(name)
    return names


def _detect_submit(messages: list[dict], result: dict) -> Optional[str]:
    for m in reversed(messages or []):
        if not isinstance(m, dict) or m.get("role") != "tool":
            continue
        name = str(m.get("name") or "")
        if name in ("submit_candidate", "submit_none", "submit_architecture"):
            try:
                body = json.loads(m.get("content") or "{}")
            except (json.JSONDecodeError, TypeError):
                body = {}
            if isinstance(body, dict) and body.get("ok") is True:
                return name
    # Fallback from result flags
    if result.get("merged") is True:
        return "architecture_merge"
    return None


def _files_from_transcript(data: dict[str, Any], run_dir: Path) -> dict[str, list[str]]:
    created: list[str] = []
    modified: list[str] = []
    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    for key, bucket in (
        ("files_created", created),
        ("files_written", created),
        ("files_modified", modified),
    ):
        raw = meta.get(key)
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str) and item and item not in bucket:
                    bucket.append(item)
                elif isinstance(item, dict):
                    p = item.get("path") or item.get("relpath") or item.get("file")
                    if p and str(p) not in bucket:
                        bucket.append(str(p))

    # Evidence pack ids → list files under evidence/<id>/
    evidence_ids: list[str] = []
    for k in ("evidence_id", "evidence_ids", "evidence_ids_written"):
        v = meta.get(k)
        if isinstance(v, str) and v:
            evidence_ids.append(v)
        elif isinstance(v, list):
            evidence_ids.extend(str(x) for x in v if x)
    res = data.get("result") if isinstance(data.get("result"), dict) else {}
    for k in ("evidence_id", "evidence_ids"):
        v = res.get(k)
        if isinstance(v, str) and v:
            evidence_ids.append(v)
        elif isinstance(v, list):
            evidence_ids.extend(str(x) for x in v if x)

    # Tool write_evidence results in messages
    for m in data.get("messages") or []:
        if not isinstance(m, dict) or m.get("role") != "tool":
            continue
        if m.get("name") not in ("write_evidence", "write_evidence_file"):
            # still try parse for evidence_id
            pass
        try:
            body = json.loads(m.get("content") or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(body, dict):
            continue
        eid = body.get("evidence_id") or body.get("pack_id")
        if eid:
            evidence_ids.append(str(eid))
        path = body.get("path") or body.get("relpath") or body.get("file")
        if path and str(path) not in created:
            created.append(str(path))

    seen_e = set()
    for eid in evidence_ids:
        if eid in seen_e:
            continue
        seen_e.add(eid)
        pack = Path(run_dir) / "evidence" / eid
        if pack.is_dir():
            for f in sorted(pack.rglob("*")):
                if f.is_file():
                    try:
                        rel = str(f.relative_to(run_dir)).replace("\\", "/")
                    except ValueError:
                        rel = str(f)
                    if rel not in created:
                        created.append(rel)
        else:
            label = f"evidence/{eid}/"
            if label not in created:
                created.append(label)

    return {"created": created, "modified": modified}


def _input_sources(kind: str, payload: dict, meta: dict) -> list[dict[str, Any]]:
    sources: list[dict[str, Any]] = []
    # Hunt class / skill body
    cls = payload.get("class") or payload.get("attack_class") or payload.get("skill_id")
    if cls and (str(kind) == "hunt" or str(kind).startswith("hunt")):
        sources.append(
            {
                "type": "md_body",
                "ref": f"config/hunt_profiles/bodies/{cls}.md",
                "label": str(cls),
            }
        )
    agent_id = (
        payload.get("recon_agent_id")
        or payload.get("agent_id")
        or meta.get("pass_key")
        or meta.get("recon_agent_id")
    )
    if agent_id and ("recon" in str(kind) or str(kind).startswith("recon")):
        sources.append(
            {
                "type": "md_body",
                "ref": f"config/recon_agents/bodies/{agent_id}.md",
                "label": str(agent_id),
            }
        )
    notes = payload.get("operator_notes") or payload.get("notes") or payload.get("brief")
    if notes:
        sources.append(
            {
                "type": "manual",
                "field": "operator_notes" if payload.get("operator_notes") else "notes",
                "preview": str(notes)[:500],
            }
        )
    if payload.get("operator_brief"):
        sources.append(
            {
                "type": "manual",
                "field": "operator_brief",
                "preview": str(payload.get("operator_brief"))[:500],
            }
        )
    if payload.get("path_hints") or payload.get("paths"):
        sources.append(
            {
                "type": "path_hints",
                "paths": payload.get("path_hints") or payload.get("paths"),
            }
        )
    if payload.get("parent_task_id") is not None:
        sources.append(
            {
                "type": "parent_task",
                "task_id": payload.get("parent_task_id"),
            }
        )
    return sources


def _pass_view(data: dict[str, Any], run_dir: Path) -> dict[str, Any]:
    messages = list(data.get("messages") or [])
    result = data.get("result") if isinstance(data.get("result"), dict) else {}
    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    payload = meta.get("payload") if isinstance(meta.get("payload"), dict) else {}
    if not payload and isinstance(result.get("payload"), dict):
        payload = result["payload"]

    system_parts = [_msg_content(m) for m in messages if m.get("role") == "system"]
    user_parts = [_msg_content(m) for m in messages if m.get("role") == "user"]
    tools = meta.get("tools") if isinstance(meta.get("tools"), list) else None
    if not tools:
        tools = _extract_tools_from_messages(messages)

    files = _files_from_transcript(data, run_dir)
    usage = {
        k: result.get(k)
        for k in (
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "reasoning_tokens",
            "llm_calls",
            "usage_source",
        )
        if k in result
    }

    return {
        "pass_key": data.get("pass_key") or meta.get("pass_key"),
        "kind": data.get("kind"),
        "model_id": data.get("model_id"),
        "saved_at": data.get("saved_at"),
        "message_count": data.get("message_count") or len(messages),
        "model": {
            "id": data.get("model_id"),
            "temperature": meta.get("temperature"),
            "max_tool_rounds": meta.get("max_tool_rounds"),
        },
        "input": {
            "system": "\n\n".join(system_parts) if system_parts else "",
            "user": "\n\n".join(user_parts) if user_parts else "",
            "tools": tools,
            "payload": payload,
            "sources": _input_sources(str(data.get("kind") or ""), payload, meta),
        },
        "turns": messages,
        "output": {
            "result": result,
            "submit": _detect_submit(messages, result),
            "content": result.get("content"),
            "ok": result.get("ok"),
            "classification": result.get("classification"),
            "error": result.get("error"),
        },
        "files": files,
        "usage": usage,
        "meta": meta,
    }


def build_task_io(
    run_dir: Path,
    task_id: int,
    *,
    task: Optional[Any] = None,
    pass_key: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Build full step I/O document for a task.

    If pass_key is set, returns that pass only under top-level fields
    (plus passes index). Otherwise merges multi-pass metadata and uses
    primary/latest pass for top-level input/turns/output.
    """
    run_dir = Path(run_dir)
    pass_list = list_transcript_passes(run_dir, task_id)
    if not pass_list:
        # Still allow task-only view without transcript
        if task is None:
            return None
        return _task_only_io(task_id, task)

    if pass_key:
        data = load_transcript(run_dir, task_id, pass_key=pass_key)
        if not data:
            return None
        view = _pass_view(data, run_dir)
        return _envelope(task_id, task, pass_list, [view], primary=view)

    all_data = load_all_transcripts(run_dir, task_id)
    if not all_data:
        data = load_transcript(run_dir, task_id)
        if not data:
            if task is None:
                return None
            return _task_only_io(task_id, task)
        all_data = [data]

    views = [_pass_view(d, run_dir) for d in all_data]
    primary = views[-1]
    # Merge file ledgers across passes
    all_created: list[str] = []
    all_modified: list[str] = []
    for v in views:
        for p in (v.get("files") or {}).get("created") or []:
            if p not in all_created:
                all_created.append(p)
        for p in (v.get("files") or {}).get("modified") or []:
            if p not in all_modified:
                all_modified.append(p)
    primary = dict(primary)
    primary["files"] = {"created": all_created, "modified": all_modified}

    # Aggregate usage from jsonl for task
    try:
        usage_events = load_usage_for_task(run_dir, task_id)
    except Exception:
        usage_events = []

    env = _envelope(task_id, task, pass_list, views, primary=primary)
    env["usage_events"] = usage_events
    if usage_events and not env.get("usage"):
        env["usage"] = _sum_usage_events(usage_events)
    return env


def _task_only_io(task_id: int, task: Any) -> dict[str, Any]:
    payload = {}
    result = {}
    kind = None
    state = None
    if isinstance(task, dict):
        payload = task.get("payload") or {}
        result = task.get("result") or task.get("result_json") or {}
        kind = task.get("kind")
        state = task.get("state")
    else:
        payload = getattr(task, "payload", None) or {}
        result = getattr(task, "result", None) or {}
        kind = getattr(task, "kind", None)
        state = getattr(task, "state", None)
    return {
        "task_id": int(task_id),
        "kind": kind,
        "state": state,
        "model": {"id": None},
        "input": {
            "system": "",
            "user": "",
            "tools": [],
            "payload": payload if isinstance(payload, dict) else {},
            "sources": _input_sources(str(kind or ""), payload if isinstance(payload, dict) else {}, {}),
        },
        "turns": [],
        "output": {"result": result if isinstance(result, dict) else {}, "submit": None},
        "files": {"created": [], "modified": []},
        "usage": {},
        "passes": [],
        "pass_views": [],
        "has_transcript": False,
    }


def _envelope(
    task_id: int,
    task: Optional[Any],
    pass_list: list[dict],
    views: list[dict],
    *,
    primary: dict,
) -> dict[str, Any]:
    state = None
    kind = primary.get("kind")
    payload = (primary.get("input") or {}).get("payload") or {}
    if task is not None:
        if isinstance(task, dict):
            state = task.get("state")
            kind = task.get("kind") or kind
            if task.get("payload"):
                payload = task["payload"]
        else:
            state = getattr(task, "state", None)
            kind = getattr(task, "kind", None) or kind
            tp = getattr(task, "payload", None)
            if tp:
                payload = tp
    return {
        "task_id": int(task_id),
        "kind": kind,
        "state": state,
        "model": primary.get("model") or {"id": primary.get("model_id")},
        "input": primary.get("input")
        or {
            "system": "",
            "user": "",
            "tools": [],
            "payload": payload,
            "sources": [],
        },
        "turns": primary.get("turns") or [],
        "output": primary.get("output") or {},
        "files": primary.get("files") or {"created": [], "modified": []},
        "usage": primary.get("usage") or {},
        "passes": pass_list,
        "pass_views": views,
        "has_transcript": True,
        "saved_at": primary.get("saved_at"),
        "message_count": primary.get("message_count"),
    }


def _sum_usage_events(events: list[dict]) -> dict[str, Any]:
    out = {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "reasoning_tokens": 0,
        "llm_calls": 0,
    }
    for e in events:
        for k in out:
            try:
                out[k] += int(e.get(k) or 0)
            except (TypeError, ValueError):
                pass
    return out


def build_graph_snapshot(
    tasks: list[Any],
    *,
    events: Optional[list[dict]] = None,
) -> dict[str, Any]:
    """
    Derive a simple agent graph from task list + optional events.

    Nodes are task instances; edges from parent_task_id and known result links.
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    by_id: dict[int, dict] = {}

    for t in tasks:
        if isinstance(t, dict):
            tid = int(t.get("id") or 0)
            kind = t.get("kind")
            state = t.get("state")
            payload = t.get("payload") if isinstance(t.get("payload"), dict) else {}
            result = t.get("result") if isinstance(t.get("result"), dict) else {}
            if not result and isinstance(t.get("result_json"), dict):
                result = t["result_json"]
        else:
            tid = int(getattr(t, "id", 0) or 0)
            kind = getattr(t, "kind", None)
            state = getattr(t, "state", None)
            payload = getattr(t, "payload", None) or {}
            result = getattr(t, "result", None) or {}
            if not isinstance(payload, dict):
                payload = {}
            if not isinstance(result, dict):
                result = {}
        if not tid:
            continue
        label_bits = [str(kind or "task"), f"#{tid}"]
        if kind == "hunt":
            cls = payload.get("class") or payload.get("attack_class")
            area = payload.get("area")
            if cls:
                label_bits.append(str(cls))
            if area:
                label_bits.append(str(area))
        if kind == "recon" or (isinstance(kind, str) and kind.startswith("recon")):
            aid = payload.get("recon_agent_id") or payload.get("agent_id")
            if aid:
                label_bits.append(str(aid))
        node = {
            "id": f"task-{tid}",
            "task_id": tid,
            "kind": kind,
            "state": state,
            "label": " · ".join(label_bits),
            "payload_summary": {
                k: payload.get(k)
                for k in (
                    "class",
                    "area",
                    "recon_agent_id",
                    "agent_id",
                    "finding_id",
                    "parent_task_id",
                )
                if k in payload
            },
            "has_parent": payload.get("parent_task_id") is not None,
        }
        nodes.append(node)
        by_id[tid] = node

        parent = payload.get("parent_task_id")
        if parent is not None:
            try:
                pid = int(parent)
            except (TypeError, ValueError):
                pid = None
            if pid is not None:
                edges.append(
                    {
                        "id": f"e-{pid}-{tid}-parent",
                        "source": f"task-{pid}",
                        "target": f"task-{tid}",
                        "type": "parent",
                    }
                )

        # Child links recorded on result
        for key, etype in (
            ("child_task_id", "requeue"),
            ("finding_id", "finding"),
        ):
            if key == "finding_id":
                continue  # finding is not a task node
            cid = result.get(key)
            if cid is not None:
                try:
                    cid_i = int(cid)
                except (TypeError, ValueError):
                    continue
                edges.append(
                    {
                        "id": f"e-{tid}-{cid_i}-{etype}",
                        "source": f"task-{tid}",
                        "target": f"task-{cid_i}",
                        "type": etype,
                    }
                )
        split = result.get("split")
        if isinstance(split, dict):
            for cid in split.get("child_task_ids") or split.get("children") or []:
                try:
                    cid_i = int(cid)
                except (TypeError, ValueError):
                    continue
                edges.append(
                    {
                        "id": f"e-{tid}-{cid_i}-split",
                        "source": f"task-{tid}",
                        "target": f"task-{cid_i}",
                        "type": "split",
                    }
                )
        for cid in result.get("spawned_hunts") or []:
            # spawned_hunts may be payloads not ids — skip non-int
            try:
                cid_i = int(cid)
            except (TypeError, ValueError):
                continue
            edges.append(
                {
                    "id": f"e-{tid}-{cid_i}-spawn",
                    "source": f"task-{tid}",
                    "target": f"task-{cid_i}",
                    "type": "spawn",
                }
            )

    # Kind-order edges when no parent (pipeline visualization aid)
    kind_order = [
        "recon",
        "hunt",
        "validate_mech",
        "validate_llm",
        "develop_poc",
        "render",
        "tool_gaps",
        "generate_skill",
        "generate_run_skills",
    ]
    # Group by kind for type-level summary
    by_kind: dict[str, list[int]] = {}
    for n in nodes:
        k = str(n.get("kind") or "unknown")
        by_kind.setdefault(k, []).append(int(n["task_id"]))

    type_nodes = [
        {
            "id": f"kind-{k}",
            "kind": k,
            "count": len(ids),
            "states": _count_states(nodes, k),
        }
        for k, ids in by_kind.items()
    ]
    type_edges = []
    present = [k for k in kind_order if k in by_kind]
    for i in range(len(present) - 1):
        type_edges.append(
            {
                "id": f"te-{present[i]}-{present[i+1]}",
                "source": f"kind-{present[i]}",
                "target": f"kind-{present[i+1]}",
                "type": "pipeline",
            }
        )

    # Event-derived edges (shallow_requeue etc.)
    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        et = ev.get("event")
        if et in ("shallow_requeue", "hunt_split", "enqueue_hunt", "task_enqueued"):
            src = ev.get("task_id") or ev.get("parent_task_id")
            dst = ev.get("child_task_id") or ev.get("new_task_id")
            if src is not None and dst is not None:
                try:
                    s, d = int(src), int(dst)
                except (TypeError, ValueError):
                    continue
                edges.append(
                    {
                        "id": f"e-{s}-{d}-{et}",
                        "source": f"task-{s}",
                        "target": f"task-{d}",
                        "type": str(et),
                    }
                )

    # Dedupe edges
    seen_e: set[str] = set()
    deduped = []
    for e in edges:
        eid = e.get("id") or f"{e.get('source')}->{e.get('target')}:{e.get('type')}"
        if eid in seen_e:
            continue
        seen_e.add(eid)
        deduped.append(e)

    return {
        "nodes": nodes,
        "edges": deduped,
        "type_nodes": type_nodes,
        "type_edges": type_edges,
        "task_count": len(nodes),
    }


def _count_states(nodes: list[dict], kind: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for n in nodes:
        if str(n.get("kind") or "") != kind:
            continue
        st = str(n.get("state") or "unknown")
        counts[st] = counts.get(st, 0) + 1
    return counts
