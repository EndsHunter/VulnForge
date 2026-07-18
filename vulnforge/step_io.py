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


def _as_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _task_fields(t: Any) -> tuple[int, Any, Any, dict, dict]:
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
    return tid, kind, state, payload, result


def _add_edge(
    edges: list[dict[str, Any]],
    *,
    source: int,
    target: int,
    etype: str,
    known_ids: set[int],
) -> None:
    if source == target:
        return
    if source not in known_ids or target not in known_ids:
        return
    edges.append(
        {
            "id": f"e-{source}-{target}-{etype}",
            "source": f"task-{source}",
            "target": f"task-{target}",
            "type": etype,
        }
    )


def build_graph_snapshot(
    tasks: list[Any],
    *,
    events: Optional[list[dict]] = None,
) -> dict[str, Any]:
    """
    Derive an agent graph from task list + optional events.

    Edges from:
      - payload.parent_task_id
      - result child/split/spawn ids
      - finding pipeline (hunt → validate_mech → validate_llm → develop_poc)
      - recon → orphan hunts (infer by hunt_enqueued count / id order)
      - events (requeue / enqueue)
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    by_id: dict[int, dict] = {}
    raw_by_id: dict[int, tuple[Any, dict, dict]] = {}

    # Pass 1: nodes only (so all ids exist before edges)
    for t in tasks:
        tid, kind, state, payload, result = _task_fields(t)
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
        fid = payload.get("finding_id")
        if fid is None:
            fid = result.get("finding_id")
        if fid is not None:
            label_bits.append(f"f#{fid}")
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
            "finding_id": _as_int(fid),
            "has_parent": payload.get("parent_task_id") is not None,
        }
        nodes.append(node)
        by_id[tid] = node
        raw_by_id[tid] = (kind, payload, result)

    known_ids = set(by_id.keys())

    # Pass 2: explicit parent / result edges
    for tid, (kind, payload, result) in raw_by_id.items():
        parent = _as_int(payload.get("parent_task_id"))
        if parent is not None:
            _add_edge(
                edges, source=parent, target=tid, etype="parent", known_ids=known_ids
            )

        for key, etype in (
            ("child_task_id", "requeue"),
            ("generate_run_skills_task_id", "skills"),
        ):
            cid = _as_int(result.get(key))
            if cid is not None:
                _add_edge(
                    edges, source=tid, target=cid, etype=etype, known_ids=known_ids
                )

        for list_key, etype in (
            ("fanout_task_ids", "fanout"),
            ("child_task_ids", "children"),
            ("spawned_task_ids", "spawn"),
            ("hunt_task_ids", "enqueue_hunt"),
            ("enqueued_task_ids", "enqueue"),
        ):
            raw_list = result.get(list_key)
            if not isinstance(raw_list, list):
                continue
            for cid in raw_list:
                cid_i = _as_int(cid)
                if cid_i is not None:
                    _add_edge(
                        edges,
                        source=tid,
                        target=cid_i,
                        etype=etype,
                        known_ids=known_ids,
                    )

        split = result.get("split")
        if isinstance(split, dict):
            for cid in split.get("child_task_ids") or split.get("children") or []:
                cid_i = _as_int(cid)
                if cid_i is not None:
                    _add_edge(
                        edges,
                        source=tid,
                        target=cid_i,
                        etype="split",
                        known_ids=known_ids,
                    )
        for cid in result.get("spawned_hunts") or []:
            cid_i = _as_int(cid)
            if cid_i is not None:
                _add_edge(
                    edges, source=tid, target=cid_i, etype="spawn", known_ids=known_ids
                )

    # --- Finding pipeline: hunt → validate_mech → validate_llm → develop_poc ---
    FINDING_KIND_RANK = {
        "hunt": 0,
        "validate_mech": 1,
        "validate_llm": 2,
        "develop_poc": 3,
    }
    by_finding: dict[int, list[tuple[int, int, str]]] = {}
    for tid, (kind, payload, result) in raw_by_id.items():
        k = str(kind or "")
        if k not in FINDING_KIND_RANK:
            continue
        fid = _as_int(payload.get("finding_id"))
        if fid is None:
            fid = _as_int(result.get("finding_id"))
        if fid is None:
            continue
        by_finding.setdefault(fid, []).append((FINDING_KIND_RANK[k], tid, k))

    for fid, members in by_finding.items():
        members.sort(key=lambda x: (x[0], x[1]))
        # Chain consecutive pipeline stages (same finding)
        for i in range(len(members) - 1):
            _, a_id, a_kind = members[i]
            _, b_id, b_kind = members[i + 1]
            # Only link forward in pipeline (not hunt→hunt)
            if FINDING_KIND_RANK.get(a_kind, 99) < FINDING_KIND_RANK.get(b_kind, -1):
                _add_edge(
                    edges,
                    source=a_id,
                    target=b_id,
                    etype="finding",
                    known_ids=known_ids,
                )
        # Also link first hunt that produced finding to first validate_mech if not adjacent
        hunts = [m for m in members if m[2] == "hunt"]
        mechs = [m for m in members if m[2] == "validate_mech"]
        if hunts and mechs:
            _add_edge(
                edges,
                source=hunts[0][1],
                target=mechs[0][1],
                etype="finding",
                known_ids=known_ids,
            )

    # --- Recon → orphan hunts (legacy runs without parent_task_id) ---
    recon_ids = sorted(
        tid
        for tid, (kind, _, _) in raw_by_id.items()
        if str(kind or "") == "recon" or str(kind or "").startswith("recon")
    )
    orphan_hunts = sorted(
        tid
        for tid, (kind, payload, _) in raw_by_id.items()
        if str(kind or "") == "hunt" and payload.get("parent_task_id") is None
    )
    # Assign orphan hunts to the most recent recon with id < hunt id
    # Prefer recon results that report hunt_enqueued > 0
    recon_capacity: dict[int, int] = {}
    for rid in recon_ids:
        _, _, result = raw_by_id[rid]
        n = result.get("hunt_enqueued")
        n_i = _as_int(n)
        if n_i is not None and n_i > 0:
            recon_capacity[rid] = n_i
        else:
            # still allow linking a few if recon succeeded
            if result.get("status") == "succeeded" or result.get("enqueue_hunts"):
                recon_capacity[rid] = recon_capacity.get(rid, 0) or 50

    assigned: set[int] = set()
    for rid in sorted(recon_capacity.keys()):
        cap = recon_capacity[rid]
        linked = 0
        for hid in orphan_hunts:
            if hid in assigned or hid <= rid:
                continue
            # stop at next recon id
            next_recons = [x for x in recon_ids if x > rid]
            if next_recons and hid >= next_recons[0]:
                break
            _add_edge(
                edges,
                source=rid,
                target=hid,
                etype="enqueue_hunt",
                known_ids=known_ids,
            )
            assigned.add(hid)
            linked += 1
            if linked >= cap:
                break

    # Remaining orphan hunts → nearest prior recon (operator / later enqueue)
    for hid in orphan_hunts:
        if hid in assigned:
            continue
        preds = [r for r in recon_ids if r < hid]
        if not preds:
            continue
        _add_edge(
            edges,
            source=preds[-1],
            target=hid,
            etype="enqueue_hunt",
            known_ids=known_ids,
        )
        assigned.add(hid)

    # Skills / render without parent: link generate_run_skills already handled;
    # link first render after last recon if no edges
    for tid, (kind, payload, result) in raw_by_id.items():
        if str(kind or "") != "render":
            continue
        if payload.get("parent_task_id") is not None:
            continue
        # Prefer latest succeeded recon before this render
        preds = [r for r in recon_ids if r < tid]
        if preds:
            _add_edge(
                edges,
                source=preds[-1],
                target=tid,
                etype="pipeline",
                known_ids=known_ids,
            )

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
        if et in (
            "shallow_requeue",
            "hunt_split",
            "enqueue_hunt",
            "task_enqueued",
            "validate_llm_done",
            "candidate_submitted",
        ):
            src = ev.get("task_id") or ev.get("parent_task_id")
            dst = (
                ev.get("child_task_id")
                or ev.get("new_task_id")
                or ev.get("spawned_task_id")
            )
            if src is not None and dst is not None:
                s, d = _as_int(src), _as_int(dst)
                if s is not None and d is not None:
                    _add_edge(
                        edges,
                        source=s,
                        target=d,
                        etype=str(et),
                        known_ids=known_ids,
                    )

    # Dedupe edges (prefer keeping first; also collapse source+target dupes)
    seen_e: set[str] = set()
    seen_pair: set[tuple[str, str]] = set()
    deduped = []
    for e in edges:
        pair = (str(e.get("source")), str(e.get("target")))
        if pair[0] == pair[1]:
            continue
        if pair in seen_pair:
            continue
        eid = e.get("id") or f"{pair[0]}->{pair[1]}:{e.get('type')}"
        if eid in seen_e:
            continue
        seen_e.add(str(eid))
        seen_pair.add(pair)
        deduped.append(e)

    return {
        "nodes": nodes,
        "edges": deduped,
        "type_nodes": type_nodes,
        "type_edges": type_edges,
        "task_count": len(nodes),
        "edge_count": len(deduped),
    }


def _count_states(nodes: list[dict], kind: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for n in nodes:
        if str(n.get("kind") or "") != kind:
            continue
        st = str(n.get("state") or "unknown")
        counts[st] = counts.get(st, 0) + 1
    return counts
