"""Shared operator-chat tool schemas and run-bound implementations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Optional

from vulnforge.db import Database
from vulnforge.operator_chat.summarize import (
    MAX_LIST,
    cap_list,
    clip_summary,
    clip_text,
)
from vulnforge.stages.recon import _normalize_class
from vulnforge.ui import runner as runctl
from vulnforge.ui.store import RunRef, discover_runs, resolve_run, run_card
from vulnforge.util import append_event, normalize_relpath

MUTATE_TOOLS = frozenset(
    {
        "init_run",
        "start_run",
        "pause_run",
        "resume_run",
        "hard_stop_run",
        "enqueue_hunt",
        "requeue_hunt",
        "requeue_hunts_bulk",
        "rerun_recon",
        "review_finding",
        "enqueue_develop_poc",
    }
)


def openai_tool(name: str, description: str, properties: dict, required: Optional[list] = None) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required or [],
            },
        },
    }


def _open_db(run_dir: Path) -> Database:
    return Database.open(Path(run_dir) / "harness.db")


def resolve_run_dir(
    runs_root: Path,
    args: dict[str, Any],
    *,
    bound: Optional[RunRef] = None,
) -> tuple[Optional[RunRef], Optional[str]]:
    if bound is not None:
        return bound, None
    tid = str(args.get("target_id") or "").strip()
    rid = str(args.get("run_id") or "").strip()
    if not tid or not rid:
        return None, "target_id and run_id required"
    try:
        return resolve_run(runs_root, tid, rid), None
    except FileNotFoundError:
        return None, f"run not found: {tid}/{rid}"
    except Exception as e:
        return None, str(e)


def list_hunt_profiles_impl(_args: dict) -> dict[str, Any]:
    from vulnforge.hunt_profiles import catalog_for_ui, ensure_collection

    ensure_collection()
    cat = catalog_for_ui()
    profiles = []
    for p in cat.get("profiles") or []:
        if not isinstance(p, dict):
            continue
        profiles.append(
            {
                "id": p.get("id"),
                "title": p.get("title") or p.get("id"),
                "active": bool(p.get("active", True)),
                "source": p.get("source"),
            }
        )
    return {"ok": True, "profiles": profiles, "count": len(profiles)}


def list_hunts_impl(run: RunRef, args: dict) -> dict[str, Any]:
    state = str(args.get("state") or "").strip().lower() or None
    cls = str(args.get("class") or args.get("attack_class") or "").strip()
    area = str(args.get("area") or "").strip()
    limit = min(MAX_LIST, max(1, int(args.get("limit") or 40)))
    db = _open_db(run.path)
    try:
        rows = []
        for t in db.list_tasks(limit=2000):
            if t.kind != "hunt":
                continue
            if state and str(t.state).lower() != state:
                continue
            p = t.payload or {}
            if cls and _normalize_class(str(p.get("class") or "")) != _normalize_class(cls):
                continue
            if area and str(p.get("area") or "") != area:
                continue
            res = t.result or {}
            rows.append(
                {
                    "task_id": t.id,
                    "state": t.state,
                    "area": p.get("area"),
                    "class": p.get("class"),
                    "path_hints": (p.get("path_hints") or [])[:8],
                    "operator_notes": clip_summary(p.get("operator_notes") or "", 200),
                    "result_summary": clip_summary(
                        res.get("summary")
                        or res.get("reason")
                        or res.get("outcome")
                        or json.dumps(res, default=str)[:300],
                        240,
                    ),
                    "attempt": t.attempt,
                }
            )
            if len(rows) >= limit:
                break
        return {
            "ok": True,
            "target_id": run.target_id,
            "run_id": run.run_id,
            "hunts": rows,
            "count": len(rows),
        }
    finally:
        db.close()


def get_hunt_impl(run: RunRef, args: dict) -> dict[str, Any]:
    try:
        tid = int(args.get("task_id"))
    except (TypeError, ValueError):
        return {"ok": False, "error": "task_id required (int)"}
    db = _open_db(run.path)
    try:
        t = db.get_task(tid)
        if not t:
            return {"ok": False, "error": f"task {tid} not found"}
        if t.kind != "hunt" and str(args.get("allow_any_kind") or "").lower() not in (
            "1",
            "true",
            "yes",
        ):
            # still return brief for other kinds when allow_any
            pass
        transcript_brief = _transcript_brief(run.path, tid)
        return {
            "ok": True,
            "target_id": run.target_id,
            "run_id": run.run_id,
            "task_id": t.id,
            "kind": t.kind,
            "state": t.state,
            "payload": t.payload,
            "result": t.result,
            "attempt": t.attempt,
            "transcript_brief": transcript_brief,
            "url": f"/runs/{run.target_id}/{run.run_id}#audit/tasks",
        }
    finally:
        db.close()


def _transcript_brief(run_dir: Path, task_id: int, max_chars: int = 2500) -> str:
    p = Path(run_dir) / "transcripts" / f"{task_id}.json"
    if not p.is_file():
        # try alternate naming
        for cand in (Path(run_dir) / "transcripts").glob(f"*{task_id}*") if (Path(run_dir) / "transcripts").is_dir() else []:
            p = cand
            break
        else:
            return ""
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return clip_text(p.read_text(encoding="utf-8", errors="replace")[:max_chars], max_chars)
    if isinstance(data, dict):
        msgs = data.get("messages") or data.get("transcript") or []
    elif isinstance(data, list):
        msgs = data
    else:
        return clip_text(str(data), max_chars)
    parts: list[str] = []
    for m in msgs[-12:]:
        if not isinstance(m, dict):
            continue
        role = m.get("role") or "?"
        content = m.get("content")
        if isinstance(content, str) and content.strip():
            parts.append(f"{role}: {clip_summary(content, 280)}")
        elif m.get("tool_calls"):
            names = []
            for tc in m.get("tool_calls") or []:
                if isinstance(tc, dict):
                    names.append(
                        str(
                            (tc.get("function") or {}).get("name")
                            if isinstance(tc.get("function"), dict)
                            else tc.get("name")
                            or "?"
                        )
                    )
            parts.append(f"{role}: tool_calls={names}")
    return clip_text("\n".join(parts), max_chars)


def query_hunts_impl(run: RunRef, args: dict) -> dict[str, Any]:
    """Filter hunts by residual-ish result signals or free text."""
    text = str(args.get("q") or args.get("text") or "").strip().lower()
    residual = bool(args.get("residual_only"))
    base = list_hunts_impl(run, {**args, "limit": args.get("limit") or 60})
    if not base.get("ok"):
        return base
    rows = []
    for h in base.get("hunts") or []:
        blob = json.dumps(h, default=str).lower()
        if text and text not in blob:
            continue
        if residual:
            st = str(h.get("state") or "")
            rs = str(h.get("result_summary") or "").lower()
            if st not in ("succeeded", "failed_task", "deadletter", "blocked") and "abort" not in rs and "shallow" not in rs and "none" not in rs:
                # keep queued/leased always if residual? skip unless done-ish residual
                if st in ("queued", "leased"):
                    rows.append(h)
                    continue
            if any(x in rs for x in ("abort", "shallow", "submit_none", "none")) or st in (
                "failed_task",
                "deadletter",
            ):
                rows.append(h)
            continue
        rows.append(h)
    return {
        "ok": True,
        "target_id": run.target_id,
        "run_id": run.run_id,
        "hunts": cap_list(rows, int(args.get("limit") or 40)),
        "count": len(rows),
    }


def enqueue_hunt_impl(run: RunRef, args: dict) -> dict[str, Any]:
    from vulnforge.control import ops as dashops

    cls = str(args.get("class") or args.get("attack_class") or "wildcard").strip()
    area = str(args.get("area") or "").strip() or None
    notes = str(args.get("notes") or args.get("operator_notes") or args.get("note") or "")
    paths = args.get("paths") or args.get("path_hints") or []
    if isinstance(paths, str):
        paths = [paths]
    path_list = [normalize_relpath(str(p)) for p in paths if p]
    force_depth = args.get("force_depth")
    if force_depth is None:
        force_depth = True

    if path_list:
        # primary path via selection helper
        r = dashops.hunt_from_selection(
            run.path,
            path=path_list[0],
            attack_class=cls,
            area=area,
            operator_notes=notes,
            note=str(args.get("note") or ""),
        )
        if r.get("ok") and len(path_list) > 1:
            # enrich: re-open and not easy; return first + note extra paths ignored
            r["extra_paths_noted"] = path_list[1:]
        return {**r, "target_id": run.target_id, "run_id": run.run_id}

    r = dashops.requeue_hunt(
        run.path,
        area=area or "app",
        attack_class=cls,
        path_hints=[],
        force_depth=bool(force_depth),
        reason="operator_chat_enqueue",
        operator_notes=notes,
    )
    try:
        append_event(
            run.path,
            {
                "source": "operator_chat",
                "event": "enqueue_hunt",
                "task_id": r.get("task_id"),
                "class": cls,
                "area": area,
            },
        )
    except OSError:
        pass
    return {**r, "target_id": run.target_id, "run_id": run.run_id}


def requeue_hunt_impl(run: RunRef, args: dict) -> dict[str, Any]:
    from vulnforge.control import ops as dashops

    area = str(args.get("area") or "").strip()
    cls = str(args.get("class") or args.get("attack_class") or "").strip()
    if not area or not cls:
        return {"ok": False, "error": "area and class required"}
    hints = args.get("path_hints") or args.get("paths") or []
    if isinstance(hints, str):
        hints = [hints]
    r = dashops.requeue_hunt(
        run.path,
        area=area,
        attack_class=cls,
        path_hints=[str(p) for p in hints if p],
        force_depth=bool(args.get("force_depth", True)),
        reason=str(args.get("reason") or "operator_chat_requeue"),
        operator_notes=str(args.get("notes") or args.get("operator_notes") or ""),
    )
    return {**r, "target_id": run.target_id, "run_id": run.run_id}


def requeue_hunts_bulk_impl(run: RunRef, args: dict) -> dict[str, Any]:
    from vulnforge.control import ops as dashops

    cells = args.get("cells") or []
    if not isinstance(cells, list):
        return {"ok": False, "error": "cells must be a list"}
    r = dashops.requeue_hunt_bulk(
        run.path,
        cells=cells,
        force_depth=bool(args.get("force_depth", True)),
        reason=str(args.get("reason") or "operator_chat_bulk"),
        operator_notes=str(args.get("notes") or ""),
    )
    return {**r, "target_id": run.target_id, "run_id": run.run_id}


def list_findings_impl(run: RunRef, args: dict) -> dict[str, Any]:
    state = str(args.get("state") or "").strip() or None
    cls = str(args.get("class") or args.get("attack_class") or "").strip()
    q = str(args.get("q") or args.get("text") or "").strip().lower()
    limit = min(MAX_LIST, max(1, int(args.get("limit") or 40)))
    db = _open_db(run.path)
    try:
        states = [state] if state else None
        rows = []
        for f in db.list_findings(states=states):
            body = f.body or {}
            wc = str(body.get("weakness_class") or body.get("class") or "")
            if cls and _normalize_class(wc) != _normalize_class(cls):
                continue
            title = str(body.get("title") or "")
            summary = str(body.get("summary") or "")
            if q and q not in (title + " " + summary + " " + f.stable_key).lower():
                continue
            rows.append(
                {
                    "finding_id": f.id,
                    "state": f.state,
                    "title": clip_summary(title, 160),
                    "summary": clip_summary(summary, 280),
                    "class": wc,
                    "stable_key": f.stable_key,
                    "evidence_id": f.evidence_id or body.get("evidence_id"),
                    "severity": body.get("severity_claim"),
                    "url": f"/runs/{run.target_id}/{run.run_id}#report",
                }
            )
            if len(rows) >= limit:
                break
        return {
            "ok": True,
            "target_id": run.target_id,
            "run_id": run.run_id,
            "findings": rows,
            "count": len(rows),
        }
    finally:
        db.close()


def get_finding_impl(run: RunRef, args: dict) -> dict[str, Any]:
    try:
        fid = int(args.get("finding_id"))
    except (TypeError, ValueError):
        return {"ok": False, "error": "finding_id required"}
    db = _open_db(run.path)
    try:
        f = db.get_finding(fid)
        if not f:
            return {"ok": False, "error": f"finding {fid} not found"}
        body = dict(f.body or {})
        # trim large fields
        for k in list(body.keys()):
            if isinstance(body[k], str) and len(body[k]) > 2000:
                body[k] = clip_text(body[k], 2000)
        return {
            "ok": True,
            "target_id": run.target_id,
            "run_id": run.run_id,
            "finding_id": f.id,
            "state": f.state,
            "stable_key": f.stable_key,
            "evidence_id": f.evidence_id,
            "body": body,
            "url": f"/runs/{run.target_id}/{run.run_id}#report",
        }
    finally:
        db.close()


def read_evidence_impl(run: RunRef, args: dict) -> dict[str, Any]:
    pack = str(args.get("pack_id") or args.get("evidence_id") or "").strip()
    rel = str(args.get("relpath") or args.get("path") or "evidence.md").strip()
    if not pack:
        return {"ok": False, "error": "pack_id / evidence_id required"}
    base = (run.path / "evidence" / pack).resolve()
    try:
        base.relative_to((run.path / "evidence").resolve())
    except ValueError:
        return {"ok": False, "error": "invalid pack path"}
    if not base.is_dir():
        # pack might be file-less naming
        pass
    # soft path join
    rel_n = rel.replace("\\", "/").lstrip("/")
    if ".." in rel_n.split("/"):
        return {"ok": False, "error": "invalid relpath"}
    fp = (base / rel_n).resolve() if base.is_dir() else (run.path / "evidence" / pack).resolve()
    if base.is_dir():
        try:
            fp.relative_to(base)
        except ValueError:
            return {"ok": False, "error": "path escape"}
    if not fp.is_file():
        # try any file in pack
        if base.is_dir():
            files = sorted(base.rglob("*"))
            files = [f for f in files if f.is_file()][:20]
            if files and not rel_n:
                fp = files[0]
            elif files:
                return {
                    "ok": False,
                    "error": "file not found",
                    "available": [str(f.relative_to(base)).replace("\\", "/") for f in files],
                }
            else:
                return {"ok": False, "error": "empty evidence pack"}
        else:
            return {"ok": False, "error": "evidence not found"}
    try:
        text = fp.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return {"ok": False, "error": str(e)}
    return {
        "ok": True,
        "target_id": run.target_id,
        "run_id": run.run_id,
        "pack_id": pack,
        "path": str(fp.relative_to(run.path)).replace("\\", "/") if fp.is_relative_to(run.path) else fp.name,
        "content": clip_text(text, 8000),
    }


def get_coverage_summary_impl(run: RunRef, args: dict) -> dict[str, Any]:
    residual_depths = {"shallow", "none", "aborted", "planned", ""}
    limit = min(40, max(1, int(args.get("limit") or 20)))
    db = _open_db(run.path)
    try:
        facts = db.list_coverage_facts()
        residual = []
        counts: dict[str, int] = {}
        for fact in facts:
            depth = str(fact.get("last_depth") or "").lower()
            counts[depth or "empty"] = counts.get(depth or "empty", 0) + 1
            if depth in residual_depths or depth == "empty":
                residual.append(
                    {
                        "area": fact.get("area"),
                        "class": fact.get("attack_class") or fact.get("class"),
                        "path": fact.get("path"),
                        "last_depth": depth or "empty",
                        "visits": fact.get("visits") or fact.get("visit_count"),
                    }
                )
        residual = residual[:limit]
        return {
            "ok": True,
            "target_id": run.target_id,
            "run_id": run.run_id,
            "depth_counts": counts,
            "residual": residual,
            "residual_count": len(residual),
        }
    finally:
        db.close()


def get_project_excerpt_impl(run: RunRef, args: dict) -> dict[str, Any]:
    name = str(args.get("name") or "REPORT.md").strip()
    base = name.replace("\\", "/").split("/")[-1]
    if base not in ("REPORT.md", "STATE.md", "CODEMAP.md", "ARCHITECTURE.md", "TOOL_GAPS.md"):
        # allow without .md
        if base.upper() in ("REPORT", "STATE", "CODEMAP", "ARCHITECTURE"):
            base = base.upper() + ".md" if not base.endswith(".md") else base
        else:
            return {"ok": False, "error": "name must be REPORT|STATE|CODEMAP|ARCHITECTURE|TOOL_GAPS"}
    fp = run.path / "project" / base
    if not fp.is_file():
        return {"ok": False, "error": f"missing project/{base}"}
    try:
        text = fp.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return {"ok": False, "error": str(e)}
    return {
        "ok": True,
        "target_id": run.target_id,
        "run_id": run.run_id,
        "name": base,
        "content": clip_text(text, 8000),
    }


def get_architecture_impl(run: RunRef, _args: dict) -> dict[str, Any]:
    db = _open_db(run.path)
    try:
        arch = db.get_architecture()
        if not arch:
            return {"ok": True, "architecture": None, "message": "no architecture yet"}
        if isinstance(arch, dict):
            out = {
                "summary": clip_text(arch.get("summary") or arch.get("overview") or "", 2000),
                "components": cap_list(list(arch.get("components") or [])[:30], 30),
                "trust_boundaries": cap_list(list(arch.get("trust_boundaries") or [])[:20], 20),
                "keys": list(arch.keys())[:40],
            }
            return {"ok": True, "target_id": run.target_id, "run_id": run.run_id, "architecture": out}
        return {"ok": True, "architecture": clip_text(str(arch), 4000)}
    finally:
        db.close()


def get_codemap_impl(run: RunRef, _args: dict) -> dict[str, Any]:
    """Compact codemap summary for operator chat (not full modules dump)."""
    from vulnforge.tools.codemap import codemap_summary_for_ui

    db = _open_db(run.path)
    try:
        codemap = db.get_codemap()
        summary = codemap_summary_for_ui(codemap if isinstance(codemap, dict) else None)
        if not summary.get("has_codemap") and not codemap:
            return {
                "ok": True,
                "codemap": None,
                "message": "no codemap yet — run recon or rebuild",
                "target_id": run.target_id,
                "run_id": run.run_id,
            }
        langs = summary.get("languages") or {}
        top_langs = sorted(
            ((k, int(v or 0)) for k, v in langs.items()),
            key=lambda kv: (-kv[1], kv[0]),
        )[:8]
        return {
            "ok": True,
            "target_id": run.target_id,
            "run_id": run.run_id,
            "codemap": {
                "has_codemap": bool(summary.get("has_codemap")),
                "module_count": summary.get("module_count") or 0,
                "file_count": summary.get("file_count") or 0,
                "package_roots": list(summary.get("package_roots") or [])[:20],
                "languages": {k: v for k, v in top_langs},
                "entrypoint_count": summary.get("entrypoint_count") or 0,
                "annotation_count": summary.get("annotation_count") or 0,
                "source": summary.get("source"),
                "generated_at": summary.get("generated_at"),
            },
        }
    finally:
        db.close()


def get_status_impl(run: RunRef, _args: dict) -> dict[str, Any]:
    card = run_card(run)
    status = runctl.runner_status(run.path)
    codemap_brief: dict[str, Any] = {
        "has_codemap": bool(card.get("has_codemap")),
        "module_count": 0,
        "package_roots": [],
    }
    try:
        from vulnforge.tools.codemap import codemap_summary_for_ui

        db = _open_db(run.path)
        try:
            cm = db.get_codemap()
            s = codemap_summary_for_ui(cm if isinstance(cm, dict) else None)
            codemap_brief = {
                "has_codemap": bool(s.get("has_codemap")),
                "module_count": int(s.get("module_count") or 0),
                "file_count": int(s.get("file_count") or 0),
                "package_roots": list(s.get("package_roots") or [])[:12],
                "annotation_count": int(s.get("annotation_count") or 0),
            }
        finally:
            db.close()
    except Exception:
        pass
    return {
        "ok": True,
        "card": {
            k: card.get(k)
            for k in (
                "key",
                "target_id",
                "run_id",
                "status",
                "tasks",
                "findings",
                "has_work",
                "progress",
                "locked",
                "stop",
                "llm_usage",
                "has_codemap",
            )
        },
        "codemap": codemap_brief,
        "runner": status,
        "url": f"/runs/{run.target_id}/{run.run_id}",
    }


def list_events_impl(run: RunRef, args: dict) -> dict[str, Any]:
    limit = min(50, max(1, int(args.get("limit") or 20)))
    p = run.path / "events.jsonl"
    if not p.is_file():
        return {"ok": True, "events": [], "count": 0}
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        return {"ok": False, "error": str(e)}
    events = []
    for line in lines[-limit:]:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({"raw": clip_text(line, 200)})
    return {"ok": True, "events": events, "count": len(events)}


def list_tasks_impl(run: RunRef, args: dict) -> dict[str, Any]:
    kind = str(args.get("kind") or "").strip() or None
    state = str(args.get("state") or "").strip() or None
    limit = min(MAX_LIST, max(1, int(args.get("limit") or 40)))
    db = _open_db(run.path)
    try:
        rows = []
        for t in db.list_tasks(limit=2000):
            if kind and t.kind != kind:
                continue
            if state and str(t.state) != state:
                continue
            rows.append(
                {
                    "task_id": t.id,
                    "kind": t.kind,
                    "state": t.state,
                    "payload": {
                        k: (t.payload or {}).get(k)
                        for k in ("area", "class", "path_hints", "agent_id")
                        if (t.payload or {}).get(k) is not None
                    },
                    "result_summary": clip_summary(
                        json.dumps(t.result or {}, default=str)[:200], 200
                    ),
                }
            )
            if len(rows) >= limit:
                break
        return {"ok": True, "tasks": rows, "count": len(rows)}
    finally:
        db.close()


def runner_action(run: RunRef, action: str, args: dict) -> dict[str, Any]:
    if action == "start_run":
        kw: dict[str, Any] = {}
        if args.get("max_tasks") is not None:
            kw["max_tasks"] = int(args["max_tasks"])
        if args.get("workers") is not None:
            kw["workers"] = int(args["workers"])
        if args.get("task_timeout") is not None:
            kw["task_timeout"] = float(args["task_timeout"])
        r = runctl.start_run(run.path, **kw)
    elif action == "pause_run":
        r = runctl.pause_run(run.path)
    elif action == "resume_run":
        kw = {}
        if args.get("max_tasks") is not None:
            kw["max_tasks"] = int(args["max_tasks"])
        if args.get("workers") is not None:
            kw["workers"] = int(args["workers"])
        r = runctl.resume_run(run.path, **kw)
    elif action == "hard_stop_run":
        r = runctl.stop_run_hard(run.path)
    else:
        return {"ok": False, "error": f"unknown action {action}"}
    try:
        append_event(
            run.path,
            {"source": "operator_chat", "event": action, "ok": bool(r.get("ok"))},
        )
    except OSError:
        pass
    return {**r, "target_id": run.target_id, "run_id": run.run_id, "action": action}


def browse_target_impl(run: RunRef, args: dict) -> dict[str, Any]:
    from vulnforge.control import ops as dashops

    rel = str(args.get("path") or args.get("rel") or ".").strip() or "."
    return dashops.target_list(run.path, rel)


def read_target_file_impl(run: RunRef, args: dict) -> dict[str, Any]:
    from vulnforge.control import ops as dashops

    path = str(args.get("path") or "").strip()
    if not path:
        return {"ok": False, "error": "path required"}
    start = args.get("start_line")
    end = args.get("end_line")
    return dashops.target_read(
        run.path,
        path,
        start_line=int(start) if start is not None else None,
        end_line=int(end) if end is not None else None,
    )


def mutation_summary(name: str, args: dict[str, Any]) -> str:
    if name == "enqueue_hunt":
        return (
            f"Enqueue hunt class={args.get('class') or args.get('attack_class')} "
            f"area={args.get('area')} paths={args.get('paths') or args.get('path_hints')} "
            f"on {args.get('target_id')}/{args.get('run_id')}"
        )
    if name == "requeue_hunt":
        return f"Requeue hunt {args.get('area')} × {args.get('class') or args.get('attack_class')}"
    if name == "requeue_hunts_bulk":
        n = len(args.get("cells") or [])
        return f"Bulk requeue {n} coverage cell(s)"
    if name in ("start_run", "pause_run", "resume_run", "hard_stop_run"):
        return f"{name.replace('_', ' ')} for {args.get('target_id')}/{args.get('run_id')}"
    if name == "init_run":
        return f"Init new run for target={args.get('target')}"
    if name == "review_finding":
        return f"Review finding {args.get('finding_id')} → {args.get('action') or args.get('decision')}"
    return f"Execute {name} with {args}"


# Fleet helpers
def list_runs_impl(runs_root: Path, args: dict) -> dict[str, Any]:
    filt = str(args.get("filter") or "all").strip().lower()
    limit = min(100, max(1, int(args.get("limit") or 40)))
    refs = discover_runs(runs_root)[:80]
    cards = []
    for ref in refs:
        try:
            card = run_card(ref)
            st = runctl.runner_status(ref.path)
            card["runner_alive"] = bool(st.get("alive"))
            card["incomplete"] = (not st.get("alive")) and bool(card.get("has_work"))
        except Exception as e:
            card = {
                "key": ref.key,
                "target_id": ref.target_id,
                "run_id": ref.run_id,
                "error": str(e),
            }
        if filt == "running" and not card.get("runner_alive"):
            continue
        if filt == "idle" and (card.get("runner_alive") or card.get("has_work")):
            continue
        if filt == "incomplete" and not card.get("incomplete") and not card.get("has_work"):
            continue
        cards.append(
            {
                "key": card.get("key"),
                "target_id": card.get("target_id"),
                "run_id": card.get("run_id"),
                "status": card.get("status"),
                "tasks": card.get("tasks"),
                "findings": card.get("findings"),
                "has_work": card.get("has_work"),
                "runner_alive": card.get("runner_alive"),
                "incomplete": card.get("incomplete"),
                "url": f"/runs/{card.get('target_id')}/{card.get('run_id')}",
            }
        )
        if len(cards) >= limit:
            break
    return {"ok": True, "runs": cards, "count": len(cards), "filter": filt}


def list_findings_all_impl(runs_root: Path, args: dict) -> dict[str, Any]:
    state = str(args.get("state") or "").strip() or None
    cls = str(args.get("class") or "").strip()
    tid_f = str(args.get("target_id") or "").strip() or None
    rid_f = str(args.get("run_id") or "").strip() or None
    q = str(args.get("q") or "").strip().lower()
    limit = min(MAX_LIST, max(1, int(args.get("limit") or 50)))
    max_runs = min(60, max(1, int(args.get("max_runs") or 40)))
    refs = discover_runs(runs_root)[:max_runs]
    out = []
    for ref in refs:
        if tid_f and ref.target_id != tid_f:
            continue
        if rid_f and ref.run_id != rid_f:
            continue
        part = list_findings_impl(
            ref, {"state": state, "class": cls, "q": q, "limit": limit}
        )
        for f in part.get("findings") or []:
            f["target_id"] = ref.target_id
            f["run_id"] = ref.run_id
            f["key"] = ref.key
            out.append(f)
            if len(out) >= limit:
                return {"ok": True, "findings": out, "count": len(out), "truncated": True}
    return {"ok": True, "findings": out, "count": len(out), "truncated": False}


def list_hunts_all_impl(runs_root: Path, args: dict) -> dict[str, Any]:
    limit = min(MAX_LIST, max(1, int(args.get("limit") or 40)))
    max_runs = min(40, max(1, int(args.get("max_runs") or 25)))
    refs = discover_runs(runs_root)[:max_runs]
    out = []
    for ref in refs:
        if args.get("target_id") and ref.target_id != args.get("target_id"):
            continue
        if args.get("run_id") and ref.run_id != args.get("run_id"):
            continue
        part = list_hunts_impl(ref, {**args, "limit": limit})
        for h in part.get("hunts") or []:
            h["target_id"] = ref.target_id
            h["run_id"] = ref.run_id
            h["key"] = ref.key
            out.append(h)
            if len(out) >= limit:
                return {"ok": True, "hunts": out, "count": len(out), "truncated": True}
    return {"ok": True, "hunts": out, "count": len(out), "truncated": False}


def rollup_results_impl(runs_root: Path, args: dict) -> dict[str, Any]:
    max_runs = min(60, max(1, int(args.get("max_runs") or 40)))
    refs = discover_runs(runs_root)[:max_runs]
    rows = []
    for ref in refs:
        try:
            card = run_card(ref)
            st = runctl.runner_status(ref.path)
            cov = get_coverage_summary_impl(ref, {"limit": 5})
            rows.append(
                {
                    "key": ref.key,
                    "target_id": ref.target_id,
                    "run_id": ref.run_id,
                    "runner_alive": bool(st.get("alive")),
                    "has_work": card.get("has_work"),
                    "tasks": card.get("tasks"),
                    "findings": card.get("findings"),
                    "coverage_depth_counts": cov.get("depth_counts"),
                    "url": f"/runs/{ref.target_id}/{ref.run_id}",
                }
            )
        except Exception as e:
            rows.append({"key": ref.key, "error": str(e)})
    return {"ok": True, "runs": rows, "count": len(rows)}


def search_results_impl(runs_root: Path, args: dict) -> dict[str, Any]:
    q = str(args.get("q") or args.get("text") or "").strip()
    if not q:
        return {"ok": False, "error": "q required"}
    limit = min(40, max(1, int(args.get("limit") or 25)))
    findings = list_findings_all_impl(runs_root, {"q": q, "limit": limit})
    hunts = list_hunts_all_impl(runs_root, {"limit": limit})
    # filter hunts by q
    ql = q.lower()
    hunt_hits = [
        h
        for h in (hunts.get("hunts") or [])
        if ql in json.dumps(h, default=str).lower()
    ][:limit]
    return {
        "ok": True,
        "q": q,
        "findings": findings.get("findings") or [],
        "hunts": hunt_hits,
    }


def open_run_impl(args: dict) -> dict[str, Any]:
    tid = str(args.get("target_id") or "").strip()
    rid = str(args.get("run_id") or "").strip()
    if not tid or not rid:
        return {"ok": False, "error": "target_id and run_id required"}
    hash_ = str(args.get("hash") or args.get("fragment") or "").strip()
    url = f"/runs/{tid}/{rid}"
    if hash_:
        url += hash_ if hash_.startswith("#") else f"#{hash_}"
    return {"ok": True, "url": url, "navigate": url}


def open_finding_impl(args: dict) -> dict[str, Any]:
    tid = str(args.get("target_id") or "").strip()
    rid = str(args.get("run_id") or "").strip()
    fid = args.get("finding_id")
    if not tid or not rid or fid is None:
        return {"ok": False, "error": "target_id, run_id, finding_id required"}
    url = f"/runs/{tid}/{rid}#report"
    return {"ok": True, "url": url, "navigate": url, "finding_id": fid}


def explain_product_impl(_args: dict) -> dict[str, Any]:
    return {
        "ok": True,
        "text": (
            "VulnForge loop: init → recon → hunt → validate_mech → human review → project projection. "
            "Modes: Mission (overview/arch), Coverage (residual matrix), Explorer (enqueue hunts), "
            "Report (findings), Evidence, Tasks. "
            "needs_human = mech gates passed; confirmed = human accepted; neither is exploit proof. "
            "Start Ralph from Mission bar or AI chat to drain the task queue."
        ),
    }


def get_tool_gaps_summary_impl(runs_root: Path, args: dict) -> dict[str, Any]:
    try:
        from vulnforge.tool_gaps import aggregate_tool_gaps, load_or_analyze

        if args.get("target_id") and args.get("run_id"):
            ref, err = resolve_run_dir(runs_root, args)
            if err or not ref:
                return {"ok": False, "error": err or "run not found"}
            analysis = load_or_analyze(ref.path, force=False, cfg=None)
            gaps = (analysis or {}).get("gaps") or analysis
            return {"ok": True, "scope": "run", "gaps": gaps}
        rollup = aggregate_tool_gaps(runs_root, analyze_missing=False)
        return {"ok": True, "scope": "fleet", "rollup": rollup}
    except Exception as e:
        return {"ok": False, "error": str(e)}
