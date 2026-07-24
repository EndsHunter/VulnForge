"""
Read-only view of runs/ artifacts for the dashboard.

Authority: harness.db + events.jsonl + evidence/ + project/ (projection).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Optional

from vulnforge.db import Database


@dataclass
class RunRef:
    target_id: str
    run_id: str
    path: Path

    @property
    def key(self) -> str:
        return f"{self.target_id}/{self.run_id}"


def default_runs_root(project_root: Path) -> Path:
    return (project_root / "runs").resolve()


def discover_runs(runs_root: Path) -> list[RunRef]:
    """Scan runs/<target_id>/<run_id>/ for harness.db."""
    runs_root = Path(runs_root)
    out: list[RunRef] = []
    if not runs_root.is_dir():
        return out
    for target_dir in sorted(runs_root.iterdir(), key=lambda p: p.name.lower()):
        if not target_dir.is_dir():
            continue
        for run_dir in sorted(target_dir.iterdir(), key=lambda p: p.name.lower()):
            if run_dir.is_dir() and (run_dir / "harness.db").is_file():
                out.append(
                    RunRef(
                        target_id=target_dir.name,
                        run_id=run_dir.name,
                        path=run_dir.resolve(),
                    )
                )
    # newest first by mtime of harness.db
    out.sort(key=lambda r: (r.path / "harness.db").stat().st_mtime, reverse=True)
    return out


def resolve_run(runs_root: Path, target_id: str, run_id: str) -> RunRef:
    path = (Path(runs_root) / target_id / run_id).resolve()
    root = Path(runs_root).resolve()
    try:
        path.relative_to(root)
    except ValueError as e:
        raise FileNotFoundError("run path escape") from e
    if not (path / "harness.db").is_file():
        raise FileNotFoundError(path)
    return RunRef(target_id=target_id, run_id=run_id, path=path)


def delete_run(
    runs_root: Path,
    target_id: str,
    run_id: str,
    *,
    force: bool = True,
    stop_runner: bool = True,
    require_db: bool = True,
) -> dict[str, Any]:
    """
    Permanently delete a run directory under ``runs_root``.

    Safety:
      - Path must resolve under runs_root (no escape)
      - By default requires harness.db so arbitrary folders are not wiped
      - Hard-stops Ralph when force and stop_runner (default both true)
      - Removes empty parent ``target_id/`` after the run dir is gone

    Returns ``{ok, path, removed_parent, stopped, error?}``.
    """
    import shutil

    root = Path(runs_root).resolve()
    if not target_id or not run_id:
        return {"ok": False, "error": "missing target_id or run_id"}
    if "/" in target_id or "\\" in target_id or ".." in target_id:
        return {"ok": False, "error": "invalid target_id"}
    if "/" in run_id or "\\" in run_id or ".." in run_id:
        return {"ok": False, "error": "invalid run_id"}

    path = (root / target_id / run_id).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return {"ok": False, "error": "run path escape"}

    if not path.is_dir():
        return {"ok": False, "error": "run not found", "path": str(path)}

    has_db = (path / "harness.db").is_file()
    if require_db and not has_db:
        return {
            "ok": False,
            "error": "no harness.db (pass force to delete anyway)",
            "path": str(path),
        }

    stopped: dict[str, Any] = {}
    if stop_runner:
        try:
            from vulnforge.ui import runner as runctl

            status = runctl.runner_status(path)
            if status.get("alive") and not force:
                return {
                    "ok": False,
                    "error": "runner still alive; pass force=true to hard-stop and delete",
                    "path": str(path),
                    "runner": status,
                }
            if status.get("alive") or status.get("pid"):
                stopped = runctl.stop_run_hard(path)
            else:
                stopped = {"ok": True, "killed": False, "status": status}
        except Exception as e:
            if not force:
                return {
                    "ok": False,
                    "error": f"could not stop runner: {e}",
                    "path": str(path),
                }
            stopped = {"ok": False, "error": str(e)}

    try:
        shutil.rmtree(path)
    except OSError as e:
        return {
            "ok": False,
            "error": f"delete failed: {e}",
            "path": str(path),
            "stopped": stopped,
        }

    removed_parent = False
    parent = path.parent
    try:
        if (
            parent.is_dir()
            and parent.resolve() != root
            and parent.parent.resolve() == root
        ):
            if not any(parent.iterdir()):
                parent.rmdir()
                removed_parent = True
    except OSError:
        pass

    return {
        "ok": True,
        "path": str(path),
        "target_id": target_id,
        "run_id": run_id,
        "removed_parent": removed_parent,
        "stopped": stopped,
    }


def _open_db(run: RunRef) -> Database:
    # read-only connection preference  -  sqlite URI mode=ro if possible
    return Database.open(run.path / "harness.db")


def _severity_counts(db: Database) -> dict[str, int]:
    """Count findings by severity_claim (normalized)."""
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for f in db.list_findings():
        if f.state not in ("confirmed", "candidate", "needs_human"):
            continue
        sev = str((f.body or {}).get("severity_claim") or "unknown").lower().strip()
        if sev in counts:
            counts[sev] += 1
        elif sev in ("crit", "p0"):
            counts["critical"] += 1
        elif sev in ("p1",):
            counts["high"] += 1
        elif sev in ("p2", "med"):
            counts["medium"] += 1
        elif sev in ("p3",):
            counts["low"] += 1
        else:
            counts["unknown"] += 1
    return counts


def run_card(run: RunRef) -> dict[str, Any]:
    """Compact summary for the home list."""
    locked = (run.path / "run.lock").is_file()
    stop = (run.path / "STOP").is_file()
    events_path = run.path / "events.jsonl"
    event_count = 0
    last_event = None
    mtime = None
    if events_path.is_file():
        try:
            lines = events_path.read_text(encoding="utf-8", errors="replace").splitlines()
            event_count = len(lines)
            if lines:
                last_event = json.loads(lines[-1])
            mtime = events_path.stat().st_mtime
        except (OSError, json.JSONDecodeError):
            pass
    try:
        mtime = mtime or (run.path / "harness.db").stat().st_mtime
    except OSError:
        mtime = None

    db = _open_db(run)
    try:
        s = db.summary()
        run_row = s.get("run") or {}
        tasks = s.get("tasks") or {}
        findings = s.get("findings") or {}
        severity = _severity_counts(db)
        total_tasks = sum(tasks.values()) or 0
        # Durable terminal states only. failed_infra is an *event* / stage signal;
        # under-cap infra requeues as queued, at-cap becomes deadletter.
        done = sum(
            tasks.get(k, 0)
            for k in (
                "succeeded",
                "failed_task",
                "blocked",
                "deadletter",
                "cancelled",
            )
        )
        progress = (done / total_tasks) if total_tasks else 0.0
        active = (
            tasks.get("leased", 0) > 0
            or tasks.get("paused", 0) > 0
            or locked
        )
        has_work = bool(s.get("has_work"))
        return {
            "key": run.key,
            "target_id": run.target_id,
            "run_id": run.run_id,
            "path": str(run.path),
            "target_path": run_row.get("target_path"),
            "profile": run_row.get("profile"),
            "status": run_row.get("status"),
            "created_at": run_row.get("created_at"),
            "updated_at": last_event.get("ts") if isinstance(last_event, dict) else None,
            "mtime": mtime,
            "prompt_pin": (run_row.get("prompt_pin") or "")[:16],
            "tasks": tasks,
            "findings": findings,
            "severity": severity,
            "has_work": has_work,
            # Finalized by API/UI with runner_status (dead + has_work).
            "incomplete": False,
            "total_tasks": total_tasks,
            "done_tasks": done,
            "progress": round(progress, 3),
            "locked": locked,
            "stop": stop,
            "active": active,
            "event_count": event_count,
            "last_event": last_event,
            "has_architecture": bool(run_row.get("has_architecture")),
            "has_codemap": bool(run_row.get("has_codemap")),
            "has_report": (run.path / "project" / "REPORT.md").is_file(),
            "llm_usage": _llm_usage_card(run),
        }
    finally:
        db.close()


# Matches vulnforge.tools.grep_index.SAMPLE_PATHS_CAP — packet seed only.
try:
    from vulnforge.tools.grep_index import SAMPLE_PATHS_CAP
except Exception:  # pragma: no cover
    SAMPLE_PATHS_CAP = 500


def _llm_usage_card(run: RunRef) -> dict[str, Any]:
    try:
        from vulnforge.usage import (
            llm_usage_for_card,
            load_usage_summary,
            rebuild_by_task_from_jsonl,
        )

        card = llm_usage_for_card(run.path)
        summary = load_usage_summary(run.path)
        card["by_kind"] = summary.get("by_kind") or {}
        card["by_model"] = summary.get("by_model") or {}
        by_task = summary.get("by_task") or {}
        if not by_task:
            # Older runs recorded usage before by_task existed
            by_task = rebuild_by_task_from_jsonl(run.path)
        card["by_task"] = by_task
        return card
    except Exception:
        return {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "reasoning_tokens": 0,
            "llm_calls": 0,
            "source": "none",
            "by_kind": {},
            "by_model": {},
            "by_task": {},
        }


def _manifest_file_count(run: RunRef) -> int | None:
    path = run.path / "target_manifest.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    fc = data.get("file_count")
    try:
        return int(fc) if fc is not None else None
    except (TypeError, ValueError):
        return None


def _target_inventory(
    run: RunRef,
    arch: dict | None,
    tasks: list[dict[str, Any]],
) -> dict[str, Any]:
    """Campaign inventory facts for Mission overview (not a recon stop limit).

    ``file_count`` is the full tree. ``planning_seed_*`` describes the capped
    path list injected into the recon packet / default hunt seeds only —
    Ralph and hunt tools still see the whole tree.
    """
    file_count: int | None = None
    entrypoints: list[str] = []
    extensions: dict[str, int] = {}
    if isinstance(arch, dict):
        inv = arch.get("inventory") or {}
        if isinstance(inv, dict):
            if inv.get("file_count") is not None:
                try:
                    file_count = int(inv["file_count"])
                except (TypeError, ValueError):
                    file_count = None
            eps = inv.get("entrypoints")
            if isinstance(eps, list):
                entrypoints = [str(x) for x in eps[:20] if x]
            ext = inv.get("extensions")
            if isinstance(ext, dict):
                extensions = {str(k): int(v) for k, v in list(ext.items())[:12]
                              if str(k) and v is not None}

    if file_count is None:
        file_count = _manifest_file_count(run)

    hunt_plan_source: str | None = None
    hunt_enqueued: int | None = None
    recon_done = False
    last_recon: dict[str, Any] | None = None
    terminal = frozenset(
        {"succeeded", "failed_task", "failed_infra", "deadletter", "cancelled"}
    )
    for t in reversed(tasks):
        if t.get("kind") != "recon":
            continue
        st = str(t.get("state") or "").lower()
        if st not in terminal:
            continue
        res = t.get("result") if isinstance(t.get("result"), dict) else {}
        payload = t.get("payload") if isinstance(t.get("payload"), dict) else {}
        err = None
        if st != "succeeded":
            err = (res or {}).get("error") or st
        gen = payload.get("recon_generation")
        try:
            gen_i = int(gen) if gen is not None else 1
        except (TypeError, ValueError):
            gen_i = 1
        last_recon = {
            "task_id": t.get("id"),
            "state": st,
            "error": str(err)[:200] if err else None,
            "hunt_enqueued": (res or {}).get("hunt_enqueued"),
            "hunt_plan_source": (res or {}).get("hunt_plan_source"),
            "recon_generation": gen_i,
            "recon_requeued": bool((res or {}).get("recon_requeued")),
            "child_task_id": (res or {}).get("child_task_id"),
            "batch_finalized": (res or {}).get("batch_finalized"),
            "enqueue_hunts": (res or {}).get("enqueue_hunts"),
        }
        if st == "succeeded":
            recon_done = True
            hps = (res or {}).get("hunt_plan_source")
            if hps is not None:
                hunt_plan_source = str(hps)
            if (res or {}).get("hunt_enqueued") is not None:
                try:
                    hunt_enqueued = int(res["hunt_enqueued"])
                except (TypeError, ValueError):
                    hunt_enqueued = None
            if file_count is None and (res or {}).get("file_count") is not None:
                try:
                    file_count = int(res["file_count"])
                except (TypeError, ValueError):
                    pass
        break

    seed_partial = file_count is not None and file_count > SAMPLE_PATHS_CAP
    return {
        "file_count": file_count,
        "entrypoints": entrypoints,
        "extensions": extensions,
        "planning_seed_cap": SAMPLE_PATHS_CAP,
        "planning_seed_partial": seed_partial,
        "sample_paths_cap": SAMPLE_PATHS_CAP,
        "hunt_plan_source": hunt_plan_source,
        "hunt_enqueued": hunt_enqueued,
        "recon_done": recon_done,
        "last_recon": last_recon,
        "note": (
            "Planning seed is a packet budget only. Full file_count is inventoried; "
            "hunts can list/grep/read the whole tree. Ralph is not limited by the seed."
        ),
    }


def run_snapshot(run: RunRef) -> dict[str, Any]:
    """Full snapshot for run detail page / API."""
    card = run_card(run)
    # Ensure full usage breakdown is present (card already has llm_usage)
    if "llm_usage" not in card or not isinstance(card.get("llm_usage"), dict):
        card["llm_usage"] = _llm_usage_card(run)
    arch = None
    codemap = None
    notes: list = []
    db = _open_db(run)
    try:
        tasks = []
        for t in db.list_tasks():
            tasks.append(
                {
                    "id": t.id,
                    "kind": t.kind,
                    "state": t.state,
                    "payload": t.payload,
                    "attempt": t.attempt,
                    "priority": t.priority,
                    "lease_owner": t.lease_owner,
                    "lease_until": t.lease_until,
                    "result": t.result,
                }
            )
        findings = []
        for f in db.list_findings():
            findings.append(
                {
                    "id": f.id,
                    "stable_key": f.stable_key,
                    "state": f.state,
                    "evidence_id": f.evidence_id,
                    "body": f.body,
                }
            )
        arch = db.get_architecture()
        codemap = db.get_codemap()
        notes = db.list_notes()
        try:
            coverage = db.coverage_matrix()
            coverage_facts = db.list_coverage_facts()
        except Exception:
            coverage = {"areas": [], "classes": [], "cells": []}
            coverage_facts = []
    finally:
        db.close()

    evidence = list_evidence(run)
    project = list_project_files(run)
    try:
        from vulnforge.transcript import list_transcript_ids

        t_ids = set(list_transcript_ids(run.path))
    except Exception:
        t_ids = set()
    for t in tasks:
        t["has_transcript"] = t["id"] in t_ids
    # Near-dup flags on findings for UI
    for f in findings:
        b = f.get("body") or {}
        f["near_dup"] = bool(
            b.get("merged_classes")
            or b.get("near_dup_titles")
            or b.get("superseded_by")
            or f.get("state") == "superseded"
        )
        f["severity"] = str(b.get("severity_claim") or "unknown").lower()

    try:
        from vulnforge.db import Database
        from vulnforge.stages.recon import hunt_class_catalog
        from vulnforge.ui.ops import (
            architecture_summary,
            coverage_policy_from_config,
            depth_reason_text,
            get_run_config,
        )

        for cell in coverage.get("cells") or []:
            cell["depth_blurb"] = depth_reason_text(str(cell.get("last_depth") or ""))
        db2 = Database.open(run.path / "harness.db")
        try:
            run_cfg = get_run_config(db2) or {}
            cov_policy = coverage_policy_from_config(run_cfg)
        finally:
            db2.close()
        run_profile = ""
        try:
            run_profile = str(card.get("profile") or "")
        except Exception:
            run_profile = ""
        if not run_profile and isinstance(run_cfg, dict):
            run_profile = str((run_cfg.get("run") or {}).get("profile") or "")
        arch_summary = architecture_summary(
            arch if isinstance(arch, dict) else None,
            profile=run_profile or None,
        )
        hunt_classes = hunt_class_catalog()
    except Exception:
        cov_policy = {"mode": "auto", "areas": [], "classes": []}
        prof = ""
        try:
            prof = str(card.get("profile") or "")
        except Exception:
            prof = ""
        arch_summary = {
            "mode": "source",
            "title": "Architecture",
            "summary": "",
            "components": [],
            "modules": [],
            "seed_sinks": [],
            "imports_preview": [],
            "exports_preview": [],
            "binary": {},
            "has_architecture": bool(arch),
        }
        hunt_classes = {"all": [], "active": []}
        run_cfg = {}

    # Codemap for Mission UI (full map + compact summary; merge agent notes).
    codemap_summary: dict[str, Any]
    try:
        from vulnforge.tools.codemap import (
            codemap_summary_for_ui,
            merge_annotations_into_codemap,
        )

        if isinstance(codemap, dict):
            note_rows = [
                n
                for n in (notes or [])
                if isinstance(n, dict) and n.get("kind") == "codemap"
            ]
            if note_rows:
                codemap = merge_annotations_into_codemap(codemap, note_rows)
            codemap_summary = codemap_summary_for_ui(codemap)
        else:
            codemap = None
            codemap_summary = codemap_summary_for_ui(None)
    except Exception:
        codemap_summary = {
            "has_codemap": bool(codemap),
            "module_count": 0,
            "file_count": 0,
            "package_roots": [],
            "languages": {},
            "entrypoint_count": 0,
            "annotation_count": 0,
            "source": None,
            "generated_at": None,
        }

    if not isinstance(run_cfg, dict):
        run_cfg = {}

    max_task_attempts = 3
    try:
        max_task_attempts = max(1, int((run_cfg.get("run") or {}).get("max_task_attempts", 3)))
    except (TypeError, ValueError):
        # run_cfg may be flat dashboard config without nested "run"
        try:
            max_task_attempts = max(1, int(run_cfg.get("max_task_attempts", 3)))
        except (TypeError, ValueError):
            max_task_attempts = 3

    # Operator enqueue/plan ceiling (same source as control/ops coverage mode).
    # UI Coverage estimates must use this — never a stale hard-coded 40.
    max_tasks = 50
    try:
        max_tasks = max(1, int((run_cfg.get("run") or {}).get("max_tasks", 50)))
    except (TypeError, ValueError):
        try:
            max_tasks = max(1, int(run_cfg.get("max_tasks", 50)))
        except (TypeError, ValueError):
            max_tasks = 50

    target_inv = _target_inventory(run, arch, tasks)
    # Preserve card-level counter maps before overwriting with full lists.
    # Live SSE compares these shapes; UI uses tasks[] / findings[] for tables.
    tasks_summary = card.get("tasks") if isinstance(card.get("tasks"), dict) else {}
    findings_summary = (
        card.get("findings") if isinstance(card.get("findings"), dict) else {}
    )
    return {
        **card,
        "tasks": tasks,
        "findings": findings,
        "tasks_summary": tasks_summary,
        "findings_summary": findings_summary,
        "architecture": arch,
        "architecture_summary": arch_summary,
        "codemap": codemap if isinstance(codemap, dict) else None,
        "codemap_summary": codemap_summary,
        "has_codemap": bool(
            (codemap_summary or {}).get("has_codemap")
            if isinstance(codemap_summary, dict)
            else codemap
        ),
        "notes": notes,
        "evidence": evidence,
        "project_files": project,
        "transcript_task_ids": sorted(t_ids),
        "coverage": coverage,
        "coverage_facts": coverage_facts,
        "coverage_policy": cov_policy,
        "hunt_classes": hunt_classes,
        "target_inventory": target_inv,
        "config": run_cfg,
        "max_task_attempts": max_task_attempts,
        "max_tasks": max_tasks,
        # Nested for clients that prefer snap.run.max_tasks (matches cfg.run.*)
        "run": {
            "max_tasks": max_tasks,
            "max_task_attempts": max_task_attempts,
        },
        "strategy": run_cfg.get("strategy"),
        "docs_path": run_cfg.get("docs_path"),
        "disclaimer": (
            "needs_human = mech gates; confirmed = human accepted. Always re-check."
        ),
    }


def list_evidence(run: RunRef) -> list[dict[str, Any]]:
    root = run.path / "evidence"
    if not root.is_dir():
        return []
    packs = []
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        files = []
        for f in sorted(d.rglob("*")):
            if f.is_file() and not f.name.endswith(".tmp"):
                try:
                    rel = str(f.relative_to(d)).replace("\\", "/")
                    size = f.stat().st_size
                except OSError:
                    continue
                files.append({"relpath": rel, "size": size})
        packs.append({"id": d.name, "files": files, "file_count": len(files)})
    return packs


def list_project_files(run: RunRef) -> list[dict[str, str]]:
    proj = run.path / "project"
    if not proj.is_dir():
        return []
    out = []
    for f in sorted(proj.iterdir()):
        if f.is_file():
            out.append({"name": f.name, "path": str(f)})
    return out


def read_project_file(run: RunRef, name: str) -> str:
    # only basename under project/
    safe = Path(name).name
    path = (run.path / "project" / safe).resolve()
    proj = (run.path / "project").resolve()
    if proj not in path.parents and path != proj:
        raise FileNotFoundError("escape")
    if not path.is_file():
        raise FileNotFoundError(safe)
    return path.read_text(encoding="utf-8", errors="replace")


def read_evidence_file(run: RunRef, pack_id: str, relpath: str) -> str:
    from vulnforge.tools.evidence_write import sanitize_evidence_id

    eid = sanitize_evidence_id(pack_id)
    rel = relpath.replace("\\", "/").lstrip("/")
    if ".." in Path(rel).parts:
        raise PermissionError("path escape")
    path = (run.path / "evidence" / eid / rel).resolve()
    root = (run.path / "evidence" / eid).resolve()
    if root not in path.parents and path != root:
        raise PermissionError("path escape")
    if not path.is_file():
        raise FileNotFoundError(rel)
    # cap size for UI
    data = path.read_bytes()
    if len(data) > 512_000:
        return data[:512_000].decode("utf-8", errors="replace") + "\n\n...[truncated]..."
    return data.decode("utf-8", errors="replace")


def read_events(
    run: RunRef, *, after: int = 0, limit: int = 2000
) -> tuple[list[dict], int]:
    """
    Read events.jsonl from line offset `after`.
    Returns (events, next_offset).
    """
    path = run.path / "events.jsonl"
    if not path.is_file():
        return [], 0
    events: list[dict] = []
    last_i = after - 1
    try:
        with path.open(encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                last_i = i
                if i < after:
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    ev = {"raw": line, "event": "parse_error"}
                ev["_line"] = i
                events.append(ev)
                if len(events) >= limit:
                    return events, i + 1
            return events, last_i + 1
    except OSError:
        return [], after


def iter_event_tail(
    run: RunRef, start_line: int = 0
) -> Iterator[tuple[list[dict], int]]:
    """Yield batches of new events (for SSE)."""
    events, nxt = read_events(run, after=start_line, limit=500)
    yield events, nxt
