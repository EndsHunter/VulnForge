"""
Operator-driven dashboard actions: coverage requeue, cell detail, area modes,
target browse, hunt-from-selection.

Authority remains harness.db; these are control-plane clients like apply-candidate.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from vulnforge.db import Database
from vulnforge.hunt_profiles import (
    HUNT_SKILL_MODES,
    active_class_ids,
    all_class_ids,
    resolve_run_class_ids,
    skill_policy_from_run_cfg,
)
from vulnforge.stages.recon import _normalize_class
from vulnforge.tools.fs_read import list_dir as tool_list_dir, read_file as tool_read_file, resolve_target_path
from vulnforge.util import append_event, normalize_relpath

# Mirrors vh/tools/grep_index.build_file_index sample window.
SAMPLE_PATHS_CAP = 500

DEPTH_BLURBS: dict[str, str] = {
    "": "No completed hunt depth recorded for this cell yet (planned or unvisited).",
    "planned": "Coverage fact created when the hunt was enqueued; visit not finished.",
    "shallow": (
        "Hunt ended without substantial read_file/grep use (shallow). "
        "Does not mean the area is safe - often requeued once with force_depth."
    ),
    "none": (
        "Hunter called submit_none after searching - honest miss for this class x area. "
        "Still not a proof of absence of bugs."
    ),
    "aborted": (
        "Hunt aborted (e.g. max_tool_rounds, no submit_*, or scope thrash). "
        "Cell is residual risk - re-queue recommended."
    ),
    "candidate": "At least one candidate finding was filed for this cell.",
    "confirmed": "A finding for this cell was accepted by a human after mech (not exploit proof).",
    "needs_human": "A finding passed mechanical gates and awaits human review.",
}


def _open_db(run_dir: Path) -> Database:
    return Database.open(run_dir / "harness.db")


def get_run_config(db: Database) -> dict[str, Any]:
    row = db.get_run()
    if not row:
        return {}
    raw = row["config_json"] if "config_json" in row.keys() else None
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}


def patch_run_config(db: Database, patch: dict[str, Any]) -> dict[str, Any]:
    """Merge patch into runs.config_json (shallow top-level merge)."""
    row = db.get_run()
    if not row:
        raise RuntimeError("no run")
    cfg = get_run_config(db)
    cfg.update(patch)
    db.conn.execute(
        "UPDATE runs SET config_json=? WHERE id=?",
        (json.dumps(cfg), row["id"]),
    )
    db.conn.commit()
    return cfg


def coverage_policy_from_config(cfg: dict[str, Any]) -> dict[str, Any]:
    pol = cfg.get("coverage_policy") if isinstance(cfg.get("coverage_policy"), dict) else {}
    mode = str(pol.get("mode") or "auto").lower()
    if mode not in ("auto", "all", "select"):
        mode = "auto"
    areas = pol.get("areas") if isinstance(pol.get("areas"), list) else []
    classes = pol.get("classes") if isinstance(pol.get("classes"), list) else []
    raw_pts = pol.get("path_targets") if isinstance(pol.get("path_targets"), list) else []
    path_targets: list[dict[str, Any]] = []
    for pt in raw_pts:
        if not isinstance(pt, dict):
            continue
        p = str(pt.get("path") or "").strip()
        if p:
            path_targets.append({"path": p, "is_dir": bool(pt.get("is_dir"))})
    return {
        "mode": mode,
        "areas": [str(a) for a in areas if a],
        "classes": [str(c) for c in classes if c],
        "path_targets": path_targets,
    }


def depth_reason_text(depth: str) -> str:
    d = (depth or "").lower().strip()
    return DEPTH_BLURBS.get(d, DEPTH_BLURBS.get("", ""))


def _tasks_for_cell(db: Database, area: str, attack_class: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for t in db.list_tasks(limit=2000):
        if t.kind != "hunt":
            continue
        p = t.payload or {}
        if str(p.get("area") or "") != area:
            continue
        if str(p.get("class") or "") != attack_class:
            continue
        res = t.result or {}
        out.append(
            {
                "id": t.id,
                "state": t.state,
                "attempt": t.attempt,
                "payload": p,
                "result": res,
                "has_transcript": False,  # filled by caller if needed
            }
        )
    return out


def _findings_for_cell(db: Database, area: str, attack_class: str) -> list[dict[str, Any]]:
    hits = []
    want = _normalize_class(attack_class)
    for f in db.list_findings():
        b = f.body or {}
        wc = _normalize_class(str(b.get("weakness_class") or ""))
        if wc != want:
            continue
        hits.append(
            {
                "id": f.id,
                "state": f.state,
                "title": b.get("title"),
                "summary": (b.get("summary") or "")[:400],
                "stable_key": f.stable_key,
                "evidence_id": f.evidence_id or b.get("evidence_id"),
                "area_hint": area,
            }
        )
    return hits


def cell_detail(run_dir: Path, area: str, attack_class: str) -> dict[str, Any]:
    """Reasons + facts for one coverage matrix cell."""
    db = _open_db(run_dir)
    try:
        facts = [
            f
            for f in db.list_coverage_facts()
            if f["area"] == area and f["attack_class"] == attack_class
        ]
        matrix = db.coverage_matrix()
        cell = next(
            (
                c
                for c in matrix.get("cells") or []
                if c.get("area") == area and c.get("class") == attack_class
            ),
            None,
        )
        last_depth = (cell or {}).get("last_depth") or (
            facts[-1]["last_depth"] if facts else ""
        )
        visit_count = (cell or {}).get("visit_count") or sum(
            int(f.get("visit_count") or 0) for f in facts
        )
        tasks = _tasks_for_cell(db, area, attack_class)
        findings = _findings_for_cell(db, area, attack_class)

        # Build human reasons from latest task outcomes
        reasons: list[str] = [depth_reason_text(str(last_depth or ""))]
        for t in reversed(tasks):
            res = t.get("result") or {}
            if res.get("none_found"):
                r = res.get("reason") or "submit_none"
                reasons.append(f"Task #{t['id']}: none - {r}")
                if res.get("shallow"):
                    reasons.append(f"Task #{t['id']}: marked shallow")
                if res.get("shallow_requeued"):
                    reasons.append(
                        f"Task #{t['id']}: auto re-queued child #{res.get('child_task_id')}"
                    )
            if res.get("aborted_scope") or res.get("error") in (
                "max_tool_rounds",
                "no_submit",
            ):
                reasons.append(
                    f"Task #{t['id']}: aborted - {res.get('error') or 'aborted_scope'}"
                )
            if res.get("finding_id"):
                reasons.append(f"Task #{t['id']}: filed finding #{res.get('finding_id')}")
            if t.get("state") == "queued":
                reasons.append(f"Task #{t['id']}: still queued")
            if t.get("state") == "leased":
                reasons.append(f"Task #{t['id']}: currently leased")
            if t.get("state") == "deadletter":
                reasons.append(f"Task #{t['id']}: deadletter after infra retries")
            if t.get("state") == "failed_task" and not res.get("aborted_scope"):
                reasons.append(
                    f"Task #{t['id']}: failed_task - {res.get('error') or 'unknown'}"
                )

        # de-dupe while preserving order
        seen: set[str] = set()
        uniq_reasons = []
        for r in reasons:
            if r and r not in seen:
                seen.add(r)
                uniq_reasons.append(r)

        path_hints: list[str] = []
        for t in tasks:
            for p in (t.get("payload") or {}).get("path_hints") or []:
                if p and p not in path_hints:
                    path_hints.append(str(p))
        for f in facts:
            if f.get("path") and f["path"] not in path_hints:
                path_hints.append(f["path"])

        return {
            "area": area,
            "class": attack_class,
            "last_depth": last_depth or "",
            "visit_count": visit_count,
            "depth_blurb": depth_reason_text(str(last_depth or "")),
            "reasons": uniq_reasons,
            "facts": facts,
            "path_hints": path_hints[:40],
            "tasks": tasks[-20:],  # recent-ish by id order
            "findings": findings[:20],
            "can_requeue": True,
        }
    finally:
        db.close()


# Operator-facing priority tiers (lower int = sooner). See lease_next_task ORDER BY.
PRIORITY_TIERS: dict[str, int] = {
    "high": 30,  # ahead of selection (35) and normal hunts (50)
    "normal": 50,  # default recon hunts
    "low": 90,  # after bulk residual work
}
# run_next is dynamic: min(queued)-1


def priority_tier_of(priority: int) -> str:
    """Map numeric priority to a coarse UI tier label."""
    try:
        p = int(priority)
    except (TypeError, ValueError):
        return "normal"
    if p <= 15:
        return "run_next"
    if p <= 40:
        return "high"
    if p <= 60:
        return "normal"
    return "low"


def set_task_priority_tier(
    run_dir: Path,
    task_id: int,
    tier: str,
) -> dict[str, Any]:
    """Set priority for a queued task using operator tiers.

    Tiers:
      - run_next: jump to front of the current queue (min priority - 1)
      - high / normal / low: fixed bands (see PRIORITY_TIERS)
    """
    t = str(tier or "").strip().lower().replace("-", "_")
    if t in ("next", "runnext", "front"):
        t = "run_next"
    if t not in ("run_next", "high", "normal", "low"):
        return {
            "ok": False,
            "error": f"invalid tier: {tier!r} (use run_next|high|normal|low)",
        }

    db = _open_db(run_dir)
    try:
        task = db.get_task(int(task_id))
        if not task:
            return {"ok": False, "error": f"task #{task_id} not found"}
        if task.state != "queued":
            return {
                "ok": False,
                "error": f"task #{task_id} is {task.state}, only queued tasks can be reordered",
            }

        if t == "run_next":
            # Strictly ahead of current queue head (may go negative — ASC order still works)
            mn = db.min_queued_priority()
            new_p = (int(mn) if mn is not None else 0) - 1
        else:
            new_p = int(PRIORITY_TIERS[t])

        ok = db.set_task_priority(int(task_id), new_p)
        if not ok:
            return {
                "ok": False,
                "error": f"task #{task_id} is not queued (state may have changed)",
            }

        try:
            append_event(
                run_dir,
                {
                    "source": "dashboard",
                    "event": "operator_priority",
                    "task_id": int(task_id),
                    "tier": t,
                    "priority": new_p,
                    "prev_priority": task.priority,
                },
            )
        except OSError:
            pass

        return {
            "ok": True,
            "task_id": int(task_id),
            "tier": t,
            "priority": new_p,
            "prev_priority": task.priority,
            "kind": task.kind,
            "state": "queued",
        }
    finally:
        db.close()


def cancel_queued_task(
    run_dir: Path,
    task_id: int,
    *,
    reason: str = "operator_cancel",
) -> dict[str, Any]:
    """Remove a task from the queue by marking it cancelled (terminal).

    Only ``queued`` tasks can be cancelled. Leased/running tasks are left alone
    so an in-flight worker is not orphaned mid-stage.
    """
    db = _open_db(run_dir)
    try:
        task = db.get_task(int(task_id))
        if not task:
            return {"ok": False, "error": f"task #{task_id} not found"}
        if task.state != "queued":
            return {
                "ok": False,
                "error": (
                    f"task #{task_id} is {task.state}; only queued tasks can be removed"
                ),
            }
        why = (reason or "operator_cancel").strip() or "operator_cancel"
        ok = db.cancel_queued_task(int(task_id), reason=why)
        if not ok:
            return {
                "ok": False,
                "error": f"task #{task_id} is not queued (state may have changed)",
            }
        try:
            append_event(
                run_dir,
                {
                    "source": "dashboard",
                    "event": "operator_cancel",
                    "task_id": int(task_id),
                    "kind": task.kind,
                    "priority": task.priority,
                    "reason": why,
                    "payload": task.payload,
                },
            )
        except OSError:
            pass
        return {
            "ok": True,
            "task_id": int(task_id),
            "kind": task.kind,
            "state": "cancelled",
            "reason": why,
            "prev_state": "queued",
            "priority": task.priority,
            "payload": task.payload,
        }
    finally:
        db.close()


def requeue_hunt(
    run_dir: Path,
    *,
    area: str,
    attack_class: str,
    path_hints: Optional[list[str]] = None,
    force_depth: bool = True,
    reason: str = "operator_requeue",
    operator_notes: str = "",
) -> dict[str, Any]:
    """Enqueue a hunt for area x class (operator force / residual coverage)."""
    cls = _normalize_class(attack_class)
    area_s = str(area or "app").strip() or "app"
    notes = (operator_notes or "").strip()
    db = _open_db(run_dir)
    try:
        hints = [normalize_relpath(str(p)) for p in (path_hints or []) if p]
        if not hints:
            # fall back from prior tasks / facts
            detail = cell_detail(run_dir, area_s, cls)
            hints = list(detail.get("path_hints") or [])[:15]
        payload = {
            "area": area_s,
            "class": cls,
            "path_hints": hints[:15],
            "force_depth": bool(force_depth),
            "operator_requested": True,
            "operator_reason": reason,
        }
        if notes:
            payload["operator_notes"] = notes[:4000]
        tid = db.enqueue_task("hunt", payload, priority=40)
        db.upsert_coverage_fact(
            area_s, cls, path=(hints[0] if hints else ""), visit_delta=0, last_depth="planned"
        )
        try:
            append_event(
                run_dir,
                {
                    "source": "dashboard",
                    "event": "operator_requeue",
                    "task_id": tid,
                    "area": area_s,
                    "class": cls,
                    "reason": reason,
                    "has_notes": bool(notes),
                },
            )
        except OSError:
            pass
        return {"ok": True, "task_id": tid, "payload": payload}
    finally:
        db.close()


def requeue_recon(
    run_dir: Path,
    *,
    operator_notes: str = "",
    focus_paths: Optional[list[str]] = None,
    include_prior_architecture: bool = True,
    enqueue_hunts: bool = True,
    reason: str = "operator_recon_rerun",
    agent_ids: Optional[list[str]] = None,
    hunt_skill_mode: Optional[str] = None,
    hunt_skill_ids: Optional[list[str]] = None,
) -> dict[str, Any]:
    """
    Enqueue recon task(s) with optional operator brief.

    Each selected recon agent becomes its own Ralph task (shared recon_batch_id
    when multiple). Prior architecture is included by default so the model can
    refine rather than start from zero. Results merge into one architecture map;
    hunts enqueue once when the batch completes.

    Optional ``hunt_skill_mode`` / ``hunt_skill_ids`` are stored on the recon
    payload and merged into run config so plan_hunt_tasks / request_hunt honor
    the operator selection for this re-run.
    """
    from vulnforge.stages.recon import (
        enqueue_recon_agent_tasks,
        resolve_recon_agent_ids,
    )

    notes = (operator_notes or "").strip()
    paths = [normalize_relpath(str(p)) for p in (focus_paths or []) if p][:40]
    agents = [str(a).strip().lower() for a in (agent_ids or []) if str(a).strip()][:32]
    db = _open_db(run_dir)
    try:
        row = db.get_run()
        if not row:
            return {"ok": False, "error": "no run"}
        # Generation for Audit Loop column: max existing recon gen + 1
        gen = 1
        try:
            for t in db.list_tasks(limit=500):
                if getattr(t, "kind", None) != "recon":
                    continue
                pl = t.payload if isinstance(t.payload, dict) else {}
                try:
                    g = int(pl.get("recon_generation") or 1)
                except (TypeError, ValueError):
                    g = 1
                if g >= gen:
                    gen = g + 1
        except Exception:
            gen = 1
        try:
            resolved = resolve_recon_agent_ids(agents or None)
        except Exception as e:
            return {"ok": False, "error": f"recon_agents: {e}"}
        if not resolved:
            return {"ok": False, "error": "no_recon_agents"}

        payload: dict[str, Any] = {
            "target": str(row["target_path"]),
            "operator_requested": True,
            "operator_reason": reason,
            "include_prior_architecture": bool(include_prior_architecture),
            "enqueue_hunts": bool(enqueue_hunts),
            "recon_generation": gen,
        }
        if notes:
            payload["operator_notes"] = notes[:6000]
        if paths:
            payload["focus_paths"] = paths

        # Hunt skill mode: persist on payload + run config when operator sets it
        mode_in = hunt_skill_mode
        ids_in = hunt_skill_ids
        if mode_in is not None or ids_in is not None:
            mode_s = str(mode_in or "all_active").strip().lower().replace("-", "_")
            if mode_s not in HUNT_SKILL_MODES:
                return {"ok": False, "error": f"invalid hunt_skill_mode: {mode_in}"}
            ids_list: list[str] = []
            if isinstance(ids_in, list):
                ids_list = [
                    str(x).strip().lower().replace("_", "-")
                    for x in ids_in
                    if str(x).strip()
                ][:64]
            payload["hunt_skill_mode"] = mode_s
            payload["hunt_skill_ids"] = ids_list
            try:
                cfg_now = get_run_config(db)
                run_sec = dict(cfg_now.get("run") or {})
                run_sec["hunt_skill_mode"] = mode_s
                run_sec["hunt_skill_ids"] = ids_list
                patch_run_config(db, {"run": run_sec})
            except Exception:
                pass

        # Priority 5: ahead of default recon (10) and hunts (40-50)
        task_ids = enqueue_recon_agent_tasks(
            db, payload, resolved, base_priority=5
        )
        tid = task_ids[0] if task_ids else None
        try:
            append_event(
                run_dir,
                {
                    "source": "dashboard",
                    "event": "operator_recon_rerun",
                    "task_id": tid,
                    "task_ids": task_ids,
                    "reason": reason,
                    "has_notes": bool(notes),
                    "focus_paths": paths[:10],
                    "include_prior_architecture": bool(include_prior_architecture),
                    "enqueue_hunts": bool(enqueue_hunts),
                    "agent_ids": resolved[:10],
                    "recon_agent_count": len(resolved),
                    "hunt_skill_mode": payload.get("hunt_skill_mode"),
                    "hunt_skill_ids": (payload.get("hunt_skill_ids") or [])[:20],
                },
            )
        except OSError:
            pass
        return {
            "ok": True,
            "task_id": tid,
            "task_ids": task_ids,
            "agent_ids": resolved,
            "payload": payload,
        }
    finally:
        db.close()


def _areas_from_architecture(db: Database) -> list[str]:
    arch = db.get_architecture() or {}
    areas: list[str] = []
    for c in arch.get("components") or []:
        if isinstance(c, dict) and c.get("name"):
            areas.append(str(c["name"]))
    inv = arch.get("inventory") if isinstance(arch.get("inventory"), dict) else {}
    for p in inv.get("dir_partitions") or []:
        if isinstance(p, dict) and p.get("dir"):
            d = str(p["dir"])
            if d not in areas:
                areas.append(d)
    for f in db.list_coverage_facts():
        a = f.get("area")
        if a and a not in areas:
            areas.append(str(a))
    if not areas:
        areas = ["app"]
    return areas[:24]


def _path_hints_for_area(db: Database, area: str) -> list[str]:
    arch = db.get_architecture() or {}
    for c in arch.get("components") or []:
        if isinstance(c, dict) and str(c.get("name")) == area:
            ph = c.get("path_hints") or []
            if isinstance(ph, list) and ph:
                return [normalize_relpath(str(x)) for x in ph if x][:15]
    inv = arch.get("inventory") if isinstance(arch.get("inventory"), dict) else {}
    samples = inv.get("entrypoints") or []
    under = [
        normalize_relpath(str(p))
        for p in samples
        if normalize_relpath(str(p)).startswith(area.rstrip("/") + "/")
        or normalize_relpath(str(p)) == area
    ]
    if under:
        return under[:15]
    # any fact path
    for f in db.list_coverage_facts():
        if f.get("area") == area and f.get("path"):
            return [f["path"]]
    return []


def _hints_for_path_target(run_dir: Path, path: str, is_dir: bool) -> list[str]:
    """Build path_hints for a folder/file chosen via the Coverage path picker."""
    rel = normalize_relpath(str(path or "").strip())
    if not rel or rel == ".":
        # Root folder: sample shallow files
        listing = target_list(run_dir, path=".", max_entries=40)
        if not listing.get("ok"):
            return []
        out: list[str] = []
        for e in listing.get("entries") or []:
            if not isinstance(e, dict) or e.get("is_dir"):
                continue
            name = str(e.get("name") or "")
            if name:
                out.append(name)
            if len(out) >= 15:
                break
        return out
    if not is_dir:
        return [rel]
    listing = target_list(run_dir, path=rel, max_entries=40)
    if not listing.get("ok"):
        return [rel]
    out = []
    for e in listing.get("entries") or []:
        if not isinstance(e, dict):
            continue
        name = str(e.get("name") or "")
        if not name:
            continue
        child = normalize_relpath(f"{rel}/{name}")
        if e.get("is_dir"):
            # one level deeper sample of files
            sub = target_list(run_dir, path=child, max_entries=12)
            if sub.get("ok"):
                for se in sub.get("entries") or []:
                    if isinstance(se, dict) and not se.get("is_dir") and se.get("name"):
                        out.append(normalize_relpath(f"{child}/{se['name']}"))
                        if len(out) >= 15:
                            return out
        else:
            out.append(child)
            if len(out) >= 15:
                break
    return out or [rel]


def apply_coverage_mode(
    run_dir: Path,
    *,
    mode: str,
    areas: Optional[list[str]] = None,
    classes: Optional[list[str]] = None,
    path_targets: Optional[list[dict[str, Any]]] = None,
    enqueue: bool = True,
) -> dict[str, Any]:
    """
    Set coverage policy and optionally enqueue hunts.

    - auto: store mode only (recon plan remains authority; no bulk enqueue)
    - all: enqueue active hunt profiles x discovered areas (capped)
    - select: enqueue user-selected areas / path targets x classes
    - path_targets: optional [{path, is_dir}] from Coverage explorer picker
    """
    mode_n = str(mode or "auto").lower()
    if mode_n not in ("auto", "all", "select"):
        return {"ok": False, "error": f"invalid mode: {mode}"}

    db = _open_db(run_dir)
    try:
        available = set(all_class_ids())
        cfg_now = get_run_config(db)
        skill_mode, skill_ids = skill_policy_from_run_cfg(cfg_now)
        # Run-scoped allowlist (all_active ≈ active_class_ids; other modes filter).
        # Empty is intentional (e.g. custom_only with no customs) — never re-expand
        # to the global active set (that would reintroduce seed skills).
        run_allowed = list(resolve_run_class_ids(skill_mode, skill_ids))
        run_allowed_set = set(run_allowed)
        active = list(run_allowed)
        raw_areas = [str(a).strip() for a in (areas or []) if str(a).strip()]
        sel_classes = [
            _normalize_class(c) for c in (classes or []) if str(c).strip()
        ]
        # validate skills against registered profiles
        sel_classes = [c for c in sel_classes if c in available]
        # mode=select is an operator override: any registered skill is allowed
        # (including inactive custom/generated). mode=all stays on run allowlist.
        if mode_n != "select":
            if skill_mode not in ("", "all_active") and run_allowed_set:
                sel_classes = [c for c in sel_classes if c in run_allowed_set]
            elif skill_mode not in ("", "all_active") and not run_allowed_set:
                sel_classes = []
        if not sel_classes and mode_n != "auto":
            # all: run allowlist; select: prefer active, else full catalog
            if mode_n == "select":
                sel_classes = list(active) if active else list(available)
            else:
                sel_classes = list(active)

        def _looks_like_path(s: str) -> bool:
            """Treat slashy names or file-like stems as path targets, not abstract areas."""
            t = (s or "").replace("\\", "/").strip()
            if not t or t in (".", "..") or ".." in t.split("/"):
                return False
            if "/" in t:
                return True
            # bare file.ext (e.g. main.py) — not multi-word abstract area names
            base = t.rsplit("/", 1)[-1]
            if "." in base and not base.startswith("."):
                ext = base.rsplit(".", 1)[-1]
                if 1 <= len(ext) <= 12 and ext.isalnum():
                    return True
            return False

        # Normalize path targets (folder/file from picker + path-like areas)
        norm_targets: list[dict[str, Any]] = []
        seen_paths: set[str] = set()

        def _add_path_target(path: str, is_dir: bool | None = None) -> None:
            p = normalize_relpath(str(path or "").strip())
            if not p or ".." in p.split("/") or p in seen_paths:
                return
            dir_flag = bool(is_dir) if is_dir is not None else False
            if is_dir is None:
                parent = "/".join(p.split("/")[:-1]) or "."
                name = p.split("/")[-1]
                listing = target_list(run_dir, path=parent, max_entries=300)
                if listing.get("ok"):
                    for e in listing.get("entries") or []:
                        if isinstance(e, dict) and e.get("name") == name:
                            dir_flag = bool(e.get("is_dir"))
                            break
                else:
                    # Heuristic: no extension → treat as folder area path
                    dir_flag = "." not in name or name.startswith(".")
            seen_paths.add(p)
            norm_targets.append({"path": p, "is_dir": dir_flag})

        for raw in path_targets or []:
            if not isinstance(raw, dict):
                # bare string path
                if isinstance(raw, str) and raw.strip():
                    _add_path_target(raw.strip(), None)
                continue
            p = str(raw.get("path") or "").strip()
            if not p:
                continue
            if "is_dir" in raw:
                _add_path_target(p, bool(raw.get("is_dir")))
            else:
                _add_path_target(p, None)

        # Split free-text / selected areas into abstract names vs file paths
        sel_areas: list[str] = []
        for a in raw_areas:
            if _looks_like_path(a):
                _add_path_target(a, None)
            else:
                if a not in sel_areas:
                    sel_areas.append(a)

        path_area_names = [t["path"] for t in norm_targets]
        policy = {
            "mode": mode_n,
            "areas": sel_areas + [a for a in path_area_names if a not in sel_areas],
            # select: operator picks any registered skill; all/auto use run allowlist
            "classes": (
                sel_classes if mode_n == "select" else list(active)
            ),
            "path_targets": norm_targets,
        }
        cfg = patch_run_config(db, {"coverage_policy": policy})

        enqueued: list[dict[str, Any]] = []
        use_areas: list[str] = []
        use_classes: list[str] = []
        # (area, path_hints) units to enqueue
        units: list[tuple[str, list[str]]] = []

        if enqueue and mode_n in ("all", "select"):
            if mode_n == "all":
                use_areas = _areas_from_architecture(db)
                # Respect run hunt_skill_mode (empty → no bulk enqueue)
                use_classes = list(run_allowed)
                for area in use_areas:
                    units.append((area, _path_hints_for_area(db, area)))
            else:
                use_classes = sel_classes or list(available)
                # Architecture / named abstract areas
                for area in sel_areas:
                    units.append((area, _path_hints_for_area(db, area)))
                # Path targets (picker + path-like custom areas)
                for pt in norm_targets:
                    area = str(pt["path"])
                    hints = _hints_for_path_target(
                        run_dir, area, bool(pt.get("is_dir"))
                    )
                    units.append((area, hints))
                # Fallback if nothing selected
                if not units:
                    use_areas = _areas_from_architecture(db)
                    for area in use_areas:
                        units.append((area, _path_hints_for_area(db, area)))
                else:
                    use_areas = [u[0] for u in units]

            # Cap total new tasks by run.max_tasks (operator setting); no fixed 40 ceiling
            try:
                max_new = int((cfg.get("run") or {}).get("max_tasks") or 50)
            except (TypeError, ValueError):
                max_new = 50
            max_new = max(1, max_new)
            seen_pair: set[tuple[str, str]] = set()
            for area, hints in units:
                for cls in use_classes:
                    if len(enqueued) >= max_new:
                        break
                    key = (area, cls)
                    if key in seen_pair:
                        continue
                    seen_pair.add(key)
                    ph = list(hints or [])[:15]
                    payload = {
                        "area": area,
                        "class": cls,
                        "path_hints": ph,
                        "force_depth": True,
                        "operator_requested": True,
                        "operator_reason": f"coverage_mode_{mode_n}",
                    }
                    if ph and (
                        any("/" in h or h.endswith((".py", ".js", ".ts", ".go", ".rs")) for h in ph)
                        or area in ph
                    ):
                        payload["operator_reason"] = f"coverage_mode_{mode_n}_path"
                    tid = db.enqueue_task("hunt", payload, priority=48)
                    db.upsert_coverage_fact(
                        area,
                        cls,
                        path=(ph[0] if ph else ""),
                        visit_delta=0,
                        last_depth="planned",
                    )
                    enqueued.append(
                        {
                            "task_id": tid,
                            "area": area,
                            "class": cls,
                            "path_hints": ph,
                        }
                    )
                if len(enqueued) >= max_new:
                    break

        try:
            append_event(
                run_dir,
                {
                    "source": "dashboard",
                    "event": "coverage_mode",
                    "mode": mode_n,
                    "enqueued": len(enqueued),
                    "areas": use_areas or policy.get("areas") or [],
                    "path_targets": [t.get("path") for t in norm_targets],
                },
            )
        except OSError:
            pass

        return {
            "ok": True,
            "policy": coverage_policy_from_config(cfg),
            "enqueued": enqueued,
            "enqueued_count": len(enqueued),
            "path_targets": norm_targets,
        }
    finally:
        db.close()


# Hard ceiling for MAX Hunt fan-out (safety; UI also confirms).
MAX_MAX_HUNT_HARD = 200


def _run_target_and_ignore(db: Database, run_dir: Path) -> tuple[Optional[Path], list[str]]:
    """Return (target_path, ignore globs) from run row / config."""
    row = db.get_run()
    if not row:
        return None, []
    target = Path(str(row["target_path"] or "")).resolve()
    if not target.is_dir():
        return None, []
    cfg = get_run_config(db)
    ignore: list[str] = []
    tools = cfg.get("tools") if isinstance(cfg.get("tools"), dict) else {}
    inv = tools.get("file_inventory") if isinstance(tools.get("file_inventory"), dict) else {}
    raw = inv.get("ignore") or cfg.get("ignore") or []
    if isinstance(raw, list):
        ignore = [str(x) for x in raw if str(x).strip()]
    elif isinstance(raw, str) and raw.strip():
        ignore = [raw.strip()]
    return target, ignore


def _norm_path_targets(
    run_dir: Path,
    path_targets: Optional[list[Any]],
) -> list[dict[str, Any]]:
    """Normalize path_targets list to [{path, is_dir}]."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in path_targets or []:
        if isinstance(raw, dict):
            p = normalize_relpath(str(raw.get("path") or "").strip())
            is_dir = bool(raw.get("is_dir")) if "is_dir" in raw else None
        else:
            p = normalize_relpath(str(raw or "").strip())
            is_dir = None
        if not p or ".." in p.split("/") or p in seen:
            continue
        if is_dir is None:
            parent = "/".join(p.split("/")[:-1]) or "."
            name = p.split("/")[-1]
            listing = target_list(run_dir, path=parent, max_entries=300)
            is_dir = False
            if listing.get("ok"):
                for e in listing.get("entries") or []:
                    if isinstance(e, dict) and e.get("name") == name:
                        is_dir = bool(e.get("is_dir"))
                        break
            else:
                is_dir = "." not in name or name.startswith(".")
        seen.add(p)
        out.append({"path": p, "is_dir": bool(is_dir)})
    return out


def _path_hints_union(
    run_dir: Path,
    areas: Optional[list[str]],
    path_targets: Optional[list[Any]],
) -> tuple[str, list[str], list[dict[str, Any]]]:
    """Combine areas + path targets into (primary_area, path_hints, norm_targets)."""
    norm = _norm_path_targets(run_dir, path_targets)
    hints: list[str] = []
    for pt in norm:
        for h in _hints_for_path_target(run_dir, pt["path"], bool(pt.get("is_dir"))):
            if h not in hints:
                hints.append(h)
            if len(hints) >= 24:
                break
        if len(hints) >= 24:
            break
    area_list = [str(a).strip() for a in (areas or []) if str(a).strip()]
    for a in area_list:
        if a not in hints and not any(a == t["path"] for t in norm):
            # abstract area name — leave for area field only
            pass
    primary = ""
    if norm:
        primary = str(norm[0]["path"])
    elif area_list:
        primary = area_list[0]
    else:
        primary = "app"
    # Prefer file path as area when single path target
    if len(norm) == 1:
        primary = norm[0]["path"]
    elif area_list:
        primary = area_list[0]
    return primary, hints[:24], norm


def coverage_generate_skill(
    run_dir: Path,
    *,
    brief: str,
    suggested_id: str = "",
    activate: bool = False,
    enqueue_hunts: bool = True,
    areas: Optional[list[str]] = None,
    path_targets: Optional[list[Any]] = None,
    reason: str = "coverage_generate_skill",
) -> dict[str, Any]:
    """
    Enqueue a Ralph ``generate_skill`` task for Coverage (async LLM).

    Does not call the model in-process — operator must Start/Resume Ralph.
    """
    notes = (brief or "").strip()
    if not notes:
        return {"ok": False, "error": "brief is required"}

    db = _open_db(run_dir)
    try:
        row = db.get_run()
        if not row:
            return {"ok": False, "error": "no run"}
        primary_area, path_hints, norm_targets = _path_hints_union(
            run_dir, areas, path_targets
        )
        # Fold checked areas into path_hints when they look like paths
        for a in areas or []:
            s = str(a).strip().replace("\\", "/")
            if not s:
                continue
            if ("/" in s or "." in s.rsplit("/", 1)[-1]) and s not in path_hints:
                path_hints.append(s)
        path_hints = path_hints[:24]

        payload: dict[str, Any] = {
            "brief": notes[:6000],
            "operator_brief": notes[:6000],
            "activate": bool(activate),
            "enqueue_hunts": bool(enqueue_hunts),
            "area": primary_area or "app",
            "path_hints": path_hints,
            "path_targets": norm_targets,
            "reason": reason or "coverage_generate_skill",
            "operator_requested": True,
        }
        sid = str(suggested_id or "").strip()
        if sid:
            payload["suggested_id"] = sid[:64]

        # Prefer higher priority than bulk hunts so generate runs soon
        tid = db.enqueue_task("generate_skill", payload, priority=25)
        try:
            append_event(
                run_dir,
                {
                    "source": "dashboard",
                    "event": "coverage_generate_skill",
                    "task_id": tid,
                    "enqueue_hunts": bool(enqueue_hunts),
                    "activate": bool(activate),
                    "path_targets": [t.get("path") for t in norm_targets][:20],
                    "areas": [str(a) for a in (areas or [])][:20],
                },
            )
        except OSError:
            pass
        return {
            "ok": True,
            "task_id": tid,
            "enqueue_hunts": bool(enqueue_hunts),
            "activate": bool(activate),
            "area": payload["area"],
            "path_hints": path_hints,
            "path_targets": norm_targets,
            "message": (
                f"Queued generate_skill #{tid}. "
                "Start/Resume Ralph to author the skill"
                + (" and enqueue hunt(s)." if enqueue_hunts else ".")
            ),
        }
    finally:
        db.close()


def _max_hunt_file_list(
    run_dir: Path,
    *,
    scope: str = "all",
    path_targets: Optional[list[Any]] = None,
    max_files: int = 50,
) -> dict[str, Any]:
    """Resolve capped source-file list for MAX Hunt (preview + enqueue)."""
    from vulnforge.strategies import list_source_files

    db = _open_db(run_dir)
    try:
        target, ignore = _run_target_and_ignore(db, run_dir)
        if target is None:
            return {"ok": False, "error": "target missing or no run"}
        cfg = get_run_config(db)
        try:
            max_tasks = max(1, int((cfg.get("run") or {}).get("max_tasks") or 50))
        except (TypeError, ValueError):
            max_tasks = 50
        try:
            want = int(max_files) if max_files is not None else max_tasks
        except (TypeError, ValueError):
            want = max_tasks
        want = max(1, want)
        hard = MAX_MAX_HUNT_HARD
        cap = min(want, max_tasks, hard)

        scope_n = str(scope or "all").strip().lower()
        if scope_n not in ("all", "paths"):
            scope_n = "all"

        files: list[str] = []
        if scope_n == "paths":
            norm = _norm_path_targets(run_dir, path_targets)
            if not norm:
                return {
                    "ok": False,
                    "error": "scope=paths requires path_targets",
                    "file_count": 0,
                    "files": [],
                    "capped_to": cap,
                }
            # Expand folders to source files; keep files as-is
            all_src = list_source_files(target, ignore=ignore)
            all_set = set(all_src)
            picked: list[str] = []
            for pt in norm:
                p = pt["path"]
                if pt.get("is_dir"):
                    # Target root: all source files
                    if p in (".", ""):
                        for f in all_src:
                            if f not in picked:
                                picked.append(f)
                        continue
                    prefix = p.rstrip("/") + "/"
                    for f in all_src:
                        if f == p or f.startswith(prefix):
                            if f not in picked:
                                picked.append(f)
                else:
                    # exact file or any source under that path
                    if p in all_set:
                        if p not in picked:
                            picked.append(p)
                    else:
                        # allow non-indexed path if it exists as file
                        if (target / p).is_file() and p not in picked:
                            picked.append(p)
            files = picked
        else:
            files = list_source_files(target, ignore=ignore)

        total = len(files)
        files_capped = files[:cap]
        return {
            "ok": True,
            "scope": scope_n,
            "file_count": total,
            "files": files_capped,
            "files_sample": files_capped[:20],
            "capped_to": cap,
            "max_tasks": max_tasks,
            "max_files_requested": want,
            "hard_ceiling": hard,
            "estimated_generate_tasks": len(files_capped),
            "estimated_hunts": len(files_capped),  # one hunt per generate when enqueue_hunts
            "truncated": total > cap,
            "target": str(target),
        }
    finally:
        db.close()


def preview_max_hunt(
    run_dir: Path,
    *,
    scope: str = "all",
    path_targets: Optional[list[Any]] = None,
    max_files: int = 50,
) -> dict[str, Any]:
    """Dry-run MAX Hunt file enumeration (no enqueue)."""
    return _max_hunt_file_list(
        run_dir, scope=scope, path_targets=path_targets, max_files=max_files
    )


def enqueue_max_hunt(
    run_dir: Path,
    *,
    scope: str = "all",
    path_targets: Optional[list[Any]] = None,
    max_files: int = 50,
    operator_notes: str = "",
    activate: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Enqueue one ``generate_skill`` (enqueue_hunts=true) per source file for MAX Hunt.

    activate defaults False so bulk does not rewrite Dev active set.
    Skills are saved as source=generated (inactive); hunts use class_body_override.
    """
    preview = _max_hunt_file_list(
        run_dir, scope=scope, path_targets=path_targets, max_files=max_files
    )
    if not preview.get("ok"):
        return preview
    if dry_run:
        return {**preview, "dry_run": True, "enqueued_generate": 0, "task_ids": []}

    files: list[str] = list(preview.get("files") or [])
    if not files:
        return {
            **preview,
            "ok": False,
            "error": "no source files matched scope",
            "enqueued_generate": 0,
            "task_ids": [],
        }

    notes = (operator_notes or "").strip()
    arch_summary = ""
    db = _open_db(run_dir)
    try:
        arch = db.get_architecture() or {}
        if isinstance(arch, dict):
            arch_summary = str(arch.get("summary") or "").strip()[:600]

        task_ids: list[int] = []
        from vulnforge.hunt_profiles.generate import slugify_profile_id

        for rel in files:
            rel_n = normalize_relpath(rel)
            parts = rel_n.split("/")
            area = parts[0] if len(parts) > 1 else rel_n
            # Slug from path for suggested skill id
            base = rel_n.replace("/", "-").replace(".", "-")
            suggested = slugify_profile_id(base, fallback="file-hunt")
            brief_parts = [
                f"Author a focused hunt skill for the single source file `{rel_n}` only.",
                "Map sinks, trust edges, input surfaces, and abuse cases in this file "
                "and its direct callees/callers when needed.",
                "Do not expand into unrelated modules except for minimal context.",
            ]
            if arch_summary:
                brief_parts.append(f"Architecture context: {arch_summary}")
            if notes:
                brief_parts.append(f"Operator notes: {notes}")
            brief = "\n".join(brief_parts)
            payload: dict[str, Any] = {
                "brief": brief[:6000],
                "operator_brief": brief[:6000],
                "suggested_id": suggested,
                "activate": bool(activate),
                "enqueue_hunts": True,
                "area": area,
                "path_hints": [rel_n],
                "path_targets": [{"path": rel_n, "is_dir": False}],
                "reason": "coverage_max_hunt",
                "operator_requested": True,
                "max_hunts": 1,
            }
            tid = db.enqueue_task("generate_skill", payload, priority=28)
            task_ids.append(int(tid))

        try:
            append_event(
                run_dir,
                {
                    "source": "dashboard",
                    "event": "coverage_max_hunt",
                    "enqueued_generate": len(task_ids),
                    "scope": preview.get("scope"),
                    "capped_to": preview.get("capped_to"),
                    "file_count": preview.get("file_count"),
                    "activate": bool(activate),
                    "task_ids": task_ids[:50],
                },
            )
        except OSError:
            pass

        return {
            **preview,
            "ok": True,
            "dry_run": False,
            "enqueued_generate": len(task_ids),
            "task_ids": task_ids,
            "activate": bool(activate),
            "message": (
                f"Queued {len(task_ids)} generate_skill task(s) "
                f"(~{len(task_ids)} hunts after generation). "
                "Start/Resume Ralph. Generated skills default inactive in Dev."
            ),
        }
    finally:
        db.close()


def target_list(run_dir: Path, path: str = ".", max_entries: int = 200) -> dict[str, Any]:
    db = _open_db(run_dir)
    try:
        row = db.get_run()
        if not row:
            return {"ok": False, "error": "no run"}
        target = Path(row["target_path"])
        if not target.is_dir():
            return {"ok": False, "error": "target missing"}
        ctx = {"target_root": str(target), "cfg": get_run_config(db) or {}, "session": {}}
        return tool_list_dir(ctx, path=path or ".", max_entries=max_entries)
    finally:
        db.close()


def target_read(
    run_dir: Path,
    path: str,
    start_line: Optional[int] = None,
    end_line: Optional[int] = None,
) -> dict[str, Any]:
    db = _open_db(run_dir)
    try:
        row = db.get_run()
        if not row:
            return {"ok": False, "error": "no run"}
        target = Path(row["target_path"])
        ctx = {"target_root": str(target), "cfg": get_run_config(db) or {}, "session": {}}
        return tool_read_file(
            ctx, path=path, start_line=start_line, end_line=end_line
        )
    finally:
        db.close()


def hunt_from_selection(
    run_dir: Path,
    *,
    path: str,
    start_line: Optional[int] = None,
    end_line: Optional[int] = None,
    attack_class: str = "wildcard",
    area: Optional[str] = None,
    note: str = "",
    operator_notes: str = "",
) -> dict[str, Any]:
    """Enqueue a focused hunt on an operator-selected file/range."""
    rel = normalize_relpath(path)
    if not rel or ".." in rel.split("/"):
        return {"ok": False, "error": "invalid path"}
    cls = _normalize_class(attack_class or "wildcard")
    # area: first path component or operator override
    area_s = (area or "").strip() or (rel.split("/")[0] if "/" in rel else "selection")
    notes = (operator_notes or note or "").strip()

    snippet = ""
    read = target_read(run_dir, rel, start_line=start_line, end_line=end_line)
    if read.get("ok"):
        snippet = (read.get("content") or "")[:2000]

    db = _open_db(run_dir)
    try:
        # Validate path is under target
        row = db.get_run()
        if not row:
            return {"ok": False, "error": "no run"}
        try:
            resolve_target_path(Path(row["target_path"]), rel)
        except (PermissionError, OSError) as e:
            return {"ok": False, "error": str(e)}

        payload = {
            "area": area_s,
            "class": cls,
            "path_hints": [rel],
            "force_depth": True,
            "operator_requested": True,
            "operator_reason": "selection_hunt",
            "selection": {
                "path": rel,
                "start_line": start_line,
                "end_line": end_line,
                "note": (note or "")[:500],
                "snippet_preview": snippet[:800],
            },
        }
        if notes:
            payload["operator_notes"] = notes[:4000]
        tid = db.enqueue_task("hunt", payload, priority=35)
        db.upsert_coverage_fact(
            area_s, cls, path=rel, visit_delta=0, last_depth="planned"
        )
        try:
            append_event(
                run_dir,
                {
                    "source": "dashboard",
                    "event": "selection_hunt",
                    "task_id": tid,
                    "path": rel,
                    "class": cls,
                    "start_line": start_line,
                    "end_line": end_line,
                },
            )
        except OSError:
            pass
        return {"ok": True, "task_id": tid, "payload": payload}
    finally:
        db.close()


def architecture_summary(arch: Optional[dict]) -> dict[str, Any]:
    """Compact fields for Overview Architecture tab."""
    if not arch:
        return {
            "summary": "",
            "components": [],
            "trust_boundaries": [],
            "input_surfaces": [],
            "hunt_focus": [],
            "has_architecture": False,
            "recon_agents_run": [],
        }
    comps = arch.get("components") if isinstance(arch.get("components"), list) else []
    agents_run = arch.get("recon_agents_run")
    if not isinstance(agents_run, list):
        agents_run = []
    return {
        "summary": str(arch.get("summary") or "")[:4000],
        "components": [
            {
                "name": c.get("name") if isinstance(c, dict) else str(c),
                "path_hints": (c.get("path_hints") if isinstance(c, dict) else None) or [],
                "role": (c.get("role") if isinstance(c, dict) else None) or "",
            }
            for c in comps[:40]
            if c
        ],
        "trust_boundaries": list(arch.get("trust_boundaries") or [])[:30]
        if isinstance(arch.get("trust_boundaries"), list)
        else [],
        "input_surfaces": list(arch.get("input_surfaces") or [])[:30]
        if isinstance(arch.get("input_surfaces"), list)
        else [],
        "hunt_focus": list(arch.get("hunt_focus") or [])[:40]
        if isinstance(arch.get("hunt_focus"), list)
        else [],
        "has_architecture": True,
        "inventory": arch.get("inventory")
        if isinstance(arch.get("inventory"), dict)
        else {},
        "recon_agents_run": [
            {
                "id": a.get("id") if isinstance(a, dict) else str(a),
                "ok": (a.get("ok") if isinstance(a, dict) else None),
                "title": (a.get("title") if isinstance(a, dict) else None) or "",
            }
            for a in agents_run[:24]
            if a
        ],
    }


# ---------------------------------------------------------------------------
# Host filesystem browse (New audit path picker — local dashboard only)
# ---------------------------------------------------------------------------

_FS_BROWSE_MAX_ENTRIES = 400
_HIDDEN_NAME_PREFIXES = (".", "$")


def list_fs_roots() -> list[dict[str, Any]]:
    """Top-level browse roots: Windows drive letters, or / and home on POSIX."""
    import os
    import string
    import sys

    roots: list[dict[str, Any]] = []
    if sys.platform == "win32":
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.isdir(drive):
                roots.append(
                    {
                        "name": f"{letter}:",
                        "path": drive,
                        "is_dir": True,
                        "is_file": False,
                    }
                )
    else:
        roots.append({"name": "/", "path": "/", "is_dir": True, "is_file": False})
        home = Path.home()
        if home.is_dir():
            roots.append(
                {
                    "name": str(home),
                    "path": str(home),
                    "is_dir": True,
                    "is_file": False,
                }
            )
    # Always include user Desktop when present (common start point)
    try:
        desk = Path.home() / "Desktop"
        if desk.is_dir():
            roots.append(
                {
                    "name": "Desktop",
                    "path": str(desk.resolve()),
                    "is_dir": True,
                    "is_file": False,
                }
            )
    except OSError:
        pass
    # de-dupe by path
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for r in roots:
        key = r["path"].lower() if sys.platform == "win32" else r["path"]
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def browse_host_fs(
    path: str = "",
    *,
    mode: str = "dirs",
) -> dict[str, Any]:
    """
    List a host directory for the New audit path picker.

    mode:
      - dirs: directories only (target tree)
      - any: directories + files (docs path)

    Empty path returns roots (drives / home).
    """
    import sys

    mode_n = (mode or "dirs").lower()
    if mode_n not in ("dirs", "any"):
        mode_n = "dirs"

    raw = (path or "").strip()
    if not raw:
        return {
            "ok": True,
            "path": "",
            "parent": None,
            "is_root": True,
            "entries": list_fs_roots(),
            "mode": mode_n,
        }

    try:
        p = Path(raw).expanduser()
        # Resolve carefully: allow non-existing intermediate typing, but require exists
        if not p.exists():
            return {"ok": False, "error": f"path does not exist: {raw}", "path": raw}
        if p.is_file():
            # Browse parent when a file path is given
            parent = p.parent
            return {
                "ok": True,
                "path": str(parent.resolve()),
                "parent": str(parent.parent.resolve()) if parent.parent != parent else None,
                "is_root": False,
                "selected_file": str(p.resolve()),
                "entries": _list_dir_entries(parent, mode_n),
                "mode": mode_n,
            }
        if not p.is_dir():
            return {"ok": False, "error": f"not a directory: {raw}", "path": raw}
        resolved = p.resolve()
        parent = resolved.parent
        parent_s = None
        if parent != resolved:
            parent_s = str(parent)
        elif sys.platform == "win32":
            # At drive root, parent may equal path; offer roots via empty parent
            parent_s = ""
        return {
            "ok": True,
            "path": str(resolved),
            "parent": parent_s,
            "is_root": False,
            "entries": _list_dir_entries(resolved, mode_n),
            "mode": mode_n,
        }
    except OSError as e:
        return {"ok": False, "error": str(e), "path": raw}


def _list_dir_entries(directory: Path, mode: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    try:
        children = list(directory.iterdir())
    except OSError:
        return []
    # dirs first, then files
    def sort_key(c: Path) -> tuple:
        try:
            is_d = c.is_dir()
        except OSError:
            is_d = False
        return (0 if is_d else 1, c.name.lower())

    for child in sorted(children, key=sort_key):
        name = child.name
        if name in (".", ".."):
            continue
        # skip obvious noise / reparse points that blow up
        if name.startswith(_HIDDEN_NAME_PREFIXES) and name not in (".github",):
            # still show .github as useful for docs sometimes
            if not (mode == "any" and name in (".github", ".well-known")):
                continue
        try:
            is_dir = child.is_dir()
            is_file = child.is_file()
        except OSError:
            continue
        if mode == "dirs" and not is_dir:
            continue
        if mode == "any" and not (is_dir or is_file):
            continue
        try:
            full = str(child.resolve())
        except OSError:
            full = str(child)
        entries.append(
            {
                "name": name,
                "path": full,
                "is_dir": is_dir,
                "is_file": is_file,
            }
        )
        if len(entries) >= _FS_BROWSE_MAX_ENTRIES:
            break
    return entries


# ---------------------------------------------------------------------------
# Human review of findings (confirm / reject / reclassify + notes)
# ---------------------------------------------------------------------------

_REVIEW_ACTIONS = {
    "confirm": "confirmed",
    "accept": "confirmed",
    "reject": "rejected_human",
    "needs_human": "needs_human",
    "reopen": "needs_human",
}

_REVIEWABLE_STATES = frozenset(
    {
        "candidate",
        "needs_human",
        "confirmed",
        "rejected_mech",
        "rejected_llm",
        "rejected_human",
        "superseded",
    }
)


def review_finding(
    run_dir: Path,
    finding_id: int,
    *,
    action: str,
    notes: str = "",
    write_note_to_evidence: bool = True,
    operator: str = "operator",
) -> dict[str, Any]:
    """
    Human review / reclassification of a finding.

    Flow (automation):
      candidate -> validate_mech -> rejected_mech | needs_human
      [optional validate_llm may set rejected_llm or keep needs_human]

    Flow (human):
      needs_human | confirmed | rejected_* -> confirm | reject | needs_human
      Optional notes are stored on the finding body and optionally written under
      evidence/<pack>/human_review_*.md
    """
    act = str(action or "").strip().lower()
    if act not in _REVIEW_ACTIONS:
        return {
            "ok": False,
            "error": f"invalid action: {action!r}; use confirm|reject|needs_human",
        }
    new_state = _REVIEW_ACTIONS[act]
    notes_s = (notes or "").strip()
    if len(notes_s) > 20000:
        notes_s = notes_s[:20000] + "\n...[truncated]"

    db = _open_db(run_dir)
    try:
        finding = db.get_finding(int(finding_id))
        if not finding:
            return {"ok": False, "error": "finding_not_found"}
        if finding.state not in _REVIEWABLE_STATES:
            return {
                "ok": False,
                "error": f"finding state {finding.state!r} is not reviewable",
            }

        from vulnforge.util import utc_now_iso

        now = utc_now_iso()
        prev = finding.state
        body = dict(finding.body or {})
        history = body.get("human_review")
        if not isinstance(history, list):
            history = []

        note_rel: Optional[str] = None
        pack_id = finding.evidence_id or body.get("evidence_id")
        if write_note_to_evidence and notes_s:
            if not pack_id:
                pack_id = f"human-{finding.id}"
                body["evidence_id"] = pack_id
            try:
                from vulnforge.tools.evidence_write import sanitize_evidence_id

                eid = sanitize_evidence_id(str(pack_id))
                pack_dir = run_dir / "evidence" / eid
                pack_dir.mkdir(parents=True, exist_ok=True)
                stamp = now.replace(":", "").replace("-", "")[:15]
                note_rel = f"human_review_{stamp}.md"
                title = body.get("title") or f"Finding #{finding.id}"
                content = (
                    f"# Human review note\n\n"
                    f"- finding_id: {finding.id}\n"
                    f"- previous_state: {prev}\n"
                    f"- action: {act}\n"
                    f"- new_state: {new_state}\n"
                    f"- operator: {operator}\n"
                    f"- at: {now}\n\n"
                    f"## Notes\n\n{notes_s}\n"
                )
                (pack_dir / note_rel).write_text(content, encoding="utf-8")
                pack_id = eid
            except Exception as e:  # noqa: BLE001 — keep review even if note write fails
                note_rel = None
                body.setdefault("validation_reasons", [])
                if isinstance(body["validation_reasons"], list):
                    body["validation_reasons"].append(f"human_note_write_failed:{e}")

        entry = {
            "at": now,
            "operator": operator,
            "action": act,
            "from_state": prev,
            "to_state": new_state,
            "notes": notes_s or None,
            "note_relpath": note_rel,
        }
        history.append(entry)
        # keep last 50 reviews
        body["human_review"] = history[-50:]
        body["human_review_latest"] = entry

        if new_state == "needs_human":
            body["needs_human"] = True
        else:
            body.pop("needs_human", None)

        if new_state == "rejected_human" and notes_s:
            reasons = body.get("validation_reasons")
            if not isinstance(reasons, list):
                reasons = []
            tag = f"human_reject:{notes_s[:200]}"
            if tag not in reasons:
                reasons.append(tag)
            body["validation_reasons"] = reasons

        eid_col = pack_id or finding.evidence_id
        db.conn.execute(
            """
            UPDATE findings
            SET state=?, body_json=?, evidence_id=?, updated_at=?
            WHERE id=?
            """,
            (new_state, json.dumps(body), eid_col, now, finding.id),
        )
        db.conn.commit()

        append_event(
            run_dir,
            {
                "source": "dashboard",
                "event": "human_review",
                "finding_id": finding.id,
                "from_state": prev,
                "to_state": new_state,
                "action": act,
                "has_notes": bool(notes_s),
                "note_relpath": note_rel,
            },
        )
        return {
            "ok": True,
            "finding_id": finding.id,
            "from_state": prev,
            "to_state": new_state,
            "action": act,
            "evidence_id": eid_col,
            "note_relpath": note_rel,
            "finding": {
                "id": finding.id,
                "state": new_state,
                "stable_key": finding.stable_key,
                "evidence_id": eid_col,
                "body": body,
            },
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Develop POC (operator scaffold + optional agent enqueue)
# ---------------------------------------------------------------------------

POC_DEVELOP_RELPATH = "poc_develop.md"

# Runnable PoC extensions surfaced in the POC workshop / finding body.
POC_CODE_EXTS = frozenset({".py", ".sh", ".ps1", ".c", ".go", ".js", ".rb", ".rs"})


def _poc_code_files_from_names(names: list[str]) -> list[str]:
    out: list[str] = []
    for n in names or []:
        base = Path(str(n)).name
        if Path(base).suffix.lower() in POC_CODE_EXTS:
            out.append(base)
    return sorted(set(out))


def _poc_pack_id(finding) -> str:
    body = finding.body or {}
    pack = finding.evidence_id or body.get("evidence_id")
    if pack:
        return str(pack)
    return f"human-{finding.id}"


def _list_pack_files(run_dir: Path, eid: str) -> list[str]:
    pack_dir = run_dir / "evidence" / eid
    if not pack_dir.is_dir():
        return []
    names: list[str] = []
    try:
        for p in sorted(pack_dir.iterdir()):
            if p.is_file() and not p.name.endswith(".tmp"):
                names.append(p.name)
    except OSError:
        return []
    return names


def build_poc_scaffold(
    finding,
    *,
    pack_files: Optional[list[str]] = None,
) -> str:
    """Markdown hub template for working-code PoC development (not exploit proof)."""
    body = dict(finding.body or {})
    tm = body.get("threat_model") if isinstance(body.get("threat_model"), dict) else {}
    cites = body.get("citations") if isinstance(body.get("citations"), list) else []
    cite_lines: list[str] = []
    for c in cites:
        if not isinstance(c, dict) or not c.get("path"):
            continue
        line = str(c.get("path"))
        if c.get("start_line") is not None:
            line += f":{c.get('start_line')}"
            if c.get("end_line") is not None and c.get("end_line") != c.get("start_line"):
                line += f"-{c.get('end_line')}"
        if c.get("symbol"):
            line += f" ({c.get('symbol')})"
        cite_lines.append(f"- `{line}`")
    if not cite_lines and body.get("sink_path"):
        cite_lines.append(f"- `{body.get('sink_path')}`")
    prior = pack_files or []
    prior_other = [n for n in prior if n != POC_DEVELOP_RELPATH]
    prior_block = (
        "\n".join(f"- `{n}`" for n in prior_other)
        if prior_other
        else "_(none yet)_"
    )
    title = body.get("title") or finding.stable_key or f"Finding #{finding.id}"
    parts = [
        f"# PoC development: {title}",
        "",
        f"- **finding_id:** {finding.id}",
        f"- **state:** {finding.state}",
        f"- **weakness_class:** {body.get('weakness_class') or '-'}",
        f"- **severity_claim:** {body.get('severity_claim') or '-'}",
        f"- **stable_key:** `{finding.stable_key or '-'}`",
        "",
        "## Threat model",
        "",
        f"- **Attacker:** {tm.get('attacker') or '-'}",
        f"- **Boundary:** {tm.get('boundary') or '-'}",
        f"- **Impact:** {tm.get('impact') or '-'}",
        "",
        "## Summary",
        "",
        str(body.get("summary") or "_No summary._"),
        "",
        "## Citations",
        "",
        "\n".join(cite_lines) if cite_lines else "_(none)_",
        "",
        "## Prior evidence pack files",
        "",
        prior_block,
        "",
        "## How to run",
        "",
        "_Deps, env vars, host/port/URL, and the exact command to run the script "
        "(e.g. `python poc.py --url http://127.0.0.1:8000`)._",
        "",
        "Optional manual steps:",
        "",
        "1. ",
        "2. ",
        "",
        "## Working PoC code",
        "",
        "_Prefer a separate pack file: `poc.py`, `poc.sh`, `poc.ps1`, or `poc.c`. "
        "The agent should write that file via `write_evidence` and only keep this "
        "hub as run instructions. Inline code is fine for small probes:_",
        "",
        "```python",
        "# TODO: runnable probe or exploit sketch",
        "",
        "```",
        "",
        "## Expected signal",
        "",
        "_What observable output proves the issue (status code, body marker, crash)?_",
        "",
        "## Residual risk / mitigations",
        "",
        "_What would block or reduce exploitability? Note: agent did not execute this PoC._",
        "",
        "---",
        "",
        "_This document is a run hub for human review. "
        "Saving it does **not** accept the finding; "
        "`confirmed` is human-only and is not exploit proof._",
        "",
    ]
    return "\n".join(parts)


def get_finding_poc(run_dir: Path, finding_id: int) -> dict[str, Any]:
    """Load current PoC draft (existing file or scaffold). Side-effect free."""
    db = _open_db(run_dir)
    try:
        finding = db.get_finding(int(finding_id))
        if not finding:
            return {"ok": False, "error": "finding_not_found"}
        from vulnforge.tools.evidence_write import sanitize_evidence_id

        raw_pack = _poc_pack_id(finding)
        try:
            eid = sanitize_evidence_id(str(raw_pack))
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"invalid evidence_id: {e}"}
        pack_files = _list_pack_files(run_dir, eid)
        body = dict(finding.body or {})
        path = run_dir / "evidence" / eid / POC_DEVELOP_RELPATH
        exists = path.is_file()
        if exists:
            try:
                content = path.read_text(encoding="utf-8")
            except OSError as e:
                return {"ok": False, "error": f"read failed: {e}"}
            scaffolded = False
        else:
            content = build_poc_scaffold(finding, pack_files=pack_files)
            scaffolded = True
        code_from_disk = _poc_code_files_from_names(pack_files)
        body_codes = body.get("poc_code_files")
        if isinstance(body_codes, list):
            code_files = sorted(
                set(code_from_disk)
                | {str(x) for x in body_codes if x and Path(str(x)).suffix.lower() in POC_CODE_EXTS}
            )
        else:
            code_files = code_from_disk
        return {
            "ok": True,
            "finding_id": finding.id,
            "state": finding.state,
            "evidence_id": eid if (finding.evidence_id or pack_files or exists) else None,
            "pack_id_proposed": eid,
            "poc_relpath": POC_DEVELOP_RELPATH,
            "exists": exists,
            "scaffolded": scaffolded,
            "content": content,
            "pack_files": pack_files,
            "poc_code_files": code_files,
        }
    finally:
        db.close()


def save_finding_poc(
    run_dir: Path,
    finding_id: int,
    *,
    content: Optional[str] = None,
    enqueue_agent: bool = False,
    operator_notes: str = "",
    operator: str = "operator",
) -> dict[str, Any]:
    """
    Write/update evidence/<pack>/poc_develop.md and optionally enqueue develop_poc.

    Does **not** change finding state (never auto-confirm).
    """
    from vulnforge.tools.evidence_write import (
        MIN_EVIDENCE_FILE_BYTES,
        InvalidEvidenceId,
        sanitize_evidence_id,
    )
    from vulnforge.util import utc_now_iso

    notes_s = (operator_notes or "").strip()
    if len(notes_s) > 8000:
        notes_s = notes_s[:8000] + "\n...[truncated]"

    db = _open_db(run_dir)
    try:
        finding = db.get_finding(int(finding_id))
        if not finding:
            return {"ok": False, "error": "finding_not_found"}

        prev_state = finding.state
        body = dict(finding.body or {})
        raw_pack = _poc_pack_id(finding)
        try:
            eid = sanitize_evidence_id(str(raw_pack))
        except InvalidEvidenceId as e:
            return {"ok": False, "error": f"invalid evidence_id: {e}"}

        pack_files = _list_pack_files(run_dir, eid)
        text = (content if content is not None else "").strip()
        if not text:
            text = build_poc_scaffold(finding, pack_files=pack_files)
        if len(text.encode("utf-8")) < MIN_EVIDENCE_FILE_BYTES:
            text = text.rstrip() + "\n\n_operator draft_\n"
        if len(text.encode("utf-8")) < MIN_EVIDENCE_FILE_BYTES:
            text = text + (" " * (MIN_EVIDENCE_FILE_BYTES - len(text.encode("utf-8"))))

        pack_dir = run_dir / "evidence" / eid
        pack_dir.mkdir(parents=True, exist_ok=True)
        dest = pack_dir / POC_DEVELOP_RELPATH
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(dest)

        now = utc_now_iso()
        body["evidence_id"] = eid
        body["poc_relpath"] = POC_DEVELOP_RELPATH
        hist = body.get("poc_development")
        if not isinstance(hist, list):
            hist = []
        entry: dict[str, Any] = {
            "at": now,
            "operator": operator or "operator",
            "action": "save",
            "poc_relpath": POC_DEVELOP_RELPATH,
            "bytes": len(text.encode("utf-8")),
            "enqueue_agent": bool(enqueue_agent),
        }
        if notes_s:
            entry["operator_notes"] = notes_s
        hist.append(entry)
        body["poc_development"] = hist[-50:]
        body["poc_development_latest"] = entry

        db.conn.execute(
            """
            UPDATE findings
            SET body_json=?, evidence_id=?, updated_at=?
            WHERE id=?
            """,
            (json.dumps(body), eid, now, finding.id),
        )
        db.conn.commit()

        task_id: Optional[int] = None
        if enqueue_agent:
            payload = {
                "finding_id": finding.id,
                "evidence_id": eid,
                "operator_notes": notes_s,
                "operator": operator or "operator",
            }
            task_id = db.enqueue_task("develop_poc", payload, priority=30)
            entry_q = {
                "at": utc_now_iso(),
                "operator": operator or "operator",
                "action": "enqueue_agent",
                "task_id": task_id,
                "poc_relpath": POC_DEVELOP_RELPATH,
            }
            hist2 = list(body.get("poc_development") or [])
            if not isinstance(hist2, list):
                hist2 = []
            hist2.append(entry_q)
            body["poc_development"] = hist2[-50:]
            body["poc_development_latest"] = entry_q
            db.conn.execute(
                """
                UPDATE findings SET body_json=?, updated_at=? WHERE id=?
                """,
                (json.dumps(body), utc_now_iso(), finding.id),
            )
            db.conn.commit()
            try:
                append_event(
                    run_dir,
                    {
                        "source": "dashboard",
                        "event": "poc_agent_enqueued",
                        "finding_id": finding.id,
                        "evidence_id": eid,
                        "task_id": task_id,
                    },
                )
            except OSError:
                pass

        try:
            append_event(
                run_dir,
                {
                    "source": "dashboard",
                    "event": "poc_saved",
                    "finding_id": finding.id,
                    "evidence_id": eid,
                    "poc_relpath": POC_DEVELOP_RELPATH,
                    "enqueue_agent": bool(enqueue_agent),
                    "task_id": task_id,
                },
            )
        except OSError:
            pass

        pack_after = _list_pack_files(run_dir, eid)
        return {
            "ok": True,
            "finding_id": finding.id,
            "state": prev_state,
            "evidence_id": eid,
            "poc_relpath": POC_DEVELOP_RELPATH,
            "pack_files": pack_after,
            "poc_code_files": _poc_code_files_from_names(pack_after),
            "task_id": task_id,
            "finding": {
                "id": finding.id,
                "state": prev_state,
                "stable_key": finding.stable_key,
                "evidence_id": eid,
                "body": body,
            },
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Findings clusters / operator merge (PR-D)
# ---------------------------------------------------------------------------


def list_finding_clusters(run_dir: Path) -> dict[str, Any]:
    """Return multi-member overlap clusters (merge_key + weak path-only)."""
    from vulnforge.stages.dedup import cluster_findings

    db = _open_db(run_dir)
    try:
        clusters = cluster_findings(db)
        return {
            "ok": True,
            "clusters": clusters,
            "count": len(clusters),
        }
    finally:
        db.close()


def merge_findings_op(
    run_dir: Path,
    keep_id: int,
    drop_ids: list[int],
    *,
    operator: str = "operator",
) -> dict[str, Any]:
    """
    Operator merge: supersede drop_ids into keep_id.

    Never changes keep state (never auto-confirm). Annotates keeper with
    merged_classes / near_dup_titles.
    """
    from vulnforge.stages.dedup import merge_findings

    if not drop_ids:
        return {"ok": False, "error": "drop_ids required"}
    db = _open_db(run_dir)
    try:
        keep = db.get_finding(int(keep_id))
        if not keep:
            return {"ok": False, "error": "keep_finding_not_found"}
        if keep.state == "superseded":
            return {"ok": False, "error": "cannot keep a superseded finding"}
        try:
            result = merge_findings(db, int(keep_id), [int(x) for x in drop_ids])
        except KeyError:
            return {"ok": False, "error": "keep_finding_not_found"}
        except ValueError as e:
            return {"ok": False, "error": str(e)}

        keep_after = db.get_finding(int(keep_id))
        try:
            append_event(
                run_dir,
                {
                    "source": "dashboard",
                    "event": "findings_merged",
                    "keep_id": int(keep_id),
                    "dropped_ids": result.get("dropped_ids") or [],
                    "operator": operator or "operator",
                    "keep_state": keep.state,
                },
            )
        except OSError:
            pass

        return {
            "ok": True,
            "keep_id": int(keep_id),
            "dropped_ids": result.get("dropped_ids") or [],
            "keep_state": keep.state,
            "merged_classes": result.get("merged_classes") or [],
            "near_dup_titles": result.get("near_dup_titles") or [],
            "finding": {
                "id": keep.id,
                "state": keep_after.state if keep_after else keep.state,
                "stable_key": keep.stable_key,
                "evidence_id": keep.evidence_id,
                "body": (keep_after.body if keep_after else keep.body),
            },
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Attack chains (PR-E) — evidence/chains/<id>.json
# ---------------------------------------------------------------------------


def list_chains_op(run_dir: Path) -> dict[str, Any]:
    from vulnforge.chains import list_chains

    chains = list_chains(run_dir)
    return {"ok": True, "chains": chains, "count": len(chains)}


def get_chain_op(run_dir: Path, chain_id: str) -> dict[str, Any]:
    from vulnforge.chains import get_chain

    chain = get_chain(run_dir, chain_id)
    if not chain:
        return {"ok": False, "error": "chain_not_found"}
    return {"ok": True, "chain": chain}


def save_chain_op(run_dir: Path, chain: dict[str, Any]) -> dict[str, Any]:
    from vulnforge.chains import save_chain

    try:
        saved = save_chain(run_dir, chain)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    try:
        append_event(
            run_dir,
            {
                "source": "dashboard",
                "event": "chain_saved",
                "chain_id": saved.get("id"),
                "steps": len(saved.get("steps") or []),
            },
        )
    except OSError:
        pass
    return {"ok": True, "chain": saved}


def delete_chain_op(run_dir: Path, chain_id: str) -> dict[str, Any]:
    from vulnforge.chains import delete_chain

    ok = delete_chain(run_dir, chain_id)
    if not ok:
        return {"ok": False, "error": "chain_not_found"}
    try:
        append_event(
            run_dir,
            {
                "source": "dashboard",
                "event": "chain_deleted",
                "chain_id": chain_id,
            },
        )
    except OSError:
        pass
    return {"ok": True, "deleted": True, "chain_id": chain_id}


def build_chain_from_findings_op(
    run_dir: Path,
    *,
    finding_ids: Optional[list[int]] = None,
    include_states: Optional[list[str]] = None,
    title: str = "",
    enqueue_poc: bool = False,
    operator: str = "operator",
) -> dict[str, Any]:
    """
    Build an attack chain from selected findings (or all matching include_states).

    Optional enqueue_poc queues develop_poc for steps missing a poc_path.
    Never auto-confirms findings.
    """
    from vulnforge.chains import build_chain_from_findings, chain_to_markdown

    states = include_states or ["confirmed"]
    db = _open_db(run_dir)
    try:
        all_findings = db.list_findings()
        by_id = {int(f.id): f for f in all_findings}
        if finding_ids is not None:
            ids = [int(x) for x in finding_ids]
            missing = [i for i in ids if i not in by_id]
            if missing:
                return {
                    "ok": False,
                    "error": f"findings not found: {missing[:10]}",
                }
            selected = [by_id[i] for i in ids]
            # Filter by include_states when provided
            state_set = {str(s).lower() for s in states}
            selected = [f for f in selected if f.state in state_set]
            if not selected:
                return {
                    "ok": False,
                    "error": "no findings match include_states",
                }
            chain = build_chain_from_findings(
                run_dir,
                finding_ids=[int(f.id) for f in selected],
                include_states=list(states),
                title=title,
                findings=selected,
            )
        else:
            state_set = {str(s).lower() for s in states}
            selected = [f for f in all_findings if f.state in state_set]
            if not selected:
                return {
                    "ok": False,
                    "error": "no findings match include_states",
                }
            chain = build_chain_from_findings(
                run_dir,
                include_states=list(states),
                title=title,
                findings=selected,
            )

        enqueued: list[dict[str, Any]] = []
        if enqueue_poc:
            for step in chain.get("steps") or []:
                if step.get("poc_path"):
                    continue
                fid = int(step.get("finding_id") or 0)
                f = by_id.get(fid)
                if not f:
                    continue
                body = dict(f.body or {})
                # Only enqueue if no existing poc_relpath on body either
                if body.get("poc_relpath"):
                    step["poc_path"] = body.get("poc_relpath")
                    continue
                r = save_finding_poc(
                    run_dir,
                    fid,
                    content=None,
                    enqueue_agent=True,
                    operator_notes="Queued from attack chain builder (missing PoC).",
                    operator=operator or "operator",
                )
                if r.get("ok"):
                    step["poc_path"] = r.get("poc_relpath") or POC_DEVELOP_RELPATH
                    enqueued.append(
                        {
                            "finding_id": fid,
                            "task_id": r.get("task_id"),
                            "evidence_id": r.get("evidence_id"),
                        }
                    )
            # Persist poc_path updates on chain
            from vulnforge.chains import save_chain

            chain = save_chain(run_dir, chain)

        md = chain_to_markdown(chain, findings_by_id=by_id)
        try:
            append_event(
                run_dir,
                {
                    "source": "dashboard",
                    "event": "chain_built",
                    "chain_id": chain.get("id"),
                    "steps": len(chain.get("steps") or []),
                    "enqueue_poc": bool(enqueue_poc),
                    "poc_tasks": len(enqueued),
                },
            )
        except OSError:
            pass
        return {
            "ok": True,
            "chain": chain,
            "markdown": md,
            "poc_enqueued": enqueued,
        }
    finally:
        db.close()


def export_chain_markdown_op(run_dir: Path, chain_id: str) -> dict[str, Any]:
    from vulnforge.chains import chain_to_markdown, get_chain

    chain = get_chain(run_dir, chain_id)
    if not chain:
        return {"ok": False, "error": "chain_not_found"}
    db = _open_db(run_dir)
    try:
        by_id = {int(f.id): f for f in db.list_findings()}
    finally:
        db.close()
    return {
        "ok": True,
        "chain_id": chain_id,
        "markdown": chain_to_markdown(chain, findings_by_id=by_id),
        "filename": f"chain-{chain_id}.md",
    }
