"""Stage: generate_skill — author a custom hunt profile from an operator brief.

Never writes to seeds/. Profiles land in the operator collection
(config/hunt_profiles/) via save_profile(source=\"generated\").
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnforge.hunt_profiles.generate import (
    GenerateSkillError,
    generate_hunt_skill,
    origin_from_run_dir,
    save_generated_profile,
)
from vulnforge.llm import InfraError, classify_llm_failure
from vulnforge.transcript import save_transcript


def run(task, db, run_dir: Path, cfg: dict) -> dict[str, Any]:
    payload = dict(getattr(task, "payload", None) or {})
    brief = str(payload.get("brief") or payload.get("operator_brief") or "").strip()
    if not brief:
        return {"status": "failed_task", "error": "brief_required"}

    path_hints = payload.get("path_hints") or []
    if not isinstance(path_hints, list):
        path_hints = []
    path_hints = [str(p) for p in path_hints if p is not None and str(p).strip()]

    signals = payload.get("signals")
    suggested_id = payload.get("suggested_id") or payload.get("class")
    activate = bool(payload.get("activate"))
    enqueue_hunts = payload.get("enqueue_hunts")
    if enqueue_hunts is None:
        enqueue_hunts = False
    enqueue_hunts = bool(enqueue_hunts)
    area = str(payload.get("area") or "app").strip() or "app"

    try:
        skill = generate_hunt_skill(
            cfg,
            brief=brief,
            signals=signals,
            suggested_id=str(suggested_id) if suggested_id else None,
            run_dir=run_dir,
            task_id=getattr(task, "id", None),
        )
    except GenerateSkillError as e:
        msg = str(e)
        # Transport / fingerprint style failures → infra when marked as such
        if "fingerprint" in msg.lower() or "connection" in msg.lower():
            return {"status": "failed_infra", "error": msg}
        return {"status": "failed_task", "error": f"generate_failed: {msg}"}
    except InfraError as e:
        return {"status": "failed_infra", "error": str(e)}
    except Exception as e:
        # Unexpected: treat thrashy LLM path as failed_task
        status = "failed_task"
        try:
            # classify if it looks like an LLMResult-bearing failure
            if hasattr(e, "classification"):
                status = classify_llm_failure(e)  # type: ignore[arg-type]
        except Exception:
            pass
        return {"status": status, "error": str(e)[:500]}

    usage = skill.pop("usage", None) or {}
    model_id = skill.get("model_id")

    try:
        save_transcript(
            run_dir,
            getattr(task, "id", 0) or 0,
            kind="generate_skill",
            model_id=model_id,
            messages=[],
            result={
                "ok": True,
                "id": skill.get("id"),
                "title": skill.get("title"),
                **(usage if isinstance(usage, dict) else {}),
            },
            meta={"brief": brief[:500], "suggested_id": suggested_id},
        )
    except OSError:
        pass

    origin_target_id, origin_run_id = origin_from_run_dir(run_dir)
    try:
        profile = save_generated_profile(
            skill,
            active=activate,
            origin_target_id=origin_target_id,
            origin_run_id=origin_run_id,
        )
    except Exception as e:
        return {
            "status": "failed_task",
            "error": f"save_failed: {e}",
            "skill_id": skill.get("id"),
            "model_id": model_id,
            **(usage if isinstance(usage, dict) else {}),
        }

    hunt_task_ids: list[int] = []
    reason = str(payload.get("reason") or "generate_skill").strip() or "generate_skill"
    if enqueue_hunts:
        # Build hunt units: one per path_hint when multiple, else single area unit.
        # Optional path_targets: [{path, is_dir}] expand to path_hints-style units.
        units: list[tuple[str, list[str]]] = []
        raw_targets = payload.get("path_targets")
        if isinstance(raw_targets, list) and raw_targets:
            for pt in raw_targets:
                if isinstance(pt, dict):
                    p = str(pt.get("path") or "").strip()
                else:
                    p = str(pt or "").strip()
                if not p:
                    continue
                units.append((p, [p]))
        if not units and path_hints:
            # One hunt per distinct path hint when multi-path Coverage generate
            for p in path_hints:
                ps = str(p).strip()
                if ps:
                    units.append((ps, [ps]))
        if not units:
            units = [(area, list(path_hints))]

        max_hunts = 50
        try:
            cfg_run = (cfg or {}).get("run") if isinstance(cfg, dict) else {}
            max_hunts = max(1, int((cfg_run or {}).get("max_tasks") or 50))
        except (TypeError, ValueError):
            max_hunts = 50
        try:
            if payload.get("max_hunts") is not None:
                max_hunts = max(1, min(max_hunts, int(payload.get("max_hunts"))))
        except (TypeError, ValueError):
            pass

        seen: set[tuple[str, str]] = set()
        for unit_area, unit_hints in units:
            if len(hunt_task_ids) >= max_hunts:
                break
            ua = str(unit_area or area).strip() or area
            uh = [str(h) for h in (unit_hints or []) if str(h).strip()][:15]
            key = (ua, profile["id"])
            if key in seen:
                continue
            seen.add(key)
            hunt_payload = {
                "area": ua,
                "class": profile["id"],
                "path_hints": uh,
                "operator_notes": brief[:2500],
                "reason": reason,
                "operator_requested": True,
            }
            # Inline body so hunt works even if collection root differs across workers
            if skill.get("body_md"):
                hunt_payload["class_body_override"] = skill["body_md"]
            tid = db.enqueue_task("hunt", hunt_payload, priority=40)
            hunt_task_ids.append(int(tid))
            try:
                db.upsert_coverage_fact(
                    ua,
                    profile["id"],
                    path=(uh[0] if uh else ""),
                    visit_delta=0,
                    last_depth="planned",
                )
            except Exception:
                pass

    return {
        "status": "succeeded",
        "profile_id": profile["id"],
        "title": profile.get("title"),
        "active": bool(profile.get("active")),
        "source": profile.get("source") or "generated",
        "activate": activate,
        "enqueue_hunts": enqueue_hunts,
        "hunt_task_ids": hunt_task_ids,
        "hunt_enqueued": len(hunt_task_ids),
        "area": area,
        "path_hints": path_hints,
        "reason": reason,
        "model_id": model_id,
        "tags": skill.get("tags") or [],
        "cwe": skill.get("cwe") or [],
        "angle_ids": skill.get("angle_ids") or [],
        "sink_families": skill.get("sink_families") or [],
        **(usage if isinstance(usage, dict) else {}),
    }
