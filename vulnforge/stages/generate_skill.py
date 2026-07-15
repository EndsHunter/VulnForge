"""Stage: generate_skill — author a custom hunt profile from an operator brief.

Never writes to prompts/v1. Profiles land in the operator collection
(config/hunt_profiles/) via save_profile(source=\"generated\").
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnforge.hunt_profiles.generate import (
    GenerateSkillError,
    generate_hunt_skill,
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

    try:
        profile = save_generated_profile(skill, active=activate)
    except Exception as e:
        return {
            "status": "failed_task",
            "error": f"save_failed: {e}",
            "skill_id": skill.get("id"),
            "model_id": model_id,
            **(usage if isinstance(usage, dict) else {}),
        }

    hunt_task_ids: list[int] = []
    if enqueue_hunts:
        hunt_payload = {
            "area": area,
            "class": profile["id"],
            "path_hints": path_hints,
            "operator_notes": brief[:2500],
            "reason": "generate_skill",
        }
        # Inline body so hunt works even if collection root differs across workers
        if skill.get("body_md"):
            hunt_payload["class_body_override"] = skill["body_md"]
        tid = db.enqueue_task("hunt", hunt_payload, priority=40)
        hunt_task_ids.append(int(tid))
        try:
            db.upsert_coverage_fact(area, profile["id"], visit_delta=0, last_depth="planned")
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
        "model_id": model_id,
        "tags": skill.get("tags") or [],
        "cwe": skill.get("cwe") or [],
        "angle_ids": skill.get("angle_ids") or [],
        "sink_families": skill.get("sink_families") or [],
        **(usage if isinstance(usage, dict) else {}),
    }
