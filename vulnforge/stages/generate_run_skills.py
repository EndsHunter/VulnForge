"""Stage: generate_run_skills — author N target-specific hunt profiles after recon.

Uses the editable skill-generator MD (config/prompts/generate_skill.md override
or package seed). Saves profiles as source=generated (inactive by default) and
optionally enqueues hunt tasks with class_body_override.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnforge.hunt_profiles.generate import (
    GenerateSkillError,
    clamp_skill_count,
    generate_hunt_skills_batch,
    origin_from_run_dir,
    save_generated_profile,
)
from vulnforge.llm import InfraError
from vulnforge.transcript import save_transcript


def _path_hints_from_arch(architecture: dict, skill: dict) -> list[str]:
    hints: list[str] = []
    focus = architecture.get("hunt_focus") if isinstance(architecture, dict) else None
    if isinstance(focus, list):
        for f in focus:
            if not isinstance(f, dict):
                continue
            ph = f.get("path_hints") or []
            if isinstance(ph, list):
                for p in ph:
                    s = str(p).strip()
                    if s and s not in hints:
                        hints.append(s)
            if len(hints) >= 8:
                break
    tags = skill.get("tags") or []
    # Prefer first few hints only
    return hints[:6]


def _area_from_arch(architecture: dict) -> str:
    focus = architecture.get("hunt_focus") if isinstance(architecture, dict) else None
    if isinstance(focus, list):
        for f in focus:
            if isinstance(f, dict) and f.get("area"):
                return str(f.get("area")).strip() or "app"
    return "app"


def run(task, db, run_dir: Path, cfg: dict) -> dict[str, Any]:
    payload = dict(getattr(task, "payload", None) or {})
    count = clamp_skill_count(payload.get("count") or payload.get("dynamic_skill_count") or 3)

    architecture = payload.get("architecture")
    if not isinstance(architecture, dict):
        # Prefer DB architecture if payload omitted snapshot
        try:
            architecture = db.get_architecture() or {}
        except Exception:
            architecture = {}
    if not isinstance(architecture, dict):
        architecture = {}

    signals = payload.get("signals")
    if signals is None:
        inv = architecture.get("inventory") if isinstance(architecture.get("inventory"), dict) else {}
        signals = {
            "extensions": inv.get("extensions"),
            "file_count": inv.get("file_count"),
            "entrypoints": inv.get("entrypoints"),
            "dir_partitions": (inv.get("dir_partitions") or [])[:20],
            "seed_sink_kinds": list(
                {
                    str(s.get("kind") or s.get("family") or "")
                    for s in (architecture.get("seed_sinks") or [])[:80]
                    if isinstance(s, dict)
                }
                - {""}
            )[:24],
        }

    operator_brief = str(
        payload.get("operator_brief")
        or payload.get("operator_notes")
        or architecture.get("operator_notes_applied")
        or ""
    ).strip()

    existing: list[str] = []
    try:
        from vulnforge.hunt_profiles import all_class_ids

        existing = list(all_class_ids())
    except Exception:
        existing = []

    activate = bool(payload.get("activate"))
    enqueue_hunts = payload.get("enqueue_hunts")
    if enqueue_hunts is None:
        enqueue_hunts = True
    enqueue_hunts = bool(enqueue_hunts)
    area = str(payload.get("area") or _area_from_arch(architecture) or "app").strip() or "app"

    # Compact architecture for the model (drop huge seed_sinks lists)
    arch_for_llm = {
        k: architecture.get(k)
        for k in (
            "summary",
            "trust_boundaries",
            "components",
            "input_surfaces",
            "hunt_focus",
        )
        if architecture.get(k) is not None
    }

    try:
        skills = generate_hunt_skills_batch(
            cfg,
            count=count,
            architecture=arch_for_llm,
            signals=signals,
            operator_brief=operator_brief,
            existing_class_ids=existing,
            run_dir=run_dir,
            task_id=getattr(task, "id", None),
        )
    except GenerateSkillError as e:
        msg = str(e)
        if "fingerprint" in msg.lower() or "connection" in msg.lower():
            return {"status": "failed_infra", "error": msg}
        return {"status": "failed_task", "error": f"generate_failed: {msg}"}
    except InfraError as e:
        return {"status": "failed_infra", "error": str(e)}
    except Exception as e:
        return {"status": "failed_task", "error": str(e)[:500]}

    model_id = None
    for s in skills:
        if s.get("model_id"):
            model_id = s.get("model_id")
            break

    try:
        save_transcript(
            run_dir,
            getattr(task, "id", 0) or 0,
            kind="generate_run_skills",
            model_id=model_id,
            messages=[],
            result={
                "ok": True,
                "requested": count,
                "produced": len(skills),
                "ids": [s.get("id") for s in skills],
            },
            meta={"count": count, "operator_brief": operator_brief[:500]},
        )
    except OSError:
        pass

    profile_ids: list[str] = []
    hunt_task_ids: list[int] = []
    errors: list[str] = []
    origin_target_id, origin_run_id = origin_from_run_dir(run_dir)

    for skill in skills:
        try:
            profile = save_generated_profile(
                skill,
                active=activate,
                origin_target_id=origin_target_id,
                origin_run_id=origin_run_id,
            )
        except Exception as e:
            errors.append(f"{skill.get('id')}: save_failed: {e}")
            continue
        pid = profile["id"]
        profile_ids.append(pid)
        if enqueue_hunts:
            path_hints = payload.get("path_hints")
            if not isinstance(path_hints, list) or not path_hints:
                path_hints = _path_hints_from_arch(architecture, skill)
            hunt_payload: dict[str, Any] = {
                "area": area,
                "class": pid,
                "path_hints": [str(p) for p in path_hints if p is not None and str(p).strip()][:12],
                "operator_notes": (
                    f"Dynamic skill for this run ({pid}). "
                    + (operator_brief[:1500] if operator_brief else "")
                ).strip(),
                "reason": "dynamic_run_skills",
            }
            if skill.get("body_md"):
                hunt_payload["class_body_override"] = skill["body_md"]
            try:
                tid = db.enqueue_task("hunt", hunt_payload, priority=45)
                hunt_task_ids.append(int(tid))
                db.upsert_coverage_fact(area, pid, visit_delta=0, last_depth="planned")
            except Exception as e:
                errors.append(f"{pid}: enqueue_failed: {e}")

    if not profile_ids:
        return {
            "status": "failed_task",
            "error": "no_profiles_saved",
            "errors": errors,
            "model_id": model_id,
        }

    return {
        "status": "succeeded",
        "requested": count,
        "produced": len(profile_ids),
        "profile_ids": profile_ids,
        "active": activate,
        "enqueue_hunts": enqueue_hunts,
        "hunt_task_ids": hunt_task_ids,
        "hunt_enqueued": len(hunt_task_ids),
        "area": area,
        "model_id": model_id,
        "errors": errors,
    }
