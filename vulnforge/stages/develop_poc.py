"""
Stage: develop_poc — write working PoC code for one finding (operator-queued).

Tools: list_dir, read_file, grep, write_evidence.
Prefers runnable scripts (poc.py / .sh / .ps1 / .c) plus thin hub poc_develop.md.
Never creates findings. Never sets confirmed / reject states. Does not execute PoCs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnforge.control.ops import POC_CODE_EXTS, POC_DEVELOP_RELPATH
from vulnforge.llm import InfraError, classify_llm_failure, make_client
from vulnforge.packet import pack_develop_poc, refuse_if_over_budget
from vulnforge.tools import build_tool_handler
from vulnforge.transcript import save_transcript
from vulnforge.usage import record_llm_result
from vulnforge.util import append_event, utc_now_iso

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _collect_poc_code_files(
    session: dict,
    pack_dir: Path,
    *,
    evidence_id: str,
) -> list[str]:
    """Basenames of code-like files written this session or already in the pack."""
    names: set[str] = set()
    for rel in session.get("evidence_files") or []:
        # rel may be "pack/file"
        p = Path(str(rel))
        parts = p.parts
        if len(parts) >= 2 and parts[0] == evidence_id:
            base = parts[-1]
        else:
            base = p.name
        if Path(base).suffix.lower() in POC_CODE_EXTS:
            names.add(base)
    if pack_dir.is_dir():
        try:
            for child in pack_dir.iterdir():
                if child.is_file() and child.suffix.lower() in POC_CODE_EXTS:
                    names.add(child.name)
        except OSError:
            pass
    return sorted(names)


def _parse_finding_id(raw: Any) -> tuple[int | None, str | None]:
    if raw is None:
        return None, "missing_finding_id"
    try:
        return int(raw), None
    except (TypeError, ValueError):
        return None, "invalid_finding_id"


def run(task, db, run_dir: Path, cfg: dict) -> dict[str, Any]:
    payload = dict(task.payload or {})
    fid, fid_err = _parse_finding_id(payload.get("finding_id"))
    if fid is None:
        return {
            "status": "failed_task",
            "error": fid_err or "missing_finding_id",
        }

    finding = db.get_finding(fid)
    if finding is None:
        return {
            "status": "failed_task",
            "error": "finding_not_found",
            "finding_id": fid,
        }

    run_row = db.get_run()
    if not run_row:
        return {"status": "failed_task", "error": "no_run", "finding_id": fid}

    target = Path(run_row["target_path"])
    body = dict(finding.body or {})
    from vulnforge.tools.evidence_write import InvalidEvidenceId, sanitize_evidence_id

    raw_eid = (
        payload.get("evidence_id")
        or finding.evidence_id
        or body.get("evidence_id")
        or f"human-{fid}"
    )
    try:
        eid = sanitize_evidence_id(str(raw_eid))
    except InvalidEvidenceId as e:
        return {
            "status": "failed_task",
            "error": f"invalid_evidence_id:{e}",
            "finding_id": fid,
        }

    # Ensure pack dir exists and body links it (state unchanged).
    pack_dir = run_dir / "evidence" / eid
    pack_dir.mkdir(parents=True, exist_ok=True)
    existing_poc = ""
    poc_path = pack_dir / POC_DEVELOP_RELPATH
    if poc_path.is_file():
        try:
            existing_poc = poc_path.read_text(encoding="utf-8")
        except OSError:
            existing_poc = ""

    from vulnforge.stages.validate_llm import load_citation_slices

    pkt_cfg = cfg.get("packet") or {}
    per_slice = int(pkt_cfg.get("max_file_slice_chars", 4000))
    max_chars = max(per_slice, min(per_slice * 4, 24_000))
    slices = load_citation_slices(finding, target, max_chars=max_chars)

    session: dict = {
        "tools_used": [],
        "evidence_id": eid,
        "evidence_ids_written": [],
        "evidence_files": [],
    }
    ctx = {
        "target_root": str(target),
        "evidence_root": str(run_dir / "evidence"),
        "task_id": task.id,
        "cfg": cfg,
        "session": session,
        # Prefer this pack for write_evidence default when model omits id.
        "default_evidence_id": eid,
    }
    # Prefer task pack when write_evidence omits evidence_id
    orig_handler = build_tool_handler(ctx)

    def handler(name: str, args: dict) -> dict[str, Any]:
        args = dict(args or {})
        if name == "write_evidence" and not args.get("evidence_id"):
            args["evidence_id"] = eid
        return orig_handler(name, args)

    prompts_root = PROJECT_ROOT / "prompts" / "v1"
    try:
        packet = pack_develop_poc(
            cfg,
            prompts_root,
            body,
            slices,
            evidence_id=eid,
            existing_poc=existing_poc,
            operator_notes=str(payload.get("operator_notes") or ""),
        )
    except FileNotFoundError as e:
        return {
            "status": "failed_task",
            "error": f"missing_prompts:{e}",
            "finding_id": fid,
        }

    try:
        refuse_if_over_budget(packet)
    except Exception as e:
        return {
            "status": "failed_task",
            "error": f"over_budget: {e}",
            "finding_id": fid,
        }

    client = make_client(cfg)
    model_id: str | None = None
    try:
        try:
            model_id = client.fingerprint_model()
        except InfraError as e:
            return {
                "status": "failed_infra",
                "error": str(e),
                "finding_id": fid,
            }

        max_rounds = int((cfg.get("llm") or {}).get("max_tool_rounds", 12))
        temp = float((cfg.get("llm") or {}).get("temperature_hunt", 0.3))
        result = client.run_tool_loop(
            packet, handler, max_rounds=max_rounds, temperature=temp
        )
        usage_fields = record_llm_result(
            run_dir,
            task_id=getattr(task, "id", 0) or 0,
            kind="develop_poc",
            model_id=model_id,
            result=result,
        )
        try:
            save_transcript(
                run_dir,
                getattr(task, "id", 0) or 0,
                kind="develop_poc",
                model_id=model_id,
                messages=list(result.transcript or []),
                result={
                    "ok": result.ok,
                    "classification": result.classification.value,
                    "error": result.error,
                    "content": result.content,
                    **usage_fields,
                },
                meta={"finding_id": fid, "evidence_id": eid, "stage": "develop_poc"},
            )
        except OSError:
            pass

        if not result.ok and result.error not in (None, "max_tool_rounds"):
            status = classify_llm_failure(result)
            if status == "failed_infra":
                return {
                    "status": "failed_infra",
                    "error": result.error or result.classification.value,
                    "finding_id": fid,
                    "model_id": model_id,
                    **usage_fields,
                }

        wrote = poc_path.is_file() and poc_path.stat().st_size >= 20
        # Also accept write_evidence to same pack with alternate name if model
        # used a different relpath; still prefer poc_develop.md when present.
        if not wrote and session.get("evidence_files"):
            for rel in session["evidence_files"]:
                # rel may be "pack/file"
                p = run_dir / "evidence" / str(rel)
                if p.is_file() and p.stat().st_size >= 20:
                    wrote = True
                    break

        if not wrote:
            return {
                "status": "failed_task",
                "error": "no_poc_written",
                "finding_id": fid,
                "model_id": model_id,
                "transcript": f"task-{task.id}",
                **usage_fields,
            }

        # Link finding to pack + history; never change state.
        now = utc_now_iso()
        body2 = dict(finding.body or {})
        body2["evidence_id"] = eid
        body2["poc_relpath"] = POC_DEVELOP_RELPATH
        code_files = _collect_poc_code_files(session, pack_dir, evidence_id=eid)
        if code_files:
            body2["poc_code_files"] = code_files
        hist = body2.get("poc_development")
        if not isinstance(hist, list):
            hist = []
        entry = {
            "at": now,
            "action": "agent_develop",
            "operator": payload.get("operator") or "agent",
            "task_id": getattr(task, "id", None),
            "poc_relpath": POC_DEVELOP_RELPATH,
            "model_id": model_id,
        }
        if code_files:
            entry["poc_code_files"] = code_files
        hist.append(entry)
        body2["poc_development"] = hist[-50:]
        body2["poc_development_latest"] = entry
        db.conn.execute(
            """
            UPDATE findings
            SET body_json=?, evidence_id=?, updated_at=?
            WHERE id=?
            """,
            (json.dumps(body2), eid, now, fid),
        )
        db.conn.commit()

        try:
            append_event(
                run_dir,
                {
                    "source": "vf",
                    "event": "poc_developed",
                    "task_id": getattr(task, "id", None),
                    "finding_id": fid,
                    "evidence_id": eid,
                    "poc_relpath": POC_DEVELOP_RELPATH,
                    "poc_code_files": code_files,
                    "model_id": model_id,
                },
            )
        except OSError:
            pass

        return {
            "status": "succeeded",
            "finding_id": fid,
            "evidence_id": eid,
            "poc_relpath": POC_DEVELOP_RELPATH,
            "poc_code_files": code_files,
            "model_id": model_id,
            "transcript": f"task-{task.id}",
            "finding_state": finding.state,
            **usage_fields,
        }
    finally:
        try:
            client.close()
        except Exception:
            pass
