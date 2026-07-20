"""Stage: validate_mech â€” mandatory pure-code gates. No LLM."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from vulnforge.tools.evidence_write import evidence_exists
from vulnforge.util import match_manifest_fingerprint, normalize_relpath, read_json


def run(task, db, run_dir: Path, cfg: dict) -> dict[str, Any]:
    fid = (task.payload or {}).get("finding_id")
    if fid is None:
        return {"status": "failed_task", "error": "missing finding_id"}
    finding = db.get_finding(int(fid))
    if not finding:
        return {"status": "failed_task", "error": "finding_not_found"}

    import json
    from vulnforge.findings.severity import apply_severity_claim
    from vulnforge.util import utc_now_iso

    # Optional severity_claim: canonicalize aliases or soft-drop free-text before
    # gates so bad_severity alone never discards an otherwise solid candidate.
    body0 = dict(finding.body or {})
    body0, sev_action = apply_severity_claim(body0)
    if sev_action is not None or body0 != dict(finding.body or {}):
        db.conn.execute(
            "UPDATE findings SET body_json=?, updated_at=? WHERE id=?",
            (json.dumps(body0), utc_now_iso(), finding.id),
        )
        db.conn.commit()
        finding = db.get_finding(int(fid))
        if not finding:
            return {"status": "failed_task", "error": "finding_not_found"}

    reasons: list[str] = []
    for check in CHECKS:
        ok, reason = check(finding, run_dir, cfg, db)
        if not ok:
            reasons.append(reason)

    if reasons:
        body = dict(finding.body)
        body["validation_reasons"] = reasons

        db.conn.execute(
            "UPDATE findings SET state=?, body_json=?, updated_at=? WHERE id=?",
            ("rejected_mech", json.dumps(body), utc_now_iso(), finding.id),
        )
        db.conn.commit()
        return {
            "status": "succeeded",
            "verdict": "rejected_mech",
            "reasons": reasons,
            "finding_id": finding.id,
        }

    # Mech passed → never auto-confirm. Confirmed is a human decision.
    # Optional validate_llm may still demote/reject; stand/hold also land as needs_human.
    body = dict(finding.body)
    body["validation_mech"] = {
        "status": "passed",
        "at": utc_now_iso(),
    }
    body["needs_human"] = True

    if (cfg.get("stages") or {}).get("validate_llm"):
        body["validation_mech"]["pending_llm"] = True
        db.conn.execute(
            "UPDATE findings SET state=?, body_json=?, updated_at=? WHERE id=?",
            ("needs_human", json.dumps(body), utc_now_iso(), finding.id),
        )
        db.conn.commit()
        db.enqueue_task(
            "validate_llm",
            {
                "finding_id": finding.id,
                "parent_task_id": getattr(task, "id", None),
            },
            priority=25,
        )
        return {
            "status": "succeeded",
            "verdict": "pending_llm",
            "finding_id": finding.id,
            "finding_state": "needs_human",
        }

    db.conn.execute(
        "UPDATE findings SET state=?, body_json=?, updated_at=? WHERE id=?",
        ("needs_human", json.dumps(body), utc_now_iso(), finding.id),
    )
    db.conn.commit()
    return {
        "status": "succeeded",
        "verdict": "needs_human",
        "finding_id": finding.id,
        "finding_state": "needs_human",
    }


def check_schema(finding, run_dir: Path, cfg: dict, db) -> tuple[bool, str]:
    body = finding.body
    from vulnforge.stages.hunt import validate_candidate_shape

    errs = validate_candidate_shape(body)
    if errs:
        return False, "schema:" + ";".join(errs)
    return True, ""


def check_citations_resolve(finding, run_dir: Path, cfg: dict, db) -> tuple[bool, str]:
    run = db.get_run()
    if not run:
        return False, "no_run"
    target = Path(run["target_path"])
    try:
        profile = str(run["profile"] or "")
    except (KeyError, IndexError, TypeError):
        profile = ""
    binary_mode = profile == "binary_re"
    # Directory agents resolve under; for a single-file target use parent.
    root = target if target.is_dir() else target.parent

    for c in finding.body.get("citations") or []:
        if not isinstance(c, dict):
            return False, "citation_not_object"
        if binary_mode:
            # PE findings: require path (binary name) and/or address/symbol.
            has_addr = bool(str(c.get("address") or "").strip())
            has_sym = bool(str(c.get("symbol") or "").strip())
            has_path = bool(str(c.get("path") or "").strip())
            if not (has_addr or has_sym or has_path):
                return False, "binary_citation_needs_address_or_symbol_or_path"
            # If path is the binary basename or absolute match, ok.
            if has_path:
                rel = normalize_relpath(str(c.get("path") or ""))
                if target.is_file():
                    if rel not in (target.name, normalize_relpath(target.name), str(target)):
                        # allow basename-only citations
                        if Path(rel).name != target.name:
                            return False, f"binary_citation_path_mismatch:{rel}"
                continue
            continue

        rel = normalize_relpath(str(c.get("path") or ""))
        if target.is_file() and (
            rel in (target.name, normalize_relpath(target.name))
            or Path(rel).name == target.name
        ):
            p = target.resolve()
        else:
            p = (root / rel).resolve()
            try:
                p.relative_to(root.resolve())
            except ValueError:
                return False, f"citation_escape:{rel}"
        if not p.is_file():
            return False, f"missing_path:{rel}"
        if c.get("start_line") is not None:
            try:
                n = sum(1 for _ in p.open(encoding="utf-8", errors="replace"))
            except OSError:
                return False, f"unreadable:{rel}"
            if int(c["start_line"]) > n or int(c["start_line"]) < 1:
                return False, f"line_oob:{rel}:{c['start_line']}"
            if c.get("end_line") is not None and int(c["end_line"]) < int(c["start_line"]):
                return False, f"bad_line_range:{rel}"
    return True, ""


def check_evidence_pack(finding, run_dir: Path, cfg: dict, db) -> tuple[bool, str]:
    from vulnforge.tools.evidence_write import MIN_EVIDENCE_FILE_BYTES

    body = finding.body
    eid = finding.evidence_id or body.get("evidence_id")
    poc = body.get("poc_relpath")
    # Policy: if poc_relpath or evidence_id claimed, pack must exist under evidence/
    # with at least one non-trivial file (min bytes). Sanitize id so path escape is impossible.
    # When poc_relpath is set, that exact file must exist and meet min size â€” no pack fallback.
    # Default: require evidence_id for mech-pass / needs_human path (strict v1).
    # DEFER L2: no_poc escape hatch retained for now; consider removing for strict v1
    # or documenting as intentional exception to missing_evidence_id.
    if poc and not eid:
        return False, "poc_without_evidence_id"
    if eid:
        root = run_dir / "evidence"
        if poc:
            if not evidence_exists(
                root, str(eid), str(poc), min_file_bytes=MIN_EVIDENCE_FILE_BYTES
            ):
                return False, f"missing_poc:{eid}:{poc}"
        elif not evidence_exists(
            root, str(eid), None, min_file_bytes=MIN_EVIDENCE_FILE_BYTES
        ):
            return False, f"missing_evidence:{eid}"
        return True, ""
    # no evidence_id: reject for mech-pass path unless justified no_poc
    if body.get("no_poc") and body.get("no_poc_justification"):
        if len(str(body["no_poc_justification"])) >= 20:
            return True, ""
        return False, "weak_no_poc_justification"
    return False, "missing_evidence_id"


def check_target_unmodified(finding, run_dir: Path, cfg: dict, db) -> tuple[bool, str]:
    man_path = run_dir / "target_manifest.json"
    if not man_path.is_file():
        return False, "missing_manifest"
    man = read_json(man_path)
    files = man.get("files") or {}
    run = db.get_run()
    target = Path(run["target_path"])

    # Single file / binary: verify the target file itself has not changed.
    kind = str(man.get("kind") or "")
    if kind in ("single_binary", "single_file") or target.is_file():
        if not target.is_file():
            return False, "binary_missing" if kind == "single_binary" else "file_missing"
        expected = None
        if isinstance(man.get("binary"), dict) and man["binary"].get("sha256"):
            expected = man["binary"]["sha256"]
        elif isinstance(man.get("single_file"), dict) and man["single_file"].get("sha256"):
            expected = man["single_file"]["sha256"]
        elif files:
            expected = next(iter(files.values()), None)
        if expected:
            try:
                ok = match_manifest_fingerprint(target, str(expected))
            except OSError:
                return False, "binary_hash_fail" if kind == "single_binary" else "hash_fail"
            if not ok:
                label = "binary" if kind == "single_binary" else "file"
                return False, f"target_mutated:{label}"
        return True, ""

    for c in finding.body.get("citations") or []:
        rel = normalize_relpath(str(c.get("path") or ""))
        if rel not in files:
            # file might have been outside manifest (ignored) — allow if still exists
            continue
        p = target / rel
        if not p.is_file():
            return False, f"cited_missing:{rel}"
        expected = files[rel]
        try:
            ok = match_manifest_fingerprint(p, str(expected))
        except OSError:
            return False, f"hash_fail:{rel}"
        if not ok:
            return False, f"target_mutated:{rel}"
    return True, ""


def check_non_vacuous(finding, run_dir: Path, cfg: dict, db) -> tuple[bool, str]:
    tm = finding.body.get("threat_model") or {}
    impact = str(tm.get("impact") or "").lower()
    boundary = str(tm.get("boundary") or "").lower()
    # crude vacuous patterns
    if "if they have write access" in impact and "write" in impact:
        return False, "vacuous_impact"
    if boundary in ("n/a", "none", "unknown"):
        return False, "vacuous_boundary"
    title = str(finding.body.get("title") or "")
    if len(title) < 5:
        return False, "title_too_short"
    return True, ""


def check_severity_claim(finding, run_dir: Path, cfg: dict, db) -> tuple[bool, str]:
    """severity_claim optional; run() already normalized/soft-dropped before CHECKS."""
    from vulnforge.findings.severity import ALLOWED_SEVERITY_CLAIMS, normalize_severity_claim

    sev = finding.body.get("severity_claim")
    if sev is None or (isinstance(sev, str) and not sev.strip()):
        return True, ""
    canon = normalize_severity_claim(sev)
    if canon is None or canon not in ALLOWED_SEVERITY_CLAIMS:
        # Soft-drop should have removed this in run(); if it remains, reject.
        return False, f"bad_severity:{sev}"
    return True, ""


def check_binary_address_present(finding, run_dir: Path, cfg: dict, db) -> tuple[bool, str]:
    """binary_re: require sink_address or citation address when profile is binary_re."""
    run = db.get_run()
    if not run:
        return True, ""
    try:
        profile = str(run["profile"] or "")
    except (KeyError, IndexError, TypeError):
        profile = ""
    if profile != "binary_re":
        return True, ""
    body = finding.body or {}
    if str(body.get("sink_address") or "").strip():
        return True, ""
    for c in body.get("citations") or []:
        if isinstance(c, dict) and (
            str(c.get("address") or "").strip() or str(c.get("symbol") or "").strip()
        ):
            return True, ""
    return False, "binary_missing_address_or_symbol"


CHECKS: list[Callable] = [
    check_schema,
    check_citations_resolve,
    check_evidence_pack,
    check_target_unmodified,
    check_non_vacuous,
    check_severity_claim,
    check_binary_address_present,
]
