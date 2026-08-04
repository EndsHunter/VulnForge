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
    # validate_llm (default on) may still demote/reject; stand/hold also land as needs_human.
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
    # Directory agents resolve under; for a single-file target use parent.
    root = target if target.is_dir() else target.parent

    for c in finding.body.get("citations") or []:
        if not isinstance(c, dict):
            return False, "citation_not_object"

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


# Placeholder / non-answer tokens for threat_model fields and summary stubs.
_VACUOUS_TOKENS: frozenset[str] = frozenset(
    {
        "n/a",
        "na",
        "none",
        "unknown",
        "tbd",
        "todo",
        "tbc",
        "-",
        "—",
        ".",
        "see summary",
        "see above",
        "same",
        "various",
        "misc",
        "other",
        "general",
        "security issue",
        "security risk",
        "security concern",
        "vulnerability",
        "potential issue",
        "potential risk",
    }
)

# Substrings that mark impact prose as non-actionable (case-insensitive).
# Keep narrow — avoid phrases that appear inside otherwise concrete claims.
_VACUOUS_IMPACT_SNIPPETS: tuple[str, ...] = (
    "if they have write access",
    "with write access you can write",
    "if they have admin",
    "if attacker has root",
    "if the attacker is root",
    "could be bad",
    "could potentially",
    "might be vulnerable",
    "may be vulnerable",
    "potential vulnerability",
    "potential security issue",
    "potential security risk",
    "could lead to issues",
    "could cause problems",
    "bad things could happen",
)

# Weak impact that needs more specificity when severity is HIGH/CRITICAL.
_IMPACT_CONCRETE_HINTS: tuple[str, ...] = (
    "rce",
    "remote code",
    "code exec",
    "code execution",
    "command injection",
    "shell",
    "auth",
    "bypass",
    "privilege",
    "escalat",
    "secret",
    "credential",
    "password",
    "token",
    "session",
    "leak",
    "exfil",
    "inject",
    "sql",
    "xss",
    "ssrf",
    "path traversal",
    "arbitrary",
    "unauthorized",
    "unauthenticated",
    "cross-user",
    "cross user",
    "tenant",
    "idor",
    "overwrite",
    "delete",
    "modify",
    "read ",
    "write ",
    "forge",
    "spoof",
    "deserial",
    "memory",
    "heap",
    "buffer",
    "pii",
    "payment",
    "money",
    "dos",
    "denial",
    "crash",
    "file",
    "data",
)


def _norm_field(value: object) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _is_vacuous_token(text: str) -> bool:
    return text in _VACUOUS_TOKENS or not text


def _impact_has_concrete_hint(impact: str) -> bool:
    return any(h in impact for h in _IMPACT_CONCRETE_HINTS)


def check_non_vacuous(finding, run_dir: Path, cfg: dict, db) -> tuple[bool, str]:
    """Reject stub / circular threat models and severity-without-impact claims.

    Intent: raise the floor for Report-ready candidates without inventing a score.
    Keep patterns conservative — prefer false-pass over false-reject on edge prose.
    """
    body = finding.body or {}
    title = str(body.get("title") or "").strip()
    if len(title) < 5:
        return False, "title_too_short"

    summary = _norm_field(body.get("summary"))
    if _is_vacuous_token(summary) or len(summary) < 20:
        return False, "summary_too_short"

    tm = body.get("threat_model") or {}
    if not isinstance(tm, dict):
        tm = {}

    attacker = _norm_field(tm.get("attacker"))
    boundary = _norm_field(tm.get("boundary"))
    impact = _norm_field(tm.get("impact"))

    if _is_vacuous_token(attacker) or len(attacker) < 8:
        return False, "vacuous_attacker"
    if _is_vacuous_token(boundary) or len(boundary) < 8:
        return False, "vacuous_boundary"
    if _is_vacuous_token(impact) or len(impact) < 16:
        return False, "vacuous_impact"

    for snip in _VACUOUS_IMPACT_SNIPPETS:
        if snip in impact:
            return False, "vacuous_impact"

    # Circular privilege restatement: "with X you can do X"
    if "write access" in impact and "write" in impact and "if" in impact:
        return False, "vacuous_impact"

    sev = str(body.get("severity_claim") or "").strip().upper()
    if sev in ("CRITICAL", "HIGH") and not _impact_has_concrete_hint(impact):
        # HIGH/CRITICAL must name a concrete damage class, not vague "bad outcome".
        return False, "vacuous_impact_for_severity"

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


CHECKS: list[Callable] = [
    check_schema,
    check_citations_resolve,
    check_evidence_pack,
    check_target_unmodified,
    check_non_vacuous,
    check_severity_claim,
]
