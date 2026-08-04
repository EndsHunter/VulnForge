"""Preflight checks for submit_candidate (non-terminal; does not store)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnforge.util import normalize_relpath


def _check_citations_on_target(body: dict, target_root: Path) -> list[str]:
    """Return list of citation errors (empty if ok)."""
    root = target_root if target_root.is_dir() else target_root.parent
    errs: list[str] = []
    for i, c in enumerate(body.get("citations") or []):
        if not isinstance(c, dict):
            errs.append(f"citations[{i}]: not an object")
            continue
        rel = normalize_relpath(str(c.get("path") or ""))
        if not rel:
            if c.get("address") or c.get("symbol"):
                continue
            errs.append(f"citations[{i}]: path required")
            continue
        p = (root / rel).resolve()
        try:
            p.relative_to(root.resolve())
        except ValueError:
            errs.append(f"citations[{i}]: path escape {rel}")
            continue
        if not p.is_file():
            errs.append(f"citations[{i}]: missing file {rel}")
            continue
        if c.get("start_line") is not None:
            try:
                n = sum(1 for _ in p.open(encoding="utf-8", errors="replace"))
            except OSError:
                errs.append(f"citations[{i}]: unreadable {rel}")
                continue
            try:
                sl = int(c["start_line"])
            except (TypeError, ValueError):
                errs.append(f"citations[{i}]: bad start_line")
                continue
            if sl < 1 or sl > n:
                errs.append(f"citations[{i}]: start_line out of bounds ({sl} of {n})")
            if c.get("end_line") is not None:
                try:
                    el = int(c["end_line"])
                except (TypeError, ValueError):
                    errs.append(f"citations[{i}]: bad end_line")
                    continue
                if el < sl:
                    errs.append(f"citations[{i}]: end_line < start_line")
    return errs


def _check_citation_content_light(
    body: dict, target_root: Path, cfg: dict | None = None
) -> list[str]:
    """Mirror validate_mech.check_citation_content for preflight (no Finding)."""
    from vulnforge.stages.validate_mech import (
        _read_citation_slice,
        _resolve_citation_file,
        citation_claim_tokens,
    )

    citations = body.get("citations") or []
    if not citations:
        return []
    stages = (cfg or {}).get("stages") if isinstance(cfg, dict) else {}
    if not isinstance(stages, dict):
        stages = {}
    strict = bool(stages.get("strict_citation_content"))
    target = target_root if target_root.is_dir() or target_root.is_file() else Path(target_root)
    root = target if target.is_dir() else target.parent
    path_cites = [
        c
        for c in citations
        if isinstance(c, dict) and normalize_relpath(str(c.get("path") or ""))
    ]
    if not path_cites:
        return []
    with_line = [c for c in path_cites if c.get("start_line") is not None]
    if not with_line:
        return ["citation_missing_line"]
    if strict and len(with_line) < len(path_cites):
        return ["citation_missing_line"]

    tokens = citation_claim_tokens(body)
    any_slice = False
    any_hit = False
    for c in with_line:
        rel = normalize_relpath(str(c.get("path") or ""))
        p = _resolve_citation_file(target, root, rel)
        if p is None:
            continue
        try:
            sl = int(c["start_line"])
        except (TypeError, ValueError):
            return [f"citation_missing_line:{rel}"]
        el = c.get("end_line")
        try:
            el_i = int(el) if el is not None else None
        except (TypeError, ValueError):
            el_i = None
        slice_txt = _read_citation_slice(p, sl, el_i, pad=2)
        if slice_txt is None:
            return [f"unreadable:{rel}"]
        if not str(slice_txt).strip():
            return [f"citation_empty_slice:{rel}:{sl}"]
        any_slice = True
        if tokens and any(tok in slice_txt.lower() for tok in tokens):
            any_hit = True
    if tokens and any_slice and not any_hit:
        return ["citation_content_mismatch"]
    return []


def _check_non_vacuous_light(body: dict) -> list[str]:
    """Mirror of validate_mech non-vacuous checks (light copy, no Finding)."""
    from vulnforge.stages.validate_mech import (
        _IMPACT_CONCRETE_HINTS,
        _VACUOUS_IMPACT_SNIPPETS,
        _VACUOUS_TOKENS,
        _impact_has_concrete_hint,
        _is_vacuous_token,
        _norm_field,
    )

    errs: list[str] = []
    title = str(body.get("title") or "").strip()
    if len(title) < 5:
        errs.append("title_too_short")
    summary = _norm_field(body.get("summary"))
    if _is_vacuous_token(summary) or len(summary) < 20:
        errs.append("summary_too_short")
    tm = body.get("threat_model") or {}
    if not isinstance(tm, dict):
        tm = {}
    attacker = _norm_field(tm.get("attacker"))
    boundary = _norm_field(tm.get("boundary"))
    impact = _norm_field(tm.get("impact"))
    if _is_vacuous_token(attacker) or len(attacker) < 8:
        errs.append("vacuous_attacker")
    if _is_vacuous_token(boundary) or len(boundary) < 8:
        errs.append("vacuous_boundary")
    if _is_vacuous_token(impact) or len(impact) < 16:
        errs.append("vacuous_impact")
    for snip in _VACUOUS_IMPACT_SNIPPETS:
        if snip in impact:
            errs.append("vacuous_impact")
            break
    sev = str(body.get("severity_claim") or "").strip().upper()
    if sev in ("CRITICAL", "HIGH") and not _impact_has_concrete_hint(impact):
        errs.append("vacuous_impact_for_severity")
    # silence unused import warning for tokens if only via helpers
    _ = _VACUOUS_TOKENS
    return errs


def _near_dup_hints(body: dict, db: Any) -> list[dict[str, Any]]:
    if db is None:
        return []
    try:
        from vulnforge.findings.identity import compute_stable_key
        from vulnforge.stages.dedup import merge_key, primary_sink
    except Exception:
        return []
    try:
        findings = list(db.list_findings() or [])
    except Exception:
        return []
    if not findings:
        return []

    profile = "code_static"
    try:
        run = db.get_run()
        if run:
            profile = str(run.get("profile") or profile)
    except Exception:
        pass

    sk = compute_stable_key(profile, body)
    mk = merge_key(body)
    path, symbol = primary_sink(body)
    out: list[dict[str, Any]] = []
    for f in findings:
        try:
            fb = f.body if isinstance(getattr(f, "body", None), dict) else {}
            fsk = getattr(f, "stable_key", None) or ""
            state = str(getattr(f, "state", "") or "")
            title = str(fb.get("title") or getattr(f, "title", "") or "")
            fid = getattr(f, "id", None)
            fmk = merge_key(fb) if fb else None
            same_key = bool(sk and fsk and sk == fsk)
            same_merge = bool(mk and fmk and mk == fmk)
            same_path = False
            if path:
                fp, _ = primary_sink(fb) if fb else ("", "")
                same_path = bool(fp and fp == path)
            if not (same_key or same_merge or same_path):
                continue
            reason = (
                "stable_key"
                if same_key
                else ("merge_key" if same_merge else "same_sink_path")
            )
            out.append(
                {
                    "finding_id": fid,
                    "title": title[:120],
                    "state": state,
                    "reason": reason,
                    "weakness_class": fb.get("weakness_class"),
                }
            )
            if len(out) >= 5:
                break
        except Exception:
            continue
    return out


def preflight_candidate(ctx: dict, body: dict | None = None, **kwargs: Any) -> dict[str, Any]:
    """Non-terminal dry-run of submit_candidate gates + near-dup hints.

    Does not store a candidate. Pass the same fields as submit_candidate.
    """
    from vulnforge.stages.hunt import validate_candidate_shape
    from vulnforge.tools.evidence_write import (
        MIN_EVIDENCE_FILE_BYTES,
        InvalidEvidenceId,
        evidence_exists,
        sanitize_evidence_id,
    )

    if body is None:
        body = dict(kwargs) if kwargs else {}
    if not isinstance(body, dict):
        return {"ok": False, "error": "candidate body must be an object"}
    body = dict(body)
    # Allow flat kwargs merge when body partially set
    for k, v in kwargs.items():
        if k not in body and v is not None:
            body[k] = v

    session = ctx.get("session") or {}
    checks: list[dict[str, Any]] = []
    blockers: list[str] = []
    warnings: list[str] = []

    shape_errs = validate_candidate_shape(body)
    checks.append(
        {
            "id": "schema",
            "ok": not shape_errs,
            "errors": shape_errs,
        }
    )
    if shape_errs:
        blockers.extend(shape_errs)

    vac_errs = _check_non_vacuous_light(body) if not shape_errs else []
    checks.append({"id": "non_vacuous", "ok": not vac_errs, "errors": vac_errs})
    if vac_errs:
        blockers.extend(vac_errs)

    target_root = Path(str(ctx.get("target_root") or "."))
    cit_errs = _check_citations_on_target(body, target_root) if body.get("citations") else []
    checks.append({"id": "citations_resolve", "ok": not cit_errs, "errors": cit_errs})
    if cit_errs:
        blockers.extend(cit_errs)

    content_errs = (
        _check_citation_content_light(body, target_root, ctx.get("cfg") or {})
        if body.get("citations") and not cit_errs
        else []
    )
    checks.append(
        {"id": "citation_content", "ok": not content_errs, "errors": content_errs}
    )
    if content_errs:
        blockers.extend(content_errs)

    # Evidence session gate (same policy as prepare_candidate_submission)
    written_ids = set(session.get("evidence_ids_written") or [])
    session_eid = session.get("evidence_id")
    if session_eid and session_eid in written_ids and not body.get("evidence_id"):
        body["evidence_id"] = session_eid
    eid = body.get("evidence_id")
    ev_ok = True
    ev_errs: list[str] = []
    if not eid:
        ev_ok = False
        ev_errs.append(
            "evidence_id missing — call write_evidence first and pass returned evidence_id"
        )
    else:
        try:
            seid = sanitize_evidence_id(str(eid))
        except InvalidEvidenceId as e:
            ev_ok = False
            ev_errs.append(f"invalid evidence_id: {e}")
            seid = None
        if seid is not None:
            if seid not in written_ids:
                ev_ok = False
                ev_errs.append(
                    f"evidence_id={seid!r} not written in this session via write_evidence"
                )
            else:
                evidence_root = Path(
                    str(ctx.get("evidence_root") or (Path(str(ctx.get("run_dir") or ".")) / "evidence"))
                )
                poc = body.get("poc_relpath")
                if not evidence_exists(
                    evidence_root,
                    seid,
                    str(poc) if poc else None,
                    min_file_bytes=MIN_EVIDENCE_FILE_BYTES,
                ):
                    ev_ok = False
                    ev_errs.append(
                        f"evidence pack missing or too small (min {MIN_EVIDENCE_FILE_BYTES} bytes)"
                    )
    checks.append({"id": "evidence", "ok": ev_ok, "errors": ev_errs})
    if not ev_ok:
        blockers.extend(ev_errs)

    near = _near_dup_hints(body, ctx.get("db"))
    if near:
        warnings.append(
            "Similar finding(s) already recorded — differentiate citations/threat "
            "or consider submit_none if true duplicate."
        )
    checks.append(
        {
            "id": "near_dup",
            "ok": True,  # never a hard blocker
            "near_duplicates": near,
        }
    )

    ready = len(blockers) == 0
    sess = ctx.setdefault("session", {})
    sess.setdefault("tools_used", []).append("preflight_candidate")
    result: dict[str, Any] = {
        "ok": True,
        "ready": ready,
        "checks": checks,
        "blockers": blockers,
        "warnings": warnings,
        "near_duplicates": near,
        "hint": (
            "ready=true: you may call submit_candidate with the same fields."
            if ready
            else "Fix blockers before submit_candidate (this tool does not store a finding)."
        ),
    }
    return result
