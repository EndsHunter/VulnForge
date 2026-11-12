"""Report → Reject → **Promote to policy** (#184).

Turns an explicit human reject into a drafted security-policy rule
(``exclusions`` or ``out_of_scope``) that the operator edits and saves.

Honesty:

* Draft is read-only. Nothing is stored until :func:`promote_rule` runs without
  ``dry_run``, which is the operator's explicit Save.
* A rule can only be promoted from a finding that is ``rejected_human`` *and*
  has a durable HITL review response ``changes-requested``. The harness
  re-reads that row; it never invents one.
* Provenance (finding id + HITL response id, value, note and time) is stamped
  server-side; anything the client sent under ``provenance`` is dropped.
* Both target lists only demote, through the visible ``validate_mech``
  exclusion gate. Nothing is re-gated: findings already in ``needs_human`` are
  only *listed* (``would_match``) for the operator to review by hand.
* No finding state is changed here.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Optional

from vulnforge.db import Database
from vulnforge.hitl import approval_block_id, finding_report_id
from vulnforge.security_policy import (
    MAX_PROVENANCE_NOTE_CHARS,
    PROVENANCE_KIND_HUMAN_REJECT,
    PROVENANCE_LISTS,
    PolicyConflictError,
    PolicyError,
    cited_paths,
    empty_policy,
    match_exclusion,
    normalize_policy,
    rule_ids,
)
from vulnforge.util import utc_now_iso

PROMOTE_TARGETS: tuple[str, ...] = PROVENANCE_LISTS
_ID_PREFIX = {"exclusions": "ex-hr", "out_of_scope": "oos-hr"}
_REASON_MAX = 2000
_WOULD_MATCH_MAX = 200

MECH_EFFECT_COPY = (
    "Saving adds this rule to the run's security policy. Findings validated after the save "
    "whose cited paths are all covered by the rule go to rejected_mech with the rule cited "
    "(visible in Report). Findings already in needs_human, confirmed or rejected are not "
    "re-gated; the list below is for you to review by hand. A rule listing several files "
    "also matches a later finding that cites only one of them."
)


def _fail(error: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": error, **extra}


def policy_root(db: Database) -> Optional[Path]:
    """Directory citations resolve under — same as ``validate_mech._policy_root``."""
    from vulnforge.stages.validate_mech import _policy_root

    return _policy_root(db)


def _reject_row(db: Database, finding_id: int) -> Optional[dict]:
    report_id = finding_report_id(finding_id)
    block_id = approval_block_id(finding_id)
    for row in db.list_hitl_responses(report_id):
        if row.get("block_id") == block_id:
            return row
    return None


def reject_context(db: Database, finding_id: int) -> dict[str, Any]:
    """The finding plus its current HITL reject response, or an error.

    Both must hold: state ``rejected_human`` and a stored
    ``finding-N-review`` answer ``changes-requested``.
    """
    finding = db.get_finding(int(finding_id))
    if finding is None:
        return _fail("finding_not_found")
    if finding.state != "rejected_human":
        return _fail(
            "not_human_rejected",
            detail=f"finding #{finding.id} is {finding.state!r}; reject it first",
        )
    row = _reject_row(db, finding.id)
    if not row or str(row.get("value") or "") != "changes-requested":
        return _fail(
            "no_hitl_reject_response",
            detail="no durable HITL reject (changes-requested) is stored for this finding",
        )
    return {"ok": True, "finding": finding, "hitl": row}


def _suggest_id(policy: dict, list_key: str, finding_id: int) -> str:
    taken = rule_ids(policy)
    base = f"{_ID_PREFIX[list_key]}-{int(finding_id)}"
    if base not in taken:
        return base
    n = 2
    while f"{base}-{n}" in taken:
        n += 1
    return f"{base}-{n}"


def _current(db: Database) -> tuple[Optional[int], dict]:
    cur = db.get_security_policy()
    if not cur:
        return None, empty_policy()
    pol, _errs = normalize_policy(cur.get("policy") or {})
    return int(cur["revision"]), pol


def _provenance(finding, hitl: dict, *, origin_paths: list[str], operator: str) -> dict:
    body = finding.body if isinstance(finding.body, dict) else {}
    return {
        "kind": PROVENANCE_KIND_HUMAN_REJECT,
        "finding_id": int(finding.id),
        "hitl_report_id": str(hitl.get("report_id") or finding_report_id(finding.id)),
        "hitl_block_id": str(hitl.get("block_id") or approval_block_id(finding.id)),
        "hitl_response_value": "changes-requested",
        "hitl_response_at": str(hitl.get("at") or ""),
        "hitl_note": str(hitl.get("note") or "").strip()[:MAX_PROVENANCE_NOTE_CHARS],
        "operator": str(operator or hitl.get("operator") or "operator"),
        "promoted_at": utc_now_iso(),
        "origin_paths": list(origin_paths),
        "origin_weakness_class": str(body.get("weakness_class") or "unknown").strip().lower()
        or "unknown",
    }


def would_match(
    db: Database,
    list_key: str,
    rule: dict,
    *,
    root: Optional[Path],
    source_finding_id: Optional[int] = None,
) -> dict[str, Any]:
    """Display-only: which current ``needs_human`` findings this rule covers.

    Uses the same ``match_exclusion`` the gate uses, on a one-rule policy.
    Changes nothing.
    """
    single = {list_key: [rule]}
    hits: list[dict[str, Any]] = []
    truncated = False
    matches_source: Optional[bool] = None
    for f in db.list_findings():
        body = f.body if isinstance(f.body, dict) else {}
        if source_finding_id is not None and f.id == int(source_finding_id):
            matches_source = match_exclusion(single, body, root=root) is not None
            continue
        if f.state != "needs_human":
            continue
        m = match_exclusion(single, body, root=root)
        if m and len(hits) >= _WOULD_MATCH_MAX:
            truncated = True
        elif m:
            hits.append(
                {
                    "finding_id": f.id,
                    "title": str(body.get("title") or "")[:200],
                    "weakness_class": body.get("weakness_class"),
                    "matched_paths": m.get("matched_paths") or [],
                }
            )
    return {"needs_human": hits, "truncated": truncated, "matches_source": matches_source}


def draft_rule_from_finding(
    db: Database, finding_id: int, *, target_list: str = "exclusions"
) -> dict[str, Any]:
    """Pre-filled, unsaved rule from a human-rejected finding."""
    if target_list not in PROMOTE_TARGETS:
        return _fail("bad_target_list", allowed=list(PROMOTE_TARGETS))
    ctx = reject_context(db, finding_id)
    if not ctx.get("ok"):
        return ctx
    finding, hitl = ctx["finding"], ctx["hitl"]
    body = finding.body if isinstance(finding.body, dict) else {}
    root = policy_root(db)
    paths = cited_paths(body, root)
    base_rev, policy = _current(db)
    note = str(hitl.get("note") or "").strip()
    rule: dict[str, Any] = {
        "id": _suggest_id(policy, target_list, finding.id),
        "paths": paths,
    }
    if target_list == "exclusions":
        rule["weakness_class"] = str(body.get("weakness_class") or "").strip().lower()
    rule["reason"] = note[:_REASON_MAX]
    warnings: list[str] = []
    if not paths:
        warnings.append("finding has no citation paths; add at least one glob")
    if not note:
        warnings.append("reject had no note; write a reason before saving")
    if len(note) > _REASON_MAX:
        warnings.append(f"reject note clipped to {_REASON_MAX} characters for the rule reason")
    if target_list == "exclusions" and not rule["weakness_class"]:
        warnings.append("finding has no weakness_class; set one (or choose all classes)")
    return {
        "ok": True,
        "saved": False,
        "finding_id": finding.id,
        "target_list": target_list,
        "targets": list(PROMOTE_TARGETS),
        "rule": rule,
        "base_revision": base_rev,
        "hitl": {
            "report_id": hitl.get("report_id"),
            "block_id": hitl.get("block_id"),
            "value": hitl.get("value"),
            "at": hitl.get("at"),
            "operator": hitl.get("operator"),
        },
        "warnings": warnings,
        "effect": MECH_EFFECT_COPY,
        "would_match": would_match(
            db, target_list, rule, root=root, source_finding_id=finding.id
        )
        if paths
        else {"needs_human": [], "truncated": False, "matches_source": None},
    }


def promote_rule(
    db: Database,
    run_dir: Path,
    finding_id: int,
    rule: Any,
    *,
    target_list: str = "exclusions",
    base_revision: Optional[int] = None,
    all_classes: bool = False,
    operator: str = "operator",
    note: str = "",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Validate (``dry_run``) or save the operator-edited rule as a new policy revision."""
    if target_list not in PROMOTE_TARGETS:
        return _fail("bad_target_list", allowed=list(PROMOTE_TARGETS))
    if not isinstance(rule, dict):
        return _fail("invalid_rule", errors=["rule must be an object"])
    edited = {k: v for k, v in rule.items() if k != "provenance"}

    if target_list == "exclusions":
        wc = edited.get("weakness_class")
        wc_s = wc.strip().lower() if isinstance(wc, str) else ""
        if all_classes:
            edited["weakness_class"] = "*"
        elif not wc_s or wc_s == "*":
            # normalize_policy would turn blank into "*" (every class). That
            # must be an explicit operator choice, never a default.
            return _fail(
                "invalid_rule",
                errors=["weakness_class is required (or choose all classes explicitly)"],
            )

    ctx = reject_context(db, finding_id)
    if not ctx.get("ok"):
        return ctx
    finding, hitl = ctx["finding"], ctx["hitl"]
    root = policy_root(db)
    cur_rev, policy = _current(db)
    if cur_rev != base_revision:
        return _fail(
            "policy_changed",
            detail=f"policy is at revision {cur_rev}, draft was built on {base_revision}",
            current_revision=cur_rev,
        )

    origin = cited_paths(finding.body if isinstance(finding.body, dict) else {}, root)
    stamped = {**edited, "provenance": _provenance(finding, hitl, origin_paths=origin, operator=operator)}
    doc = copy.deepcopy(policy)
    doc.setdefault(target_list, []).append(stamped)
    normalized, errors = normalize_policy(doc)
    if errors:
        return _fail("invalid_rule", errors=errors)
    saved_rule = normalized[target_list][-1]
    rule_id = str(saved_rule.get("id") or "")
    preview = would_match(db, target_list, saved_rule, root=root, source_finding_id=finding.id)
    if dry_run:
        return {
            "ok": True,
            "saved": False,
            "dry_run": True,
            "target_list": target_list,
            "rule": saved_rule,
            "base_revision": cur_rev,
            "would_match": preview,
            "effect": MECH_EFFECT_COPY,
        }

    fid = int(finding.id)
    at = str(hitl.get("at") or "")
    stamped_note = str(hitl.get("note") or "")

    def _still_rejected() -> Optional[str]:
        # Runs inside set_security_policy's BEGIN IMMEDIATE: plain SELECTs on
        # db.conn only (db helpers that ensure tables would commit the lock).
        row = db.conn.execute("SELECT state FROM findings WHERE id=?", (fid,)).fetchone()
        if row is None:
            return "finding_not_found"
        if row["state"] != "rejected_human":
            return "not_human_rejected"
        resp = db.conn.execute(
            "SELECT value, note, at FROM hitl_responses WHERE report_id=? AND block_id=?",
            (finding_report_id(fid), approval_block_id(fid)),
        ).fetchone()
        if resp is None or resp["value"] != "changes-requested":
            return "no_hitl_reject_response"
        if str(resp["at"] or "") != at or str(resp["note"] or "") != stamped_note:
            return "hitl_response_changed"
        return None

    rev_note = (
        f"promoted from finding #{fid} (HITL {hitl.get('report_id')}/{hitl.get('block_id')} "
        f"changes-requested @ {at}): {target_list} rule {rule_id}"
    )
    if note and note.strip():
        rev_note = f"{rev_note} — {note.strip()}"
    try:
        rev = db.set_security_policy(
            normalized,
            source="human_reject",
            note=rev_note,
            expected_revision=base_revision,
            new_provenance_rule=(target_list, rule_id),
            precheck=_still_rejected,
        )
    except PolicyConflictError as e:
        return _fail("policy_changed", detail=str(e), current_revision=e.current)
    except PolicyError as e:
        first = e.errors[0] if e.errors else ""
        if first in (
            "finding_not_found",
            "not_human_rejected",
            "no_hitl_reject_response",
            "hitl_response_changed",
        ):
            return _fail(first, detail="the reject changed while saving; nothing was stored")
        return _fail("invalid_rule", errors=e.errors)

    from vulnforge.util import append_event

    append_event(
        run_dir,
        {
            "event": "security_policy_updated",
            "source": "human_reject",
            "revision": rev,
            "finding_id": fid,
            "rule_id": rule_id,
            "target_list": target_list,
        },
    )
    return {
        "ok": True,
        "saved": True,
        "revision": rev,
        "target_list": target_list,
        "rule": saved_rule,
        "would_match": preview,
        "finding_state": finding.state,
    }
