"""Derived evidence tier for a finding (label only).

One pure function, :func:`evidence_tier`, reads fields that already live on the
finding body and returns how much evidence backs the finding, weakest first:

``ungated``     mechanical gates have not passed (candidate, rejected_mech, …)
``gated``       mechanical gates passed; disprove off, pending, skipped, split
                or not run
``stood``       dual disprove ran and every slot returned ``stand``
``reproduced``  the latest finished sandbox PoC run returned ``signal_observed``

Rank 30 is left free for a future "a deterministic tool agrees with the flow"
tier between ``stood`` and ``reproduced``. Nothing feeds it today.

Honesty rules: the tier is a label. It never sets ``confirmed``, never changes
finding state and never raises severity. ``stood`` is still a weak signal
(same-model stand weaker still). ``reproduced`` means a signal was observed in
the sandbox, nothing more. A PoC run that returned ``signal_absent``,
``poc_broken``, ``inconclusive`` or a fail-closed verdict does not raise the
tier but is reported under ``poc`` so the UI can show it next to the tier.

Readers: the run snapshot (findings API), the HITL packet
(``vulnforge/hitl.py``), the exports (``vulnforge/export_findings.py``) and the
``human_review`` entry written on Accept / Reject (``control/ops.py``).
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

SCHEMA_ID = "vulnforge/evidence-tier@1"

TIERS = ("ungated", "gated", "stood", "reproduced")
# Spaced so a tier can slot in between without renumbering (30 is reserved).
TIER_RANK = {"ungated": 0, "gated": 10, "stood": 20, "reproduced": 40}
TIER_LABEL = {
    "ungated": "Not gated",
    "gated": "Gated",
    "stood": "Stood",
    "reproduced": "Reproduced",
}

# States that are only reachable after the mech gates passed. Used for older
# findings that predate the ``validation_mech`` stamp.
_POST_MECH_STATES = frozenset(
    {"needs_human", "confirmed", "rejected_llm", "rejected_human"}
)

# PoC verdicts recorded by validate_poc / iterate_poc. Only signal_observed
# raises the tier; the rest stay visible next to it.
POC_VERDICTS = frozenset(
    {
        "signal_observed",
        "signal_absent",
        "poc_broken",
        "inconclusive",
        "build_failed",
        "sandbox_unavailable",
        "unsafe_skipped",
    }
)

DISPROVE_TEXT = {
    "stand": "every disprove slot could not disprove it",
    "split": "disprove slots disagreed",
    "rejected": "every disprove slot rejected it",
    "pending": "disprove is queued or running",
    "off": "disprove is turned off",
    "skipped": "disprove was skipped",
    "inconclusive": "disprove returned no usable verdict",
    "not_run": "disprove has not run",
}


def _dict(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _mech_passed(body: Mapping[str, Any], state: str) -> bool:
    mech = body.get("validation_mech")
    if state == "rejected_mech":
        return False
    if isinstance(mech, dict) and mech.get("status") is not None:
        return str(mech.get("status") or "").lower() == "passed"
    # Older findings without the stamp: infer from a post-mech state.
    return state in _POST_MECH_STATES


def _disprove(body: Mapping[str, Any]) -> dict[str, Any]:
    mech = _dict(body.get("validation_mech"))
    llm = body.get("validation_llm")
    out: dict[str, Any] = {
        "status": "not_run",
        "verdict": None,
        "stood": None,
        "total": None,
        "models": 0,
        "same_model": None,
        "label": None,
    }
    if mech.get("pending_llm"):
        out["status"] = "pending"
        return out
    if not isinstance(llm, dict):
        return out

    status = str(llm.get("status") or "").lower()
    verdict = str(llm.get("verdict") or "").lower()
    out["verdict"] = verdict or None
    for k in ("stood", "total"):
        if isinstance(llm.get(k), int):
            out[k] = llm[k]
    out["label"] = llm.get("multi_model_label") or llm.get("label")

    verifiers = [v for v in (llm.get("verifiers") or []) if isinstance(v, dict)]
    ids = [str(v.get("model_id") or "").strip() for v in verifiers]
    distinct = {i for i in ids if i}
    out["models"] = len(distinct)
    if len(verifiers) >= 2 and all(ids):
        out["same_model"] = len(distinct) == 1

    if status == "disabled_after_enqueue":
        out["status"] = "off"
    elif status.startswith("skipped") or verdict == "skipped":
        out["status"] = "skipped"
    elif status == "partial" or verdict == "pending":
        out["status"] = "pending"
    elif verdict == "stand":
        out["status"] = "stand"
    elif verdict == "reject":
        out["status"] = "rejected"
    elif verdict == "needs_human":
        slot = [str(v.get("verdict") or "").lower() for v in verifiers]
        out["status"] = (
            "split" if any(s in ("stand", "reject") for s in slot) else "inconclusive"
        )
    else:
        out["status"] = "inconclusive"
    return out


def _poc(body: Mapping[str, Any]) -> Optional[dict[str, Any]]:
    """Latest *finished* sandbox run. An enqueue marker does not erase it."""
    latest = body.get("poc_validation_latest")
    pending = isinstance(latest, dict) and not latest.get("verdict")
    run: Optional[dict] = None
    if isinstance(latest, dict) and latest.get("verdict"):
        run = latest
    else:
        hist = body.get("poc_validation")
        if isinstance(hist, list):
            for entry in reversed(hist):
                if isinstance(entry, dict) and entry.get("verdict"):
                    run = entry
                    break
    if run is None and not pending:
        return None
    verdict = str((run or {}).get("verdict") or "").lower() or None
    return {
        "verdict": verdict,
        "at": (run or {}).get("at"),
        "pending": bool(pending),
        "raises_tier": verdict == "signal_observed",
    }


def _summary(tier: str, disprove: dict, poc: Optional[dict]) -> str:
    if tier == "ungated":
        return "Mechanical gates have not passed."
    if tier == "reproduced":
        text = (
            "Signal observed in the sandbox PoC run. "
            "Not exploit proof; a person still decides."
        )
    elif tier == "stood":
        text = "Gates passed and " + DISPROVE_TEXT["stand"]
        if disprove.get("same_model"):
            text += " (same model on every slot, weaker still)"
        elif disprove.get("models", 0) >= 2:
            text += f" ({disprove['models']} models)"
        text += ". A weak signal, not proof."
    else:
        text = (
            "Mechanical gates passed; "
            + DISPROVE_TEXT.get(disprove.get("status") or "not_run", "disprove has not run")
            + "."
        )
    if poc and not poc.get("raises_tier"):
        if poc.get("verdict"):
            text += f" Latest sandbox run: {poc['verdict']} (does not raise the tier)."
        elif poc.get("pending"):
            text += " A sandbox run is queued."
    return text


def evidence_tier(body: Optional[Mapping[str, Any]], state: Optional[str] = None) -> dict[str, Any]:
    """Derive the evidence tier from a finding body (+ its state). Pure; no I/O.

    Never mutates ``body``. The result is a label for sorting and display.
    """
    b: Mapping[str, Any] = body if isinstance(body, Mapping) else {}
    st = str(state or "").strip().lower()
    disprove = _disprove(b)
    poc = _poc(b)
    if not _mech_passed(b, st):
        tier = "ungated"
    elif poc and poc["raises_tier"]:
        tier = "reproduced"
    elif disprove["status"] == "stand":
        tier = "stood"
    else:
        tier = "gated"
    return {
        "schema": SCHEMA_ID,
        "tier": tier,
        "rank": TIER_RANK[tier],
        "label": TIER_LABEL[tier],
        "summary": _summary(tier, disprove, poc),
        "disprove": disprove,
        "poc": poc,
    }


def evidence_tier_for_finding(finding: Any) -> dict[str, Any]:
    """Convenience wrapper for a ``Finding`` row or a ``{state, body}`` dict."""
    if isinstance(finding, Mapping):
        return evidence_tier(finding.get("body"), finding.get("state"))
    return evidence_tier(getattr(finding, "body", None), getattr(finding, "state", None))
