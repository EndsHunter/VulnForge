"""Threshold and integrity evaluation for ``vf ci``.

Honesty rules (AGENTS.md):

* CI never sets ``confirmed``. A ``confirmed`` finding that appears during the
  CI loop without a human review record is an integrity failure (exit 2).
* A threshold hit on ``needs_human`` means "needs review", not "proven".
  ``confirmed`` means a human accepted it, which is still not exploit proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

from vulnforge.findings.severity import normalize_severity_claim

# Findings that are still "live" for a CI gate. rejected_*, superseded and
# candidate never meet a threshold.
LIVE_STATES: tuple[str, ...] = ("needs_human", "confirmed")
FAIL_ON_STATES: frozenset[str] = frozenset(LIVE_STATES)

SEVERITY_RANK: dict[str, int] = {
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Task states that mean a task ended without doing its job.
FAILED_TASK_STATES: tuple[str, ...] = ("deadletter", "failed_task", "blocked")

STATE_MEANING = {
    "needs_human": "needs review (mechanical gates passed; not proven)",
    "confirmed": "human-accepted (not exploit proof)",
}


def parse_fail_on_states(values: Optional[Iterable[str]]) -> frozenset[str]:
    """Accept repeatable and comma-separated ``--fail-on-state`` values."""
    out: set[str] = set()
    for raw in values or ():
        for part in str(raw).split(","):
            s = part.strip().lower()
            if not s:
                continue
            if s not in FAIL_ON_STATES:
                raise ValueError(
                    f"--fail-on-state {s!r}: choose from {sorted(FAIL_ON_STATES)}"
                )
            out.add(s)
    return frozenset(out)


def parse_min_severity(value: Optional[str]) -> Optional[str]:
    if value is None or not str(value).strip():
        return None
    sev = normalize_severity_claim(value)
    if sev is None:
        raise ValueError(
            f"--fail-on-severity {value!r}: choose from "
            f"{[s.lower() for s in SEVERITY_RANK]}"
        )
    return sev


@dataclass(frozen=True)
class Threshold:
    """``--fail-on-state`` and/or ``--fail-on-severity``.

    Both given: a finding must match both (state in the set AND severity at
    or above the level). One given: that predicate alone, over live states.
    Neither: no threshold, so findings never fail the job.

    Severity uses the optional ``severity_claim``. An unrated finding meets a
    severity threshold (fail closed): the harness cannot show it is lower.
    """

    states: frozenset[str] = frozenset()
    min_severity: Optional[str] = None

    @property
    def active(self) -> bool:
        return bool(self.states) or self.min_severity is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "fail_on_states": sorted(self.states),
            "fail_on_severity": self.min_severity.lower() if self.min_severity else None,
            "combine": "and" if self.states and self.min_severity else None,
            "unrated_severity": "meets threshold (fail closed)"
            if self.min_severity
            else None,
        }

    def match(self, state: str, body: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Return a match record, or None when the finding does not fail the gate."""
        if not self.active or state not in LIVE_STATES:
            return None
        if self.states and state not in self.states:
            return None
        sev = normalize_severity_claim((body or {}).get("severity_claim"))
        reasons = []
        if self.states:
            reasons.append(f"state={state}")
        if self.min_severity is not None:
            if sev is None:
                reasons.append("severity_unrated")
            elif SEVERITY_RANK[sev] >= SEVERITY_RANK[self.min_severity]:
                reasons.append(f"severity={sev.lower()}>={self.min_severity.lower()}")
            else:
                return None
        return {
            "severity": sev.lower() if sev else None,
            "reasons": reasons,
            "meaning": STATE_MEANING.get(state, state),
        }


def _location(body: dict[str, Any]) -> tuple[Optional[str], Optional[int]]:
    from vulnforge.export_findings import _primary_citation

    cit = _primary_citation(body)
    path = cit.get("path")
    line = cit.get("start_line")
    try:
        line_i = int(line) if line is not None else None
    except (TypeError, ValueError):
        line_i = None
    return (str(path) if path else None), line_i


def matched_findings(findings: Iterable[Any], threshold: Threshold) -> list[dict[str, Any]]:
    """Findings (``db.Finding``-like) that meet the threshold, in id order."""
    out: list[dict[str, Any]] = []
    for f in findings:
        body = dict(getattr(f, "body", None) or {})
        hit = threshold.match(str(getattr(f, "state", "")), body)
        if hit is None:
            continue
        path, line = _location(body)
        out.append(
            {
                "id": int(getattr(f, "id")),
                "state": str(getattr(f, "state")),
                "title": str(body.get("title") or "")[:300],
                "weakness_class": body.get("weakness_class") or None,
                "path": path,
                "line": line,
                "stable_key": getattr(f, "stable_key", None),
                **hit,
            }
        )
    return out


def confirmed_integrity_errors(
    findings: Iterable[Any], confirmed_before: Iterable[int]
) -> list[str]:
    """``confirmed`` findings new since the loop started must carry a human review.

    ``human_review_latest.to_state == "confirmed"`` is written only by
    ``control.ops.review_finding`` (human review and HITL approval). Anything
    else that turned a finding ``confirmed`` breaks the honesty rule.
    """
    before = {int(i) for i in confirmed_before}
    errors: list[str] = []
    for f in findings:
        if str(getattr(f, "state", "")) != "confirmed":
            continue
        fid = int(getattr(f, "id"))
        if fid in before:
            continue
        latest = (getattr(f, "body", None) or {}).get("human_review_latest")
        if not (isinstance(latest, dict) and latest.get("to_state") == "confirmed"):
            errors.append(f"confirmed_without_human_review: finding {fid}")
    return errors


def task_integrity_errors(task_counts: dict[str, int], *, completed: bool) -> list[str]:
    """A drained queue with zero successes and some failures is not a pass.

    Typical cause: a dead LLM endpoint. Infra failures requeue, then
    deadletter, and Ralph ends "idle" with nothing done. A budget stop with
    work still queued is a coverage gap instead, so it is not checked here.
    """
    if not completed:
        return []
    failed = sum(int(task_counts.get(s) or 0) for s in FAILED_TASK_STATES)
    if int(task_counts.get("succeeded") or 0) == 0 and failed > 0:
        return [f"no_task_succeeded: {failed} task(s) failed/deadlettered, 0 succeeded"]
    return []


def coverage_gaps(task_counts: dict[str, int]) -> dict[str, int]:
    """Reported, never failing on their own."""
    keys = (*FAILED_TASK_STATES, "queued", "leased", "paused", "cancelled")
    return {k: int(task_counts.get(k) or 0) for k in keys if task_counts.get(k)}


# Ralph stop classification -------------------------------------------------

RALPH_STOP_EVENTS = frozenset(
    {
        "idle",
        "budget_wall",
        "budget_tasks",
        "budget_iterations",
        "budget_cost",
        "stop_file",
        "infra_give_up",
        "config_halt",
        "unknown_exit",
    }
)
EARLY_STOP_REASONS = frozenset(
    {"budget_wall", "budget_tasks", "budget_iterations", "budget_cost", "stop_file"}
)
# Cost-hook reasons where the cap could not be enforced.
COST_ERROR_REASONS = frozenset({"cost_unpriced", "cost_unmeasured"})


def classify_ralph_stop(
    ralph_code: int, last_event: Optional[dict[str, Any]]
) -> tuple[str, Optional[str]]:
    """Map Ralph's exit and last stop event to ``(stop_reason, error_or_None)``.

    Ralph exit 40 covers wall, iterations, max-tasks and the cost hook, so the
    reason comes from the last Ralph event, not the code.
    """
    ev = dict(last_event or {})
    name = str(ev.get("event") or "")
    if ralph_code == 10:
        return "idle", None
    if ralph_code == 40:
        if name == "budget_cost":
            reason = str(ev.get("reason") or "budget_cost")
            if reason in COST_ERROR_REASONS:
                detail = ev.get("detail") or ev.get("unpriced_models")
                return reason, f"{reason}: cost cap cannot be enforced ({detail})"
            return "budget_cost", None
        if name in EARLY_STOP_REASONS:
            return name, None
        return "budget", None
    if ralph_code == 0:
        return "stop_file", None
    if ralph_code == 20:
        return "infra_give_up", "ralph_infra: consecutive infra failures exhausted"
    if ralph_code == 30:
        return "config_halt", "ralph_config: config/hard error from vf run-once"
    if ralph_code == 130:
        return "interrupted", "ralph_interrupted"
    return "unknown", f"ralph_unknown_exit: {ralph_code}"
