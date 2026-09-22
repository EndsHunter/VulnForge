"""Hunt mixture-of-agents helpers (spike #68).

Pure resolve + merge for sequential multi-perspective hunt. Mirrors
``validate_llm.resolve_disprove_verifiers`` / ``aggregate_disprove_verdicts``:
config slots, then a merge that never confirms.

This module is the thin proof. ``stages.hunt.run`` does not loop perspectives
until a follow-up PR turns ``stages.hunt_moa`` on (default off).
"""

from __future__ import annotations

from typing import Any

from vulnforge.findings.identity import compute_stable_key
from vulnforge.findings.merge import merge_key

# Finding state this merge is allowed to emit. Human review is the only
# path to confirmed (PROTOCOL / HITL). Hunt MoA outputs candidates for
# validate_mech only.
EMIT_STATE = "candidate"
_FORBIDDEN_EMIT_STATES = frozenset({"confirmed"})

# Default slots when llm.hunt_perspectives is omitted. Prompt files land
# with the wiring PR; resolve only names them.
_DEFAULT_HUNT_PERSPECTIVES: list[dict[str, str]] = [
    {"id": "sink_driven", "prompt": "hunt_sink.md"},
    {"id": "dataflow", "prompt": "hunt_dataflow.md"},
    {"id": "authz", "prompt": "hunt_authz.md"},
]


def default_hunt_perspective_prompt(perspective_id: str) -> str:
    """Prompt file for a perspective id.

    Known built-in ids keep their spike filenames. Any other id gets
    ``hunt_<id>.md`` so a Settings row without a prompt is still resolvable.
    """
    pid = str(perspective_id or "").strip()
    for row in _DEFAULT_HUNT_PERSPECTIVES:
        if row["id"] == pid:
            return row["prompt"]
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in pid).strip("_")
    return f"hunt_{safe or 'perspective'}.md"


def hunt_moa_enabled(cfg: dict) -> bool:
    """Return True only when stages.hunt_moa is explicitly on.

    Missing / false → off. Hunt.py must keep today's single-pass loop
    until the wiring PR reads this flag.
    """
    stages = cfg.get("stages") if isinstance(cfg, dict) else None
    if not isinstance(stages, dict):
        return False
    return bool(stages.get("hunt_moa"))


def resolve_hunt_perspectives(cfg: dict) -> list[dict[str, Any]]:
    """Return ordered hunt perspective slots from config or built-in defaults.

    Same shape as ``resolve_disprove_verifiers``: ``id``, ``prompt``, optional
    ``model``. Invalid rows are skipped. Empty/missing list → defaults.
    """
    llm = (cfg.get("llm") if isinstance(cfg, dict) else None) or {}
    raw = llm.get("hunt_perspectives") if isinstance(llm, dict) else None
    if not isinstance(raw, list) or not raw:
        return [dict(x) for x in _DEFAULT_HUNT_PERSPECTIVES]
    out: list[dict[str, Any]] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        pid = str(item.get("id") or f"perspective_{i + 1}").strip() or f"perspective_{i + 1}"
        prompt = str(item.get("prompt") or "").strip()
        if not prompt:
            continue
        slot: dict[str, Any] = {"id": pid, "prompt": prompt}
        if item.get("model") is not None:
            slot["model"] = item.get("model")
        out.append(slot)
    return out if out else [dict(x) for x in _DEFAULT_HUNT_PERSPECTIVES]


def merge_hunt_candidates(
    perspective_results: list[dict[str, Any]] | None,
    *,
    profile: str = "code_static",
) -> dict[str, Any]:
    """Pure merge/rank of per-perspective hunt outcomes.

    Each item is a dict with:
      - ``perspective_id`` (str)
      - ``outcome``: ``candidate`` | ``none`` (other values treated as none)
      - ``candidate``: finding body dict when outcome is candidate
      - ``none_reason``: optional str

    Returns a result whose ranked ``candidates`` always use ``state=candidate``.
    No path sets ``confirmed``. Empty / all-none → ``cell_outcome=none``.
    """
    rows = list(perspective_results or [])
    none_ids: list[str] = []
    collected: list[dict[str, Any]] = []

    for i, raw in enumerate(rows):
        if not isinstance(raw, dict):
            none_ids.append(f"slot_{i + 1}")
            continue
        pid = str(raw.get("perspective_id") or f"slot_{i + 1}").strip() or f"slot_{i + 1}"
        body = raw.get("candidate")
        outcome = str(raw.get("outcome") or "").strip().lower()
        has_body = isinstance(body, dict) and body
        if outcome == "candidate" or (not outcome and has_body):
            if not has_body:
                none_ids.append(pid)
                continue
            collected.append(_normalize_slot(pid, body, profile))
        else:
            none_ids.append(pid)

    if not collected:
        return _empty_none(none_ids, n_slots=len(rows))

    clusters = _cluster_slots(collected)
    ranked: list[dict[str, Any]] = []
    for members in clusters:
        ranked.append(_collapse_cluster(members))
    ranked.sort(
        key=lambda c: (
            -int(c["agree_count"]),
            -int(c["rank_score"]["richness"]),
            str(c["identity"]),
        )
    )

    result = {
        "candidates": ranked,
        "cell_outcome": "candidate",
        "all_none": False,
        "none_perspectives": none_ids,
        "requeue_note": _requeue_note(all_none=False, any_candidate=True, none_ids=none_ids),
    }
    _assert_never_confirmed(result)
    return result


def result_emits_confirmed(result: dict[str, Any] | None) -> bool:
    """True if any finding-state field in the merge result is ``confirmed``."""
    if not isinstance(result, dict):
        return False
    return _walk_emits_confirmed(result)


def _normalize_slot(perspective_id: str, body: dict, profile: str) -> dict[str, Any]:
    clean = dict(body)
    clean.pop("state", None)
    sk = compute_stable_key(profile, clean)
    mk = merge_key(clean)
    return {
        "perspective_id": perspective_id,
        "body": clean,
        "stable_key": sk,
        "merge_key": mk,
        "richness": _evidence_richness(clean),
    }


def _cluster_slots(slots: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    n = len(slots)
    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    by_stable: dict[str, int] = {}
    by_merge: dict[str, int] = {}
    for i, slot in enumerate(slots):
        sk = slot["stable_key"]
        if sk in by_stable:
            union(i, by_stable[sk])
        else:
            by_stable[sk] = i
        mk = slot.get("merge_key")
        if mk:
            if mk in by_merge:
                union(i, by_merge[mk])
            else:
                by_merge[mk] = i

    groups: dict[int, list[dict[str, Any]]] = {}
    for i, slot in enumerate(slots):
        groups.setdefault(find(i), []).append(slot)
    return list(groups.values())


def _collapse_cluster(members: list[dict[str, Any]]) -> dict[str, Any]:
    keeper = max(members, key=lambda m: (int(m["richness"]), -members.index(m)))
    body = dict(keeper["body"])
    body.pop("state", None)
    perspectives: list[str] = []
    for m in members:
        pid = str(m["perspective_id"])
        if pid not in perspectives:
            perspectives.append(pid)
    titles: list[str] = []
    for m in members:
        title = m["body"].get("title")
        if title and title not in titles:
            titles.append(str(title))
    if len(titles) > 1:
        extras = [t for t in titles if t != body.get("title")]
        if extras:
            body["near_dup_titles"] = extras[:10]
    identity = keeper["stable_key"]
    emit = {
        "body": body,
        "state": EMIT_STATE,
        "identity": identity,
        "stable_key": keeper["stable_key"],
        "merge_key": keeper.get("merge_key"),
        "agree_count": len(perspectives),
        "perspectives": perspectives,
        "rank_score": {
            "agree": len(perspectives),
            "richness": int(keeper["richness"]),
        },
    }
    if emit["state"] in _FORBIDDEN_EMIT_STATES:
        emit["state"] = EMIT_STATE
    return emit


def _evidence_richness(body: dict) -> int:
    cits = body.get("citations") or []
    n_cits = len(cits) if isinstance(cits, list) else 0
    score = min(n_cits, 8) * 2
    if body.get("evidence_id"):
        score += 6
    tm = body.get("threat_model") or {}
    if isinstance(tm, dict) and any(bool(v) for v in tm.values()):
        score += 3
    summary = str(body.get("summary") or "")
    if len(summary) >= 80:
        score += 2
    elif len(summary) >= 20:
        score += 1
    if body.get("poc_relpath"):
        score += 2
    return score


def _requeue_note(*, all_none: bool, any_candidate: bool, none_ids: list[str]) -> str | None:
    """Document-only hint. Wiring PR owns actual requeue policy."""
    if all_none:
        return (
            "all_perspectives_none: keep cell as none; existing shallow-none "
            "requeue in hunt.py still applies at the lease level"
        )
    if any_candidate and none_ids:
        return (
            "partial_none: keep best-ranked candidate; do not close the cell "
            "as none because at least one perspective produced a candidate"
        )
    return None


def _empty_none(none_ids: list[str], *, n_slots: int) -> dict[str, Any]:
    result = {
        "candidates": [],
        "cell_outcome": "none",
        "all_none": True,
        "none_perspectives": none_ids,
        "requeue_note": _requeue_note(all_none=True, any_candidate=False, none_ids=none_ids)
        if n_slots
        else None,
    }
    _assert_never_confirmed(result)
    return result


def _assert_never_confirmed(result: dict[str, Any]) -> None:
    if result_emits_confirmed(result):
        raise AssertionError("hunt MoA merge must never emit finding state confirmed")


def _walk_emits_confirmed(obj: Any) -> bool:
    if isinstance(obj, dict):
        state = obj.get("state")
        if isinstance(state, str) and state.strip().lower() == "confirmed":
            return True
        return any(_walk_emits_confirmed(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_walk_emits_confirmed(v) for v in obj)
    return False
