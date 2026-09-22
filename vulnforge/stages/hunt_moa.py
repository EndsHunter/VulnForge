"""Hunt mixture-of-agents helpers (spike #68, wired by #71).

Pure resolve + merge for sequential multi-perspective hunt. Mirrors
``validate_llm.resolve_disprove_verifiers`` / ``aggregate_disprove_verdicts``:
config slots, then a merge that never confirms.

``stages.hunt.run`` loops perspectives only when ``stages.hunt_moa`` is true
(default off). ``build_hunt_moa_body`` is the finding-body contract #73 reads.
"""

from __future__ import annotations

import re
from typing import Any

from vulnforge.findings.identity import compute_stable_key
from vulnforge.findings.merge import merge_key

# Finding state this merge is allowed to emit. Human review is the only
# path to confirmed (PROTOCOL / HITL). Hunt MoA outputs candidates for
# validate_mech only.
EMIT_STATE = "candidate"
_FORBIDDEN_EMIT_STATES = frozenset({"confirmed"})

# Default slots when llm.hunt_perspectives is omitted. Prompt files live in
# seeds/system/ (hunt_sink.md, hunt_dataflow.md, hunt_authz.md).
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

    Missing / false → off. ``stages.hunt.run`` keeps the single-pass loop.
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


_TITLE_CLIP = 160
_REASON_CLIP = 240


def slot_evidence_id(task_id: int, perspective_id: str, index: int = 0) -> str:
    """Distinct evidence pack id for one MoA slot (session auth is per loop)."""
    from vulnforge.tools.evidence_write import InvalidEvidenceId, sanitize_evidence_id

    raw = f"t{int(task_id)}-{perspective_id}"
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip("-._")
    if not cleaned or not cleaned[0].isalnum():
        cleaned = f"t{int(task_id)}p{int(index) + 1}"
    cleaned = cleaned[:128]
    try:
        return sanitize_evidence_id(cleaned)
    except InvalidEvidenceId:
        return sanitize_evidence_id(f"t{int(task_id)}p{int(index) + 1}")


def build_hunt_moa_body(
    slots: list[dict[str, Any]] | None,
    *,
    n_perspectives: int,
    agree_count: int = 0,
    cell_outcome: str = "none",
) -> dict[str, Any]:
    """Build the ``body.hunt_moa`` object (#71 writes, #73 reads).

    ``slots`` use internal outcomes ``candidate`` | ``none`` | ``aborted`` |
    ``skipped``. Public perspective outcomes are only ``candidate`` or ``none``.
    ``requeue_note`` is ``all_perspectives_none``, ``partial_none``, or None.
    ``label`` is ``{agree_count}/{n_perspectives} hunt agree``. Never confirmed.
    """
    n = max(0, int(n_perspectives))
    cell = str(cell_outcome or "").strip().lower()
    if cell != "candidate":
        cell = "none"
    agree = max(0, int(agree_count)) if cell == "candidate" else 0

    perspectives: list[dict[str, Any]] = []
    none_ids: list[str] = []
    internals: list[str] = []
    for i, raw in enumerate(slots or []):
        if not isinstance(raw, dict):
            pid = f"slot_{i + 1}"
            internal = "none"
            cand = None
            title = None
            reason = None
        else:
            pid = str(
                raw.get("perspective_id") or raw.get("id") or f"slot_{i + 1}"
            ).strip() or f"slot_{i + 1}"
            internal = str(raw.get("outcome") or "").strip().lower() or "none"
            cand = raw.get("candidate") if isinstance(raw.get("candidate"), dict) else None
            title = raw.get("title")
            reason = raw.get("reason") or raw.get("none_reason")
        internals.append(internal)
        public = "candidate" if internal == "candidate" else "none"
        entry: dict[str, Any] = {"id": pid, "outcome": public}
        if not title and isinstance(cand, dict):
            title = cand.get("title")
        if title and str(title).strip():
            entry["title"] = _clip(str(title), _TITLE_CLIP)
        if (not reason or not str(reason).strip()) and public == "candidate" and isinstance(
            cand, dict
        ):
            reason = cand.get("summary")
        if reason and str(reason).strip():
            entry["reason"] = _clip(str(reason), _REASON_CLIP)
        perspectives.append(entry)
        if public == "none" and pid not in none_ids:
            none_ids.append(pid)

    if cell == "candidate" and any(x == "none" for x in internals):
        note: str | None = "partial_none"
    elif cell == "none" and internals and all(x == "none" for x in internals):
        note = "all_perspectives_none"
    else:
        note = None

    record = {
        "perspectives": perspectives,
        "agree_count": agree,
        "label": f"{agree}/{n} hunt agree",
        "cell_outcome": cell,
        "requeue_note": note,
        "none_perspectives": none_ids,
    }
    _assert_never_confirmed(record)
    return record


def result_emits_confirmed(result: dict[str, Any] | None) -> bool:
    """True if any finding-state field in the merge result is ``confirmed``."""
    if not isinstance(result, dict):
        return False
    return _walk_emits_confirmed(result)


def _clip(text: str, limit: int) -> str:
    s = " ".join(str(text).split())
    if len(s) <= limit:
        return s
    if limit <= 3:
        return s[:limit]
    return s[: limit - 3].rstrip() + "..."


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
