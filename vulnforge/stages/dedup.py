"""Mechanical near-duplicate merge helpers (no LLM).

Used on hunt insert and by Report cluster / operator merge. Not a leased task kind.
"""

from __future__ import annotations

from typing import Any

from vulnforge.util import normalize_relpath

# More specific class wins when same sink path+symbol across classes
_CLASS_SPECIFICITY = {
    "ai-llm": 30,
    "injection": 20,
    "access-control": 20,
    "cryptography": 20,
    "web-protocol-auth": 18,
    "memory-safety": 18,
    "graphql": 18,
    "business-logic": 15,
    "client-side": 15,
    "supply-chain": 14,
    "feature-abuse": 12,
    "chains": 10,
    "obvious": 5,
    "wildcard": 1,
}


def primary_sink(body: dict) -> tuple[str, str]:
    """Return (normalized_path, symbol) for merge identity."""
    path = normalize_relpath(str(body.get("sink_path") or ""))
    symbol = str(body.get("sink_symbol") or "")
    if not path:
        cits = body.get("citations") or []
        if cits and isinstance(cits[0], dict):
            path = normalize_relpath(str(cits[0].get("path") or ""))
            if not symbol:
                symbol = str(cits[0].get("symbol") or "")
    # Prefer citation with symbol if first lacks it
    if not symbol:
        for c in body.get("citations") or []:
            if isinstance(c, dict) and c.get("symbol"):
                symbol = str(c.get("symbol"))
                if not path:
                    path = normalize_relpath(str(c.get("path") or ""))
                break
    return path, symbol


def merge_key(body: dict) -> str | None:
    """
    Cross-class merge key: path + non-empty symbol.

    Path-only (empty symbol) is too aggressive â€” models often omit symbols and
    distinct same-file sinks must not merge. Without a symbol, return None so
    mechanical near-dup is skipped (stable_key still handles exact identity).
    """
    path, symbol = primary_sink(body)
    if not path:
        return None
    sym = (symbol or "").strip()
    if not sym:
        return None
    return f"{path}|{sym.lower()}"


def class_rank(weakness_class: str) -> int:
    cls = str(weakness_class or "").lower()
    try:
        from vulnforge.hunt_profiles import specificity_for_class

        rank = int(specificity_for_class(cls) or 0)
        if rank > 0:
            return rank
    except Exception:
        pass
    return _CLASS_SPECIFICITY.get(cls, 10)


def _annotate_only(merged: dict, body: dict, old_cls: str, new_cls: str) -> dict:
    """Fold near-dup metadata without overwriting material finding body."""
    notes = list(merged.get("near_dup_titles") or [])
    title = body.get("title")
    if title and title not in notes:
        notes.append(title)
    merged["near_dup_titles"] = notes[:10]
    merged["merged_classes"] = sorted(
        {old_cls, new_cls, *(merged.get("merged_classes") or [])} - {""}
    )
    return merged


def merge_near_duplicate(
    db, body: dict, *, profile: str = "code_static"
) -> dict[str, Any] | None:
    """
    If an existing finding shares the same sink path+symbol, supersede the
    less-specific class (or update body on the keeper). No LLM.

    Returns merge info dict or None if no near-dup.

    revalidate:
      - True when material body fields changed (and state is candidate-like)
      - False when only annotations / protected keeper preserved
    Never demotes confirmed / needs_human / rejected_human (or other terminal
    rejects) by overwriting body then re-running mech gates; those keepers only
    receive annotation merges (rejected_human is skipped entirely).
    """
    key = merge_key(body)
    if not key:
        return None
    new_cls = str(body.get("weakness_class") or "")
    new_rank = class_rank(new_cls)

    # Annotate-only keepers: do not force candidate or revalidate.
    _ANNOTATE_ONLY_STATES = frozenset({"confirmed", "needs_human"})
    # Terminal rejects: skip like other closed rejects (no reopen).
    _SKIP_STATES = frozenset(
        ("rejected_mech", "rejected_llm", "rejected_human", "superseded")
    )

    for f in db.list_findings():
        if f.state in _SKIP_STATES:
            continue
        b = f.body or {}
        ek = merge_key(b)
        if ek is None or ek != key:
            continue
        # Same path+sink — decide keeper
        old_cls = str(b.get("weakness_class") or "")
        old_rank = class_rank(old_cls)
        annotate_only = f.state in _ANNOTATE_ONLY_STATES

        if new_rank > old_rank or (new_rank == old_rank and new_cls == old_cls):
            if annotate_only:
                # Do not overwrite material fields or re-open gates.
                merged = _annotate_only(dict(b), body, old_cls, new_cls)
                if new_rank > old_rank:
                    # Record that a more-specific class was seen without demotion
                    merged["merged_classes"] = sorted(
                        set(merged.get("merged_classes") or []) | {new_cls}
                    )
                fid = db.insert_finding(
                    merged,
                    state=f.state,
                    stable_key=f.stable_key,
                    profile=profile,
                )
                out = {
                    "superseded_existing": True,
                    "finding_id": fid,
                    "merge_key": key,
                    "kept_class": old_cls,
                    "prior_class": old_cls,
                    "revalidate": False,
                }
                if f.state == "confirmed":
                    out["confirmed_preserved"] = True
                if f.state == "needs_human":
                    out["needs_human_preserved"] = True
                return out
            # Candidate (or other open state): material update → revalidate
            merged = dict(b)
            merged.update({k: v for k, v in body.items() if v is not None})
            merged["weakness_class"] = (
                new_cls if new_rank >= old_rank else old_cls
            )
            merged.setdefault("near_dup_of", f.id)
            merged["merged_classes"] = sorted(
                {old_cls, new_cls, *(merged.get("merged_classes") or [])}
                - {""}
            )
            # Always re-validate from candidate after material body change
            fid = db.insert_finding(
                merged,
                state="candidate",
                stable_key=f.stable_key,
                profile=profile,
            )
            return {
                "superseded_existing": True,
                "finding_id": fid,
                "merge_key": key,
                "kept_class": merged["weakness_class"],
                "prior_class": old_cls,
                "revalidate": True,
            }
        # Existing more specific → annotate only; never revalidate
        merged = _annotate_only(dict(b), body, old_cls, new_cls)
        fid = db.insert_finding(
            merged,
            state=f.state,
            stable_key=f.stable_key,
            profile=profile,
        )
        return {
            "superseded_existing": True,
            "finding_id": fid,
            "merge_key": key,
            "kept_class": old_cls,
            "dropped_class": new_cls,
            "near_dup": True,
            "revalidate": False,
        }
    return None


# Keeper preference for cluster labels (lower = better primary).
_CLUSTER_STATE_RANK = {
    "confirmed": 0,
    "needs_human": 1,
    "candidate": 2,
    "rejected_mech": 10,
    "rejected_llm": 11,
    "rejected_human": 12,
}


def _cluster_sort_key(f) -> tuple:
    """confirmed > needs_human > candidate; then lower id first."""
    rank = _CLUSTER_STATE_RANK.get(str(f.state or ""), 50)
    return (rank, int(f.id))


def _member_dict(f, label: str) -> dict[str, Any]:
    body = f.body or {}
    path, symbol = primary_sink(body)
    return {
        "id": int(f.id),
        "label": label,
        "state": f.state,
        "title": body.get("title") or f.stable_key or f"Finding #{f.id}",
        "class": body.get("weakness_class") or "",
        "path": path or "",
        "symbol": symbol or "",
        "stable_key": f.stable_key,
        "near_dup": bool(
            body.get("merged_classes")
            or body.get("near_dup_titles")
            or body.get("superseded_by")
            or f.state == "superseded"
        ),
        "merged_classes": list(body.get("merged_classes") or []),
        "near_dup_titles": list(body.get("near_dup_titles") or []),
        "superseded_by": body.get("superseded_by"),
    }


def _label_for_index(index: int) -> str:
    """0 -> 1A, 1 -> 1B, … 25 -> 1Z, 26 -> 1AA (rare)."""
    n = index
    letters = ""
    while True:
        letters = chr(ord("A") + (n % 26)) + letters
        n = n // 26 - 1
        if n < 0:
            break
    return f"1{letters}"


def _build_cluster(
    cluster_index: int,
    members_sorted: list,
    *,
    strength: str,
    group_key: str,
) -> dict[str, Any]:
    labeled = []
    for i, f in enumerate(members_sorted):
        labeled.append(_member_dict(f, _label_for_index(i)))
    primary = members_sorted[0]
    return {
        "cluster_id": f"c{cluster_index}",
        "primary_id": int(primary.id),
        "strength": strength,  # merge_key | path_only
        "group_key": group_key,
        "size": len(labeled),
        "members": labeled,
    }


def cluster_findings(db) -> list[dict[str, Any]]:
    """
    Group non-superseded findings for operator overlap review.

    - Strong clusters: same merge_key (path|symbol) when symbol present
    - Weak clusters: same path without symbol (path-only; report-time only)
    - Exact stable_key is unique in DB so never multi-member

    Each cluster:
      { cluster_id, primary_id, strength, group_key, size,
        members: [{id, label "1A"|"1B", state, title, class, path, symbol, …}] }

    Labels: keeper first (confirmed > needs_human > candidate; then lower id)
    as 1A, then 1B, 1C, …
    Only multi-member clusters are returned.
    """
    findings = [
        f
        for f in db.list_findings()
        if f.state not in ("superseded",)
    ]

    by_merge: dict[str, list] = {}
    by_path_weak: dict[str, list] = {}
    for f in findings:
        body = f.body or {}
        mk = merge_key(body)
        if mk:
            by_merge.setdefault(mk, []).append(f)
            continue
        path, _sym = primary_sink(body)
        if path:
            by_path_weak.setdefault(path, []).append(f)

    clusters: list[dict[str, Any]] = []
    idx = 1
    # Strong first, stable order by group_key
    for key in sorted(by_merge.keys()):
        group = by_merge[key]
        if len(group) < 2:
            continue
        ordered = sorted(group, key=_cluster_sort_key)
        clusters.append(
            _build_cluster(idx, ordered, strength="merge_key", group_key=key)
        )
        idx += 1
    for path in sorted(by_path_weak.keys()):
        group = by_path_weak[path]
        if len(group) < 2:
            continue
        ordered = sorted(group, key=_cluster_sort_key)
        clusters.append(
            _build_cluster(
                idx, ordered, strength="path_only", group_key=f"path:{path}"
            )
        )
        idx += 1
    return clusters


def merge_findings(db, keep_id: int, drop_ids: list[int]) -> dict[str, Any]:
    """
    Mark drop_ids as superseded; link each to keep_id via body.superseded_by.

    Annotates the keeper with merged_classes / near_dup_titles from dropped
    findings. Does **not** change keeper state (never auto-confirms).
    """
    import json

    keep = db.get_finding(keep_id)
    if not keep:
        raise KeyError(keep_id)
    if keep.state == "superseded":
        raise ValueError("cannot keep a superseded finding")

    keep_body = dict(keep.body or {})
    titles = list(keep_body.get("near_dup_titles") or [])
    classes: set[str] = set(keep_body.get("merged_classes") or [])
    kc = str(keep_body.get("weakness_class") or "")
    if kc:
        classes.add(kc)

    dropped: list[int] = []
    for did in drop_ids or []:
        did_i = int(did)
        if did_i == int(keep_id):
            continue
        f = db.get_finding(did_i)
        if not f:
            continue
        body = dict(f.body or {})
        body["superseded_by"] = int(keep_id)
        title = body.get("title")
        if title and title not in titles:
            titles.append(title)
        cls = str(body.get("weakness_class") or "")
        if cls:
            classes.add(cls)
        for t in body.get("near_dup_titles") or []:
            if t and t not in titles:
                titles.append(t)
        for c in body.get("merged_classes") or []:
            if c:
                classes.add(str(c))
        db.conn.execute(
            """
            UPDATE findings SET state=?, body_json=?, updated_at=datetime('now')
            WHERE id=?
            """,
            ("superseded", json.dumps(body), did_i),
        )
        dropped.append(did_i)

    keep_body["near_dup_titles"] = titles[:20]
    keep_body["merged_classes"] = sorted(c for c in classes if c)
    # Keep state unchanged — never promote to confirmed.
    db.conn.execute(
        """
        UPDATE findings SET body_json=?, updated_at=datetime('now')
        WHERE id=?
        """,
        (json.dumps(keep_body), int(keep_id)),
    )
    db.conn.commit()
    return {
        "ok": True,
        "keep_id": int(keep_id),
        "dropped_ids": dropped,
        "keep_state": keep.state,
        "merged_classes": keep_body["merged_classes"],
        "near_dup_titles": keep_body["near_dup_titles"],
    }
