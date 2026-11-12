"""Track findings in an external issue tracker (#189).

Two entry points, both behind explicit human confirmation:

* Dashboard: ``preview_track`` (no network) mints a one-shot token bound to
  the run, sink, destination, ``include_needs_human``, finding ids and a hash
  of each rendered body. ``publish_with_token`` consumes it.
* Operator chat: the ``track_findings`` mutator runs ``track_findings`` only
  after UI Confirm (``operator_chat.confirm``).

Eligibility is re-checked at publish time. Default is ``confirmed`` only;
``needs_human`` needs a per-call opt-in (config cannot turn it on). Finding
state is never changed. Ralph and the stages never import this module.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from vulnforge.db import Database
from vulnforge.tracking.base import TrackingError, build_sink
from vulnforge.tracking.github import create_labels, redact
from vulnforge.tracking.render import render_issue
from vulnforge.util import append_event

MAX_PER_PUBLISH = 25
TOKEN_TTL_S = 600
DEFAULT_SINK = "github"


def tracking_config(cfg: Optional[dict] = None) -> dict[str, Any]:
    if cfg is None:
        try:
            from vulnforge.settings.load import load_config

            cfg = load_config()
        except Exception:  # noqa: BLE001 — missing config → defaults
            cfg = {}
    tc = cfg.get("tracking") if isinstance(cfg, dict) else None
    return dict(tc) if isinstance(tc, dict) else {}


def resolve_destination(
    tcfg: dict[str, Any], sink: Optional[str], destination: Optional[str]
) -> tuple[str, str]:
    name = str(sink or tcfg.get("sink") or DEFAULT_SINK).strip().lower()
    dest = str(destination or "").strip()
    if not dest:
        sub = tcfg.get(name) if isinstance(tcfg.get(name), dict) else {}
        dest = str(sub.get("repo") or sub.get("destination") or "").strip()
    if not dest:
        raise TrackingError(
            f"no destination for sink {name!r}: pass repo (owner/name) or set "
            f"tracking.{name}.repo in config"
        )
    return name, dest


def _labels(tcfg: dict[str, Any], sink: str) -> list[str]:
    sub = tcfg.get(sink) if isinstance(tcfg.get(sink), dict) else {}
    raw = sub.get("labels") or []
    return [str(x).strip() for x in raw if str(x).strip()][:10] if isinstance(raw, list) else []


def eligible_states(include_needs_human: bool) -> frozenset[str]:
    return frozenset({"confirmed", "needs_human"} if include_needs_human else {"confirmed"})


def _norm_ids(finding_ids: Any) -> list[int]:
    out: list[int] = []
    for v in finding_ids or []:
        try:
            n = int(str(v).strip().lstrip("#"))
        except (TypeError, ValueError):
            continue
        if n > 0 and n not in out:
            out.append(n)
    return out


def _hash(title: str, body: str, labels: list[str]) -> str:
    blob = "\0".join([title, body, ",".join(labels)])
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _plan(
    db: Database,
    run_dir: Path,
    ids: list[int],
    *,
    include_needs_human: bool,
    sink: str,
    destination: str,
    labels: list[str],
) -> list[dict[str, Any]]:
    allowed = eligible_states(include_needs_human)
    items: list[dict[str, Any]] = []
    for fid in ids:
        f = db.get_finding(fid)
        if not f:
            items.append({"finding_id": fid, "eligible": False, "reason": "finding not found"})
            continue
        item: dict[str, Any] = {
            "finding_id": f.id,
            "state": f.state,
            "stable_key": f.stable_key,
            "title": str((f.body or {}).get("title") or ""),
        }
        if f.state not in allowed:
            hint = (
                " (opt in to include needs_human)"
                if f.state == "needs_human"
                else ""
            )
            item.update(eligible=False, reason=f"state {f.state!r} is not eligible{hint}")
            items.append(item)
            continue
        payload = render_issue(f, run_dir=run_dir, run_id=run_dir.name, labels=labels)
        row = db.get_tracking(f.stable_key, sink, destination)
        linked = bool(row and row.get("status") == "linked" and row.get("external_id"))
        item.update(
            eligible=True,
            would="update" if linked else "create_or_update",
            existing_url=(row or {}).get("url") if linked else None,
            issue_title=payload.title,
            issue_body=payload.body_md,
            issue_labels=create_labels(payload.labels),
            body_hash=_hash(payload.title, payload.body_md, create_labels(payload.labels)),
            _payload=payload,
            _finding=f,
        )
        items.append(item)
    return items


def _public(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{k: v for k, v in it.items() if not k.startswith("_")} for it in items]


# --------------------------------------------------------------------------
# Preview tokens (dashboard). Process-local, one-shot, TTL-bound.
# --------------------------------------------------------------------------


@dataclass
class _Ticket:
    run_dir: str
    sink: str
    destination: str
    include_needs_human: bool
    hashes: dict[int, str]
    created_at: float = field(default_factory=time.time)


_TICKETS: dict[str, _Ticket] = {}


def _gc_tickets() -> None:
    now = time.time()
    for k in [k for k, t in _TICKETS.items() if now - t.created_at > TOKEN_TTL_S]:
        _TICKETS.pop(k, None)


def preview_track(
    run_dir: Path,
    finding_ids: Any,
    *,
    include_needs_human: bool = False,
    destination: Optional[str] = None,
    sink: Optional[str] = None,
    cfg: Optional[dict] = None,
) -> dict[str, Any]:
    """Plan a publish without any network call. Returns the exact issue text."""
    run_dir = Path(run_dir)
    ids = _norm_ids(finding_ids)
    if not ids:
        return {"ok": False, "error": "finding_ids required"}
    if len(ids) > MAX_PER_PUBLISH:
        return {"ok": False, "error": f"at most {MAX_PER_PUBLISH} findings per publish"}
    tcfg = tracking_config(cfg)
    try:
        sink_name, dest = resolve_destination(tcfg, sink, destination)
        build_sink(sink_name, tcfg, dest, transport=_no_network)  # validates name + destination
    except TrackingError as e:
        return {"ok": False, "error": str(e)}
    db = Database.open(run_dir / "harness.db")
    try:
        items = _plan(
            db, run_dir, ids,
            include_needs_human=bool(include_needs_human),
            sink=sink_name, destination=dest, labels=_labels(tcfg, sink_name),
        )
    finally:
        db.close()
    eligible = [it for it in items if it.get("eligible")]
    out: dict[str, Any] = {
        "ok": True,
        "sink": sink_name,
        "destination": dest,
        "include_needs_human": bool(include_needs_human),
        "items": _public(items),
        "eligible_count": len(eligible),
        "state_counts": _state_counts(eligible),
        "token": None,
    }
    if eligible:
        _gc_tickets()
        tok = secrets.token_urlsafe(24)
        _TICKETS[tok] = _Ticket(
            run_dir=str(run_dir.resolve()),
            sink=sink_name,
            destination=dest,
            include_needs_human=bool(include_needs_human),
            hashes={it["finding_id"]: it["body_hash"] for it in eligible},
        )
        out["token"] = tok
        out["expires_in_s"] = TOKEN_TTL_S
    return out


def _state_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    c: dict[str, int] = {}
    for it in items:
        c[str(it.get("state"))] = c.get(str(it.get("state")), 0) + 1
    return c


def _no_network(*_a: Any, **_k: Any) -> Any:
    raise TrackingError("preview must not call the sink")


def publish_with_token(
    run_dir: Path,
    token: str,
    *,
    operator: str = "operator",
    transport: Any = None,
    cfg: Optional[dict] = None,
) -> dict[str, Any]:
    """Consume a preview token and publish exactly what was previewed."""
    t = _TICKETS.pop(str(token or ""), None)
    if t is None or time.time() - t.created_at > TOKEN_TTL_S:
        return {"ok": False, "error": "preview token missing or expired; preview again"}
    if t.run_dir != str(Path(run_dir).resolve()):
        return {"ok": False, "error": "preview token belongs to another run"}
    return track_findings(
        run_dir,
        list(t.hashes),
        include_needs_human=t.include_needs_human,
        destination=t.destination,
        sink=t.sink,
        operator=operator,
        transport=transport,
        cfg=cfg,
        expected_hashes=t.hashes,
        source="dashboard",
    )


# --------------------------------------------------------------------------
# Publish
# --------------------------------------------------------------------------


def track_findings(
    run_dir: Path,
    finding_ids: Any,
    *,
    include_needs_human: bool = False,
    destination: Optional[str] = None,
    sink: Optional[str] = None,
    operator: str = "operator",
    transport: Any = None,
    cfg: Optional[dict] = None,
    expected_hashes: Optional[dict[int, str]] = None,
    source: str = "dashboard",
) -> dict[str, Any]:
    """Create or update one external issue per eligible finding.

    Callers must already hold explicit human confirmation. Per-finding errors
    are collected; one failure does not stop the batch.
    """
    run_dir = Path(run_dir)
    ids = _norm_ids(finding_ids)
    if not ids:
        return {"ok": False, "error": "finding_ids required"}
    if len(ids) > MAX_PER_PUBLISH:
        return {"ok": False, "error": f"at most {MAX_PER_PUBLISH} findings per publish"}
    tcfg = tracking_config(cfg)
    try:
        sink_name, dest = resolve_destination(tcfg, sink, destination)
        sk = build_sink(sink_name, tcfg, dest, transport=transport)
    except TrackingError as e:
        return {"ok": False, "error": redact(str(e))}

    results: list[dict[str, Any]] = []
    db = Database.open(run_dir / "harness.db")
    try:
        items = _plan(
            db, run_dir, ids,
            include_needs_human=bool(include_needs_human),
            sink=sink_name, destination=dest, labels=_labels(tcfg, sink_name),
        )
        for it in items:
            fid = it["finding_id"]
            if not it.get("eligible"):
                results.append({"finding_id": fid, "ok": False, "action": "skipped",
                                "reason": it.get("reason")})
                continue
            if expected_hashes is not None and expected_hashes.get(fid) != it["body_hash"]:
                results.append({"finding_id": fid, "ok": False, "action": "skipped",
                                "reason": "finding changed since preview; preview again"})
                continue
            try:
                res = _publish_one(db, sk, it["_finding"], it["_payload"], operator=operator)
            except TrackingError as e:
                results.append({"finding_id": fid, "ok": False, "action": "error",
                                "reason": redact(str(e))})
                continue
            except Exception as e:  # noqa: BLE001 — keep the batch going; redact
                results.append({"finding_id": fid, "ok": False, "action": "error",
                                "reason": redact(f"{type(e).__name__}: {e}")})
                continue
            results.append(res)
            append_event(
                run_dir,
                {
                    "source": source,
                    "event": "finding_tracked",
                    "finding_id": fid,
                    "operator": operator,
                    "sink": sink_name,
                    "destination": dest,
                    "url": res.get("url"),
                    "action": res.get("action"),
                },
            )
    finally:
        db.close()
    done = [r for r in results if r.get("ok")]
    return {
        "ok": bool(done) and len(done) == len(results),
        "partial": bool(done) and len(done) != len(results),
        "sink": sink_name,
        "destination": dest,
        "results": results,
        "published": len(done),
    }


def _publish_one(db: Database, sk: Any, finding: Any, payload: Any, *, operator: str) -> dict:
    key = finding.stable_key
    sink_name, dest = sk.name, sk.destination
    claim: Optional[str] = None
    row = db.get_tracking(key, sink_name, dest)
    if row and row.get("status") == "linked" and row.get("external_id"):
        res = sk.update(str(row["external_id"]), payload)
    else:
        claim, other = db.claim_tracking(
            key, sink_name, dest, finding_id=finding.id, operator=operator
        )
        if not claim:
            if other and other.get("status") == "linked" and other.get("external_id"):
                res = sk.update(str(other["external_id"]), payload)
            else:
                raise TrackingError("another publish for this finding is in progress")
        else:
            try:
                existing = sk.find_by_marker(key)
                # The scan can be slow; make sure nobody took the claim over.
                claim = db.refresh_tracking_claim(key, sink_name, dest, claim) or ""
                if not claim:
                    raise TrackingError("publish claim was taken over; retry later")
                res = (
                    sk.update(existing.external_id, payload)
                    if existing
                    else sk.create(payload)
                )
            except Exception:
                # Nothing recorded that we know of; a retry re-scans by marker.
                db.release_tracking_claim(key, sink_name, dest, claim)
                raise
    rec = db.record_tracking(
        key, sink_name, dest,
        external_id=res.external_id, url=res.url,
        finding_id=finding.id, state_at_track=finding.state, operator=operator,
        claim_token=claim or None,
    )
    if rec is None:
        raise TrackingError(
            f"{res.action} {res.url} but the publish claim was lost before it was "
            "recorded; check the tracker for a duplicate"
        )
    return {
        "finding_id": finding.id,
        "ok": True,
        **res.to_dict(),
        "tracked_at": rec.get("updated_at"),
    }
