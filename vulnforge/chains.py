"""
Attack chain builder — operator research tool (not exploit proof).

Chains live under ``evidence/chains/<chain_id>.json`` inside a run directory.
Automation never auto-confirms findings; chains are human-curated narratives.
"""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any, Optional

from vulnforge.util import utc_now_iso

CHAINS_SUBDIR = Path("evidence") / "chains"
_SAFE_ID = re.compile(r"^[a-zA-Z0-9._-]{8,64}$")
DEFAULT_INCLUDE_STATES = ("confirmed",)
ALLOWED_INCLUDE_STATES = frozenset({"confirmed", "needs_human", "candidate"})


def chains_dir(run_dir: Path) -> Path:
    return Path(run_dir) / CHAINS_SUBDIR


def _validate_chain_id(chain_id: str) -> str:
    cid = str(chain_id or "").strip()
    if not _SAFE_ID.match(cid):
        raise ValueError(f"invalid chain id: {chain_id!r}")
    return cid


def _chain_path(run_dir: Path, chain_id: str) -> Path:
    cid = _validate_chain_id(chain_id)
    return chains_dir(run_dir) / f"{cid}.json"


def _normalize_include_states(states: Optional[list[str] | tuple[str, ...]]) -> list[str]:
    if not states:
        return list(DEFAULT_INCLUDE_STATES)
    out: list[str] = []
    for s in states:
        st = str(s or "").strip().lower()
        if st in ALLOWED_INCLUDE_STATES and st not in out:
            out.append(st)
    return out or list(DEFAULT_INCLUDE_STATES)


def _normalize_step(step: dict[str, Any]) -> dict[str, Any]:
    fid = step.get("finding_id")
    try:
        fid_i = int(fid)
    except (TypeError, ValueError) as e:
        raise ValueError(f"invalid finding_id in step: {fid!r}") from e
    if fid_i <= 0:
        raise ValueError(f"invalid finding_id in step: {fid!r}")
    poc = step.get("poc_path")
    if poc is not None:
        poc = str(poc).strip() or None
    return {
        "finding_id": fid_i,
        "role": str(step.get("role") or ""),
        "notes": str(step.get("notes") or ""),
        "poc_path": poc,
    }


def _normalize_chain(data: dict[str, Any], *, chain_id: Optional[str] = None) -> dict[str, Any]:
    cid = chain_id or data.get("id") or uuid.uuid4().hex
    cid = _validate_chain_id(str(cid))
    now = utc_now_iso()
    steps_in = data.get("steps") or []
    if not isinstance(steps_in, list):
        raise ValueError("steps must be a list")
    steps = [_normalize_step(s if isinstance(s, dict) else {}) for s in steps_in]
    include = _normalize_include_states(data.get("include_states"))
    title = str(data.get("title") or "").strip() or "Attack chain"
    created = str(data.get("created_at") or now)
    return {
        "id": cid,
        "title": title[:200],
        "include_states": include,
        "steps": steps,
        "created_at": created,
        "updated_at": now,
    }


def list_chains(run_dir: Path) -> list[dict[str, Any]]:
    """List chain documents (sorted by updated_at desc). Missing dir → []."""
    d = chains_dir(run_dir)
    if not d.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for p in sorted(d.glob("*.json")):
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                continue
            cid = raw.get("id") or p.stem
            out.append(_normalize_chain(raw, chain_id=str(cid)))
        except (OSError, json.JSONDecodeError, ValueError):
            continue
    out.sort(key=lambda c: str(c.get("updated_at") or ""), reverse=True)
    return out


def get_chain(run_dir: Path, chain_id: str) -> Optional[dict[str, Any]]:
    path = _chain_path(run_dir, chain_id)
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict):
        return None
    try:
        return _normalize_chain(raw, chain_id=chain_id)
    except ValueError:
        return None


def save_chain(run_dir: Path, chain: dict[str, Any]) -> dict[str, Any]:
    """Write/update a chain JSON under evidence/chains/. Returns normalized doc."""
    normalized = _normalize_chain(chain)
    d = chains_dir(run_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{normalized['id']}.json"
    # Preserve created_at if file exists
    if path.is_file():
        try:
            prev = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(prev, dict) and prev.get("created_at"):
                normalized["created_at"] = str(prev["created_at"])
        except (OSError, json.JSONDecodeError):
            pass
    normalized["updated_at"] = utc_now_iso()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(normalized, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    return normalized


def delete_chain(run_dir: Path, chain_id: str) -> bool:
    path = _chain_path(run_dir, chain_id)
    if not path.is_file():
        return False
    path.unlink()
    return True


def chain_to_markdown(
    chain: dict[str, Any],
    *,
    findings_by_id: Optional[dict[int, Any]] = None,
) -> str:
    """Export a chain as markdown with honesty disclaimer."""
    lines = [
        f"# {chain.get('title') or 'Attack chain'}",
        "",
        f"- **id:** `{chain.get('id')}`",
        f"- **include_states:** {', '.join(chain.get('include_states') or [])}",
        f"- **created_at:** {chain.get('created_at') or '-'}",
        f"- **updated_at:** {chain.get('updated_at') or '-'}",
        "",
        "> **Disclaimer:** Attack chains are operator research narratives. "
        "`needs_human` = mechanical gates passed; `confirmed` = human accepted. "
        "Neither is exploit proof. Human review is required before any claim.",
        "",
        "## Steps",
        "",
    ]
    steps = chain.get("steps") or []
    if not steps:
        lines.append("_No steps._")
        lines.append("")
    else:
        for i, step in enumerate(steps, 1):
            fid = step.get("finding_id")
            role = step.get("role") or ""
            notes = step.get("notes") or ""
            poc = step.get("poc_path")
            title = ""
            state = ""
            cls = ""
            if findings_by_id and fid is not None:
                f = findings_by_id.get(int(fid))
                if f is not None:
                    body = getattr(f, "body", None) or (
                        f.get("body") if isinstance(f, dict) else {}
                    ) or {}
                    title = body.get("title") or ""
                    state = getattr(f, "state", None) or (
                        f.get("state") if isinstance(f, dict) else ""
                    ) or ""
                    cls = body.get("weakness_class") or ""
            head = f"### Step {i}: finding #{fid}"
            if title:
                head += f" — {title}"
            lines.append(head)
            lines.append("")
            if role:
                lines.append(f"- **role:** {role}")
            if state:
                lines.append(f"- **state:** {state}")
            if cls:
                lines.append(f"- **class:** {cls}")
            if poc:
                lines.append(f"- **poc_path:** `{poc}`")
            if notes:
                lines.append(f"- **notes:** {notes}")
            lines.append("")
    return "\n".join(lines)


def build_chain_from_findings(
    run_dir: Path,
    *,
    finding_ids: Optional[list[int]] = None,
    include_states: Optional[list[str]] = None,
    title: str = "",
    findings: Optional[list[Any]] = None,
) -> dict[str, Any]:
    """
    Create a chain from selected findings (or all matching include_states).

    ``findings`` may be a preloaded list of Finding-like objects with .id/.state/.body;
    otherwise the caller should pass finding_ids after filtering.
    """
    states = set(_normalize_include_states(include_states))
    steps: list[dict[str, Any]] = []

    if finding_ids is not None:
        id_order = [int(x) for x in finding_ids]
        by_id: dict[int, Any] = {}
        if findings:
            for f in findings:
                fid = int(getattr(f, "id", None) or (f.get("id") if isinstance(f, dict) else 0))
                if fid:
                    by_id[fid] = f
        for fid in id_order:
            f = by_id.get(fid)
            if f is not None:
                st = str(
                    getattr(f, "state", None)
                    or (f.get("state") if isinstance(f, dict) else "")
                    or ""
                )
                if st and st not in states:
                    continue
                body = getattr(f, "body", None) or (
                    f.get("body") if isinstance(f, dict) else {}
                ) or {}
                poc = body.get("poc_relpath")
                steps.append(
                    {
                        "finding_id": fid,
                        "role": "",
                        "notes": "",
                        "poc_path": str(poc) if poc else None,
                    }
                )
            else:
                # Unknown / not preloaded — still record the id (caller filtered).
                steps.append(
                    {
                        "finding_id": fid,
                        "role": "",
                        "notes": "",
                        "poc_path": None,
                    }
                )
    elif findings is not None:
        ordered = sorted(
            findings,
            key=lambda f: int(
                getattr(f, "id", None) or (f.get("id") if isinstance(f, dict) else 0) or 0
            ),
        )
        for f in ordered:
            st = str(
                getattr(f, "state", None)
                or (f.get("state") if isinstance(f, dict) else "")
                or ""
            )
            if st not in states:
                continue
            fid = int(
                getattr(f, "id", None) or (f.get("id") if isinstance(f, dict) else 0) or 0
            )
            if fid <= 0:
                continue
            body = getattr(f, "body", None) or (
                f.get("body") if isinstance(f, dict) else {}
            ) or {}
            poc = body.get("poc_relpath")
            steps.append(
                {
                    "finding_id": fid,
                    "role": "",
                    "notes": "",
                    "poc_path": str(poc) if poc else None,
                }
            )
    else:
        raise ValueError("finding_ids or findings required")

    st_label = "+".join(sorted(states))
    default_title = title.strip() or f"Attack chain ({st_label}, {len(steps)} steps)"
    doc = {
        "id": uuid.uuid4().hex,
        "title": default_title,
        "include_states": list(states) if states else list(DEFAULT_INCLUDE_STATES),
        "steps": steps,
    }
    return save_chain(run_dir, doc)
