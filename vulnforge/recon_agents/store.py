"""Editable recon agent collection under config/recon_agents/."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Optional

from vulnforge.paths import (
    CONFIG_ROOT,
    LEGACY_PROMPTS_V1,
    PROJECT_ROOT,
    recon_agent_seeds_root,
    system_prompts_root,
)
from vulnforge.util import utc_now_iso

DEFAULT_COLLECTION_ROOT = CONFIG_ROOT / "recon_agents"
# Dual-read: seeds/recon_agents when present, else prompts/v1/recon_agents.
SEED_PROMPTS_DIR = recon_agent_seeds_root()
# Legacy single recon.md: prefer system_prompts_root, fall back to prompts/v1.
_sys = system_prompts_root()
LEGACY_RECON_PROMPT = (
    (_sys / "recon.md")
    if (_sys / "recon.md").is_file()
    else (LEGACY_PROMPTS_V1 / "recon.md")
)

COLLECTION_FORMAT = "vulnforge.recon_collection/v1"
AGENT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
MAX_BODY_BYTES = 256 * 1024

# Default seed: only default-map active so single-agent recon matches legacy.
SEED_ACTIVE_IDS = frozenset({"default-map"})
SEED_ORDER = ("default-map", "surface-mapper", "dependency-risk", "auth-model")

_root_override: Optional[Path] = None


class ReconAgentError(ValueError):
    """Invalid recon agent or collection operation."""


def set_collection_root(root: Path | str | None) -> None:
    """Override collection root (tests). Pass None to clear."""
    global _root_override
    if root is None:
        _root_override = None
    else:
        _root_override = Path(root).resolve()


def reset_collection_root_override() -> None:
    set_collection_root(None)


def collection_root() -> Path:
    if _root_override is not None:
        return _root_override
    env = (os.environ.get("VULNFORGE_RECON_AGENTS_ROOT") or "").strip()
    if env:
        return Path(env).resolve()
    return DEFAULT_COLLECTION_ROOT


def _collection_path(root: Optional[Path] = None) -> Path:
    return (root or collection_root()) / "collection.json"


def _bodies_dir(root: Optional[Path] = None) -> Path:
    return (root or collection_root()) / "bodies"


def _validate_id(agent_id: str) -> str:
    aid = str(agent_id or "").strip().lower()
    if not AGENT_ID_RE.match(aid):
        raise ReconAgentError(
            f"invalid agent id {agent_id!r}: use lowercase slug "
            f"[a-z][a-z0-9-]{{0,63}}"
        )
    return aid


def _body_path(agent_id: str, root: Optional[Path] = None) -> Path:
    root = root or collection_root()
    bodies = _bodies_dir(root).resolve()
    path = (bodies / f"{agent_id}.md").resolve()
    if bodies not in path.parents and path != bodies:
        raise ReconAgentError(f"path escape for body: {agent_id}")
    if path.name != f"{agent_id}.md":
        raise ReconAgentError(f"path escape for body: {agent_id}")
    return path


def _title_from_body(body: str, fallback_id: str) -> str:
    for line in (body or "").splitlines():
        s = line.strip()
        if s.startswith("#"):
            t = s.lstrip("#").strip()
            if ":" in t:
                t = t.split(":", 1)[1].strip() or t
            return t[:120] if t else fallback_id
    return fallback_id.replace("-", " ").title()


def _empty_collection() -> dict[str, Any]:
    return {
        "format": COLLECTION_FORMAT,
        "updated_at": utc_now_iso(),
        "seeded_from": "prompts/v1/recon_agents",
        "agents": [],
    }


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2) + "\n"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _read_collection_raw(root: Optional[Path] = None) -> Optional[dict[str, Any]]:
    path = _collection_path(root)
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise ReconAgentError(f"corrupt collection.json: {e}") from e
    if not isinstance(raw, dict):
        raise ReconAgentError("collection.json must be an object")
    return raw


def _coerce_order(value: object, default: int = 100) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _coerce_optional_float(value: object) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _coerce_optional_int(value: object) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _coerce_tools(value: object) -> Optional[list[str]]:
    if value is None:
        return None
    if not isinstance(value, list):
        return None
    out = [str(x).strip() for x in value if str(x).strip()]
    return out or None


def _normalize_agent_entry(p: dict[str, Any]) -> Optional[dict[str, Any]]:
    try:
        aid = _validate_id(str(p.get("id") or ""))
    except ReconAgentError:
        return None
    mode = str(p.get("mode") or "sequential").strip().lower() or "sequential"
    if mode not in ("sequential",):
        mode = "sequential"
    output = str(p.get("output") or "architecture").strip()[:64] or "architecture"
    return {
        "id": aid,
        "title": str(p.get("title") or aid).strip()[:120] or aid,
        "description": str(p.get("description") or "").strip()[:500],
        "active": bool(p.get("active")),
        "order": _coerce_order(p.get("order"), 100),
        "mode": mode,
        "tools": _coerce_tools(p.get("tools")),
        "temperature": _coerce_optional_float(p.get("temperature")),
        "max_tool_rounds": _coerce_optional_int(p.get("max_tool_rounds")),
        "output": output,
        "body_file": str(p.get("body_file") or f"bodies/{aid}.md"),
        "source": str(p.get("source") or "custom")[:32],
    }


def _normalize_collection(raw: dict[str, Any]) -> dict[str, Any]:
    out = _empty_collection()
    if raw.get("format") and raw.get("format") != COLLECTION_FORMAT:
        if str(raw.get("format")).startswith("vulnforge.recon_collection/"):
            raise ReconAgentError(f"unsupported collection format: {raw.get('format')}")
    out["format"] = COLLECTION_FORMAT
    out["updated_at"] = str(raw.get("updated_at") or utc_now_iso())
    out["seeded_from"] = str(raw.get("seeded_from") or "prompts/v1/recon_agents")
    agents: list[dict[str, Any]] = []
    seen: set[str] = set()
    for p in raw.get("agents") or []:
        if not isinstance(p, dict):
            continue
        entry = _normalize_agent_entry(p)
        if entry is None or entry["id"] in seen:
            continue
        seen.add(entry["id"])
        agents.append(entry)
    agents.sort(key=lambda a: (a.get("order", 100), a["id"]))
    out["agents"] = agents
    return out


def _default_map_body_fallback() -> str:
    """Embed current prompts/v1/recon.md when seed dir lacks default-map."""
    if LEGACY_RECON_PROMPT.is_file():
        return LEGACY_RECON_PROMPT.read_text(encoding="utf-8")
    return (
        "# Recon agent: default-map\n\n"
        "**Mission:** Map the application so hunt tasks are grounded in real structure.\n\n"
        "## Method\n\n"
        "1. Trust mechanical inventory; sample real paths with tools.\n"
        "2. Produce summary, trust boundaries, components, input surfaces, hunt_focus.\n\n"
        "## Anti-patterns\n\n"
        "- Inventing microservices not in the tree\n"
        "- Filing vulnerability findings during recon\n\n"
        "## Submit checklist\n\n"
        "- Call `submit_architecture` with a non-empty summary\n"
        "- Prefer active hunt class ids in hunt_focus\n"
    )


def _seed_agents_from_package() -> list[dict[str, Any]]:
    """Build agent entries + bodies from package seed library (or recon.md fallback)."""
    seed_dir = SEED_PROMPTS_DIR
    by_id: dict[str, str] = {}
    if seed_dir.is_dir():
        for path in sorted(seed_dir.glob("*.md")):
            aid = path.stem.lower()
            if not AGENT_ID_RE.match(aid):
                continue
            by_id[aid] = path.read_text(encoding="utf-8")

    if "default-map" not in by_id:
        by_id["default-map"] = _default_map_body_fallback()

    if not by_id:
        raise ReconAgentError("seed library has no valid recon agent markdown files")

    # Stable order: SEED_ORDER first, then remaining alpha
    ordered: list[str] = [a for a in SEED_ORDER if a in by_id]
    ordered.extend(sorted(a for a in by_id if a not in SEED_ORDER))

    defaults_meta: dict[str, dict[str, Any]] = {
        "default-map": {
            "title": "Default map",
            "description": "Full architecture map (legacy recon.md behavior).",
            "order": 10,
            "active": True,
        },
        "surface-mapper": {
            "title": "Surface mapper",
            "description": "Deepen input surfaces, entrypoints, and trust boundaries.",
            "order": 20,
            "active": False,
        },
        "dependency-risk": {
            "title": "Dependency risk",
            "description": "Map third-party deps, supply chain, and update surfaces.",
            "order": 30,
            "active": False,
        },
        "auth-model": {
            "title": "Auth model",
            "description": "Map authentication, sessions, roles, and authorization boundaries.",
            "order": 40,
            "active": False,
        },
    }

    agents: list[dict[str, Any]] = []
    for i, aid in enumerate(ordered):
        body = by_id[aid]
        meta = defaults_meta.get(aid, {})
        agents.append(
            {
                "id": aid,
                "title": meta.get("title") or _title_from_body(body, aid),
                "description": meta.get("description") or "",
                "active": bool(meta.get("active", aid in SEED_ACTIVE_IDS)),
                "order": int(meta.get("order", 100 + i * 10)),
                "mode": "sequential",
                "tools": None,
                "temperature": None,
                "max_tool_rounds": None,
                "output": "architecture",
                "body_file": f"bodies/{aid}.md",
                "source": "seed",
                "_body": body,
            }
        )
    return agents


def _public_agent(p: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": p["id"],
        "title": p["title"],
        "description": p.get("description") or "",
        "active": bool(p.get("active")),
        "order": _coerce_order(p.get("order"), 100),
        "mode": str(p.get("mode") or "sequential"),
        "tools": _coerce_tools(p.get("tools")),
        "temperature": _coerce_optional_float(p.get("temperature")),
        "max_tool_rounds": _coerce_optional_int(p.get("max_tool_rounds")),
        "output": str(p.get("output") or "architecture")[:64],
        "body_file": f"bodies/{p['id']}.md",
        "source": p.get("source") or "custom",
    }


def _write_collection(
    coll: dict[str, Any],
    *,
    bodies: Optional[dict[str, str]] = None,
    root: Optional[Path] = None,
) -> dict[str, Any]:
    root = root or collection_root()
    root.mkdir(parents=True, exist_ok=True)
    _bodies_dir(root).mkdir(parents=True, exist_ok=True)
    coll = _normalize_collection(coll)
    coll["updated_at"] = utc_now_iso()
    coll["format"] = COLLECTION_FORMAT
    if bodies:
        for aid, body in bodies.items():
            _validate_id(aid)
            _check_body(body)
            _atomic_write_text(_body_path(aid, root), body)
    clean_agents = [_public_agent(p) for p in coll["agents"]]
    clean_agents.sort(key=lambda a: (a.get("order", 100), a["id"]))
    coll["agents"] = clean_agents
    _atomic_write_json(_collection_path(root), coll)
    return coll


def _check_body(body: str) -> str:
    if body is None:
        raise ReconAgentError("body_md is required")
    text = str(body)
    if not text.strip():
        raise ReconAgentError("body_md must be non-empty")
    if len(text.encode("utf-8")) > MAX_BODY_BYTES:
        raise ReconAgentError(f"body_md exceeds {MAX_BODY_BYTES} bytes")
    return text


def ensure_collection(root: Optional[Path] = None) -> dict[str, Any]:
    """Load collection, seeding from package prompts if missing."""
    root = root or collection_root()
    existing = _read_collection_raw(root)
    if existing is not None:
        return _normalize_collection(existing)
    seeded = _seed_agents_from_package()
    bodies = {p["id"]: p.pop("_body") for p in seeded}
    coll = _empty_collection()
    coll["agents"] = seeded
    return _write_collection(coll, bodies=bodies, root=root)


def list_agents(*, include_body: bool = False) -> list[dict[str, Any]]:
    coll = ensure_collection()
    out: list[dict[str, Any]] = []
    for p in coll["agents"]:
        row = dict(p)
        if include_body:
            try:
                row["body_md"] = get_body(p["id"])
            except ReconAgentError:
                row["body_md"] = ""
        out.append(row)
    return out


def get_agent(agent_id: str, *, include_body: bool = True) -> dict[str, Any]:
    aid = _validate_id(agent_id)
    coll = ensure_collection()
    for p in coll["agents"]:
        if p["id"] == aid:
            row = dict(p)
            if include_body:
                row["body_md"] = get_body(aid)
            return row
    raise ReconAgentError(f"unknown recon agent: {aid}")


def get_body(agent_id: str) -> str:
    aid = _validate_id(agent_id)
    ensure_collection()
    path = _body_path(aid)
    if not path.is_file():
        raise ReconAgentError(f"missing body for agent: {aid}")
    return path.read_text(encoding="utf-8")


def all_agent_ids() -> list[str]:
    return [p["id"] for p in ensure_collection()["agents"]]


def active_agents(
    *,
    agent_ids: Optional[list[str]] = None,
) -> list[dict[str, Any]]:
    """Return agents to run: active set, optionally filtered by id list, ordered.

    If agent_ids is provided (non-empty), only those ids that exist are returned
    (regardless of active flag) in the requested order when possible, else by
    collection order.
    """
    coll = ensure_collection()
    by_id = {p["id"]: p for p in coll["agents"]}
    if agent_ids:
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        for raw in agent_ids:
            try:
                aid = _validate_id(str(raw))
            except ReconAgentError:
                continue
            if aid in by_id and aid not in seen:
                out.append(dict(by_id[aid]))
                seen.add(aid)
        return out
    active = [dict(p) for p in coll["agents"] if p.get("active")]
    if active:
        return active
    # Empty active set: fall back to all so recon never deadlocks
    return [dict(p) for p in coll["agents"]]


def catalog_for_ui() -> dict[str, list[str]]:
    coll = ensure_collection()
    all_ids = [p["id"] for p in coll["agents"]]
    active = [p["id"] for p in coll["agents"] if p.get("active")]
    if not active:
        active = list(all_ids)
    return {"all": all_ids, "active": active}


def save_agent(
    agent_id: str,
    *,
    body_md: Optional[str] = None,
    title: Optional[str] = None,
    description: Optional[str] = None,
    active: Optional[bool] = None,
    order: Optional[int] = None,
    mode: Optional[str] = None,
    tools: Optional[list[str]] = None,
    temperature: Optional[float] = None,
    max_tool_rounds: Optional[int] = None,
    output: Optional[str] = None,
    source: Optional[str] = None,
    create: bool = False,
    clear_tools: bool = False,
    clear_temperature: bool = False,
    clear_max_tool_rounds: bool = False,
) -> dict[str, Any]:
    aid = _validate_id(agent_id)
    coll = ensure_collection()
    agents = list(coll["agents"])
    idx = next((i for i, p in enumerate(agents) if p["id"] == aid), None)

    if idx is None:
        if not create and body_md is None:
            raise ReconAgentError(f"unknown recon agent: {aid}")
        if body_md is None:
            body_md = (
                f"# Recon agent: {aid}\n\n"
                f"**Mission:** (describe the recon goal)\n\n"
                f"## Method\n\n1. \n\n## Anti-patterns\n\n- \n\n"
                f"## Submit checklist\n\n"
                f"- `submit_architecture` with a non-empty summary\n"
            )
        body = _check_body(body_md)
        entry = {
            "id": aid,
            "title": (title or _title_from_body(body, aid)).strip()[:120],
            "description": (description or "").strip()[:500],
            "active": bool(active) if active is not None else False,
            "order": _coerce_order(order, 100) if order is not None else 100,
            "mode": (str(mode).strip().lower() if mode else "sequential") or "sequential",
            "tools": _coerce_tools(tools),
            "temperature": _coerce_optional_float(temperature),
            "max_tool_rounds": _coerce_optional_int(max_tool_rounds),
            "output": (str(output).strip() if output else "architecture")[:64]
            or "architecture",
            "body_file": f"bodies/{aid}.md",
            "source": (source or "custom")[:32],
        }
        if entry["mode"] not in ("sequential",):
            entry["mode"] = "sequential"
        agents.append(entry)
        coll["agents"] = agents
        _write_collection(coll, bodies={aid: body})
        return get_agent(aid)

    entry = dict(agents[idx])
    bodies: dict[str, str] = {}
    if body_md is not None:
        body = _check_body(body_md)
        bodies[aid] = body
        if title is None and not entry.get("title"):
            entry["title"] = _title_from_body(body, aid)
    if title is not None:
        entry["title"] = str(title).strip()[:120] or aid
    if description is not None:
        entry["description"] = str(description).strip()[:500]
    if active is not None:
        entry["active"] = bool(active)
    if order is not None:
        entry["order"] = _coerce_order(order, entry.get("order", 100))
    if mode is not None:
        m = str(mode).strip().lower() or "sequential"
        entry["mode"] = m if m in ("sequential",) else "sequential"
    if clear_tools:
        entry["tools"] = None
    elif tools is not None:
        entry["tools"] = _coerce_tools(tools)
    if clear_temperature:
        entry["temperature"] = None
    elif temperature is not None:
        entry["temperature"] = _coerce_optional_float(temperature)
    if clear_max_tool_rounds:
        entry["max_tool_rounds"] = None
    elif max_tool_rounds is not None:
        entry["max_tool_rounds"] = _coerce_optional_int(max_tool_rounds)
    if output is not None:
        entry["output"] = str(output).strip()[:64] or "architecture"
    if source is not None:
        entry["source"] = str(source)[:32]
    if body_md is not None and entry.get("source") == "seed" and source is None:
        entry["source"] = "custom"
    agents[idx] = entry
    coll["agents"] = agents
    _write_collection(coll, bodies=bodies if bodies else None)
    return get_agent(aid)


def delete_agent(agent_id: str) -> dict[str, Any]:
    aid = _validate_id(agent_id)
    coll = ensure_collection()
    agents = [p for p in coll["agents"] if p["id"] != aid]
    if len(agents) == len(coll["agents"]):
        raise ReconAgentError(f"unknown recon agent: {aid}")
    if not agents:
        raise ReconAgentError("cannot delete the last recon agent")
    coll["agents"] = agents
    _write_collection(coll)
    body = _body_path(aid)
    if body.is_file():
        try:
            body.unlink()
        except OSError:
            pass
    return {"ok": True, "deleted": aid, "remaining": len(agents)}


def export_collection() -> dict[str, Any]:
    coll = ensure_collection()
    agents_out: list[dict[str, Any]] = []
    for p in coll["agents"]:
        try:
            body = get_body(p["id"])
        except ReconAgentError:
            body = ""
        agents_out.append(
            {
                "id": p["id"],
                "title": p.get("title") or p["id"],
                "description": p.get("description") or "",
                "active": bool(p.get("active")),
                "order": _coerce_order(p.get("order"), 100),
                "mode": p.get("mode") or "sequential",
                "tools": p.get("tools"),
                "temperature": p.get("temperature"),
                "max_tool_rounds": p.get("max_tool_rounds"),
                "output": p.get("output") or "architecture",
                "source": p.get("source") or "custom",
                "body_md": body,
            }
        )
    return {
        "format": COLLECTION_FORMAT,
        "updated_at": coll.get("updated_at") or utc_now_iso(),
        "seeded_from": coll.get("seeded_from"),
        "agents": agents_out,
    }


def import_collection(
    data: dict[str, Any] | list,
    *,
    mode: str = "merge",
) -> dict[str, Any]:
    mode_n = str(mode or "merge").lower().strip()
    if mode_n not in ("merge", "replace"):
        raise ReconAgentError("mode must be 'merge' or 'replace'")

    if isinstance(data, list):
        raw_agents = data
        fmt = COLLECTION_FORMAT
    elif isinstance(data, dict):
        fmt = data.get("format") or COLLECTION_FORMAT
        if fmt != COLLECTION_FORMAT:
            raise ReconAgentError(f"unsupported collection format: {fmt}")
        raw_agents = data.get("agents")
        if raw_agents is None:
            raise ReconAgentError("import data missing 'agents'")
    else:
        raise ReconAgentError("import data must be an object or list")

    if not isinstance(raw_agents, list) or not raw_agents:
        raise ReconAgentError("import agents must be a non-empty list")

    incoming: list[dict[str, Any]] = []
    bodies: dict[str, str] = {}
    for p in raw_agents:
        if not isinstance(p, dict):
            raise ReconAgentError("each agent must be an object")
        aid = _validate_id(str(p.get("id") or ""))
        body = p.get("body_md")
        if body is None or not str(body).strip():
            raise ReconAgentError(f"agent {aid}: body_md required")
        body = _check_body(str(body))
        bodies[aid] = body
        entry = _normalize_agent_entry(
            {
                **p,
                "id": aid,
                "title": str(p.get("title") or _title_from_body(body, aid)).strip()[:120],
                "source": str(p.get("source") or "import")[:32],
                "active": bool(p.get("active")) if "active" in p else False,
            }
        )
        if entry is None:
            continue
        incoming.append(entry)

    if mode_n == "replace":
        coll = _empty_collection()
        coll["agents"] = incoming
        root = collection_root()
        written = _write_collection(coll, bodies=bodies, root=root)
        bdir = _bodies_dir(root)
        keep = {f"{p['id']}.md" for p in written["agents"]}
        if bdir.is_dir():
            for f in bdir.glob("*.md"):
                if f.name not in keep:
                    try:
                        f.unlink()
                    except OSError:
                        pass
        return {
            "ok": True,
            "mode": "replace",
            "count": len(written["agents"]),
            "agents": [p["id"] for p in written["agents"]],
        }

    coll = ensure_collection()
    by_id = {p["id"]: dict(p) for p in coll["agents"]}
    for p in incoming:
        by_id[p["id"]] = p
    order: list[str] = []
    for p in coll["agents"]:
        if p["id"] in by_id and p["id"] not in order:
            order.append(p["id"])
    for p in incoming:
        if p["id"] not in order:
            order.append(p["id"])
    coll["agents"] = [by_id[i] for i in order]
    written = _write_collection(coll, bodies=bodies)
    return {
        "ok": True,
        "mode": "merge",
        "count": len(written["agents"]),
        "agents": [p["id"] for p in written["agents"]],
    }


def reseed_from_package(*, replace: bool = True) -> dict[str, Any]:
    """Replace collection with package seed library (destructive)."""
    if not replace:
        raise ReconAgentError("reseed currently only supports replace=True")
    seeded = _seed_agents_from_package()
    bodies = {p["id"]: p.pop("_body") for p in seeded}
    coll = _empty_collection()
    coll["agents"] = seeded
    root = collection_root()
    written = _write_collection(coll, bodies=bodies, root=root)
    bdir = _bodies_dir(root)
    keep = {f"{p['id']}.md" for p in written["agents"]}
    if bdir.is_dir():
        for f in bdir.glob("*.md"):
            if f.name not in keep:
                try:
                    f.unlink()
                except OSError:
                    pass
    return {
        "ok": True,
        "mode": "reseed",
        "count": len(written["agents"]),
        "agents": [p["id"] for p in written["agents"]],
    }
