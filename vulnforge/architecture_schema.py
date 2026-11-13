"""Architecture schema v2 (``vulnforge/architecture@2``): normalize, validate, merge.

Spec: ``docs/harness/recon/FLOWS.md``. Pure functions; the only I/O is the
read-only citation check in :func:`validate_citations`, which reads files
under the target root and never writes or follows paths outside it.

Honesty: zones, relations and flows steer recon and hunts. They are never
evidence for a finding, and an empty zone or a missing flow never means safe.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, Iterable, Optional

SCHEMA_V2 = "vulnforge/architecture@2"

ZONE_KINDS: tuple[str, ...] = (
    "internet",
    "authenticated",
    "internal",
    "external",
    "build",
)
ZONE_LABELS: dict[str, str] = {
    "internet": "Internet-facing",
    "authenticated": "Authenticated",
    "internal": "Internal",
    "external": "External services",
    "build": "Build / CI",
}
_ZONE_SYNONYMS: dict[str, str] = {
    "public": "internet",
    "internet-facing": "internet",
    "internet_facing": "internet",
    "untrusted": "internet",
    "edge": "internet",
    "auth": "authenticated",
    "authed": "authenticated",
    "logged-in": "authenticated",
    "session": "authenticated",
    "private": "internal",
    "backend": "internal",
    "trusted": "internal",
    "third-party": "external",
    "third_party": "external",
    "thirdparty": "external",
    "saas": "external",
    "upstream": "external",
    "ci": "build",
    "ci/cd": "build",
    "cicd": "build",
    "install": "build",
}

RELATION_KINDS: tuple[str, ...] = (
    "calls",
    "data_flow",
    "imports",
    "queue",
    "db",
    "http_out",
    "auth_gate",
    "depends_on",
    "trust_boundary",
)
_RELATION_SYNONYMS: dict[str, str] = {
    "call": "calls",
    "invokes": "calls",
    "import": "imports",
    "dataflow": "data_flow",
    "data-flow": "data_flow",
    "flow": "data_flow",
    "database": "db",
    "sql": "db",
    "http": "http_out",
    "http-out": "http_out",
    "outbound": "http_out",
    "auth": "auth_gate",
    "auth-gate": "auth_gate",
    "depends": "depends_on",
    "depends-on": "depends_on",
    "dependency": "depends_on",
    "uses": "depends_on",
    "trust-boundary": "trust_boundary",
    "boundary": "trust_boundary",
    "enqueue": "queue",
    "publish": "queue",
}
CONFIDENCE_LEVELS: tuple[str, ...] = ("mechanical", "cited", "inferred")
_CONF_RANK = {"inferred": 0, "cited": 1, "mechanical": 2}
FLOW_CONFIDENCE: tuple[str, ...] = ("cited", "inferred")
ORIGINS: tuple[str, ...] = ("mechanical", "recon")

# Caps (snapshot + packet sanity; mirrors recon.normalize_relations style)
MAX_ZONES = 12
MAX_COMPONENTS = 60
MAX_BOUNDARIES = 24
MAX_RELATIONS = 120
MAX_FLOWS = 32
MAX_STEPS = 24
MAX_PATH_HINTS = 12
MAX_ENTRYPOINTS = 24
MAX_SINKS = 24
MAX_EVIDENCE = 6
MAX_V1_ITEMS = 40
MAX_SUMMARY = 8000
MAX_TEXT = 400
MAX_NAME = 120
MAX_PATH = 300
MAX_ID = 80
MAX_CLASSES = 12

_SLUG_RX = re.compile(r"[^a-z0-9]+")
_LOC_STR_RX = re.compile(r"^\s*([^\s:][^:]*?):(\d+)(?::\d+)?\s*$")


# ---------------------------------------------------------------------------
# Small coercion helpers
# ---------------------------------------------------------------------------


def slugify(value: Any, *, limit: int = MAX_ID) -> str:
    """Lowercase ``a-z0-9-`` slug; empty when nothing usable."""
    s = _SLUG_RX.sub("-", str(value or "").strip().lower()).strip("-")
    return s[:limit].strip("-")


def _s(value: Any, limit: int = MAX_TEXT) -> str:
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return ""
    return str(value).strip()[:limit]


def _as_list(value: Any) -> list:
    """List field; one json.loads attempt for double-encoded strings."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        s = value.strip()
        if s[:1] in ("[", "{"):
            try:
                parsed = json.loads(s)
            except (json.JSONDecodeError, TypeError, ValueError):
                return []
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        return []
    if isinstance(value, dict):
        return [value]
    return []


def _line(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        n = int(str(value).strip()) if not isinstance(value, int) else value
    except (TypeError, ValueError):
        return None
    return n if 1 <= n <= 10_000_000 else None


def _relpath(value: Any) -> str:
    p = _s(value, MAX_PATH).replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def _loc(obj: Any) -> dict[str, Any]:
    """Extract ``{path, line}`` from a dict or ``"path:line"`` string."""
    if isinstance(obj, str):
        m = _LOC_STR_RX.match(obj)
        if m:
            out: dict[str, Any] = {"path": _relpath(m.group(1))}
            ln = _line(m.group(2))
            if ln:
                out["line"] = ln
            return out if out["path"] else {}
        return {}
    if not isinstance(obj, dict):
        return {}
    path = _relpath(obj.get("path") or obj.get("file") or "")
    ln = _line(obj.get("line") if obj.get("line") is not None else obj.get("lineno"))
    if not path:
        # "app.py:52" packed into path-like keys
        for key in ("location", "loc", "at"):
            if isinstance(obj.get(key), str):
                return _loc(obj.get(key))
        return {}
    if ln is None and ":" in path:
        packed = _loc(path)
        if packed.get("line"):
            return packed
    out = {"path": path}
    if ln:
        out["line"] = ln
    return out


def _evidence(value: Any) -> dict[str, Any]:
    """Single evidence ``{path, line?, text?}`` from dict / string / list."""
    if isinstance(value, list):
        for item in value:
            ev = _evidence(item)
            if ev:
                return ev
        return {}
    loc = _loc(value)
    if not loc:
        return {}
    if isinstance(value, dict):
        text = _s(value.get("text") or value.get("snippet") or "", 200)
        if text:
            loc["text"] = text
    return loc


def _evidence_list(value: Any, limit: int = MAX_EVIDENCE) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for item in _as_list(value) if not isinstance(value, dict) else [value]:
        ev = _evidence(item)
        if not ev:
            continue
        key = (ev.get("path"), ev.get("line"))
        if key in seen:
            continue
        seen.add(key)
        out.append(ev)
        if len(out) >= limit:
            break
    return out


def _str_list(value: Any, limit: int, item_limit: int = 200) -> list[str]:
    out: list[str] = []
    for item in _as_list(value) if not isinstance(value, str) else [value]:
        s = _s(item, item_limit)
        if s and s not in out:
            out.append(s)
        if len(out) >= limit:
            break
    return out


def _zone_kind(value: Any) -> str:
    """Map free text onto a ZONE_KINDS member; '' when unknown."""
    s = _s(value, 80).lower()
    if not s:
        return ""
    if s in ZONE_KINDS:
        return s
    if s in _ZONE_SYNONYMS:
        return _ZONE_SYNONYMS[s]
    slug = slugify(s)
    if slug in ZONE_KINDS:
        return slug
    if slug in _ZONE_SYNONYMS:
        return _ZONE_SYNONYMS[slug]
    for k in ZONE_KINDS:
        if s.startswith(k):
            return k
    return ""


def relation_kind(value: Any) -> str:
    s = _s(value, 80).lower().replace(" ", "_")
    if s in RELATION_KINDS:
        return s
    if s in _RELATION_SYNONYMS:
        return _RELATION_SYNONYMS[s]
    s2 = s.replace("_", "-")
    if s2 in _RELATION_SYNONYMS:
        return _RELATION_SYNONYMS[s2]
    return "related"


def _confidence(value: Any, allowed: Iterable[str] = CONFIDENCE_LEVELS) -> str:
    s = _s(value, 40).lower()
    return s if s in tuple(allowed) else "inferred"


def _dedupe_dicts(items: list, limit: int) -> list:
    out: list = []
    seen: set[str] = set()
    for item in items:
        try:
            key = json.dumps(item, sort_keys=True, default=str)
        except (TypeError, ValueError):
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= limit:
            break
    return out


def _v1_list(value: Any, limit: int = MAX_V1_ITEMS) -> list:
    """Keep v1 free-form lists (strings or shallow dicts), capped, deduped."""
    kept: list = []
    for item in _as_list(value):
        if isinstance(item, str):
            s = item.strip()[:600]
            if s:
                kept.append(s)
        elif isinstance(item, dict) and item:
            try:
                blob = json.dumps(item, default=str)
            except (TypeError, ValueError):
                continue
            if len(blob) <= 4000:
                kept.append(copy.deepcopy(item))
    return _dedupe_dicts(kept, limit)


# ---------------------------------------------------------------------------
# Normalizers
# ---------------------------------------------------------------------------


def _norm_zone(item: Any) -> Optional[dict[str, Any]]:
    if isinstance(item, str):
        kind = _zone_kind(item)
        zid = slugify(item)
        if not zid:
            return None
        return {
            "id": zid,
            "label": ZONE_LABELS.get(zid) or _s(item, MAX_NAME),
            "kind": kind or "internal",
            "description": "",
        }
    if not isinstance(item, dict):
        return None
    raw_id = item.get("id") or item.get("name") or item.get("label") or item.get("kind")
    zid = slugify(raw_id)
    kind = (
        _zone_kind(item.get("kind"))
        or _zone_kind(item.get("id"))
        or _zone_kind(item.get("label") or item.get("name"))
    )
    if not zid:
        zid = kind
    if not zid:
        return None
    label = _s(item.get("label") or item.get("name") or "", MAX_NAME) or ZONE_LABELS.get(
        kind or zid, zid
    )
    out: dict[str, Any] = {
        "id": zid,
        "label": label,
        "kind": kind or "internal",
        "description": _s(item.get("description") or item.get("note") or ""),
    }
    ev = _evidence_list(item.get("evidence"))
    if ev:
        out["evidence"] = ev
    return out


def _norm_entrypoint(item: Any) -> Optional[dict[str, Any]]:
    if isinstance(item, str):
        loc = _loc(item)
        if loc:
            return {"label": _s(item, 200), **loc}
        s = _s(item, 200)
        return {"label": s} if s else None
    if not isinstance(item, dict):
        return None
    loc = _loc(item)
    label = _s(
        item.get("label") or item.get("name") or item.get("route") or item.get("marker") or "",
        200,
    )
    if not label and not loc:
        return None
    out: dict[str, Any] = {"label": label or loc.get("path", "")}
    out.update(loc)
    return out


def _norm_sink(item: Any) -> Optional[dict[str, Any]]:
    if isinstance(item, str):
        loc = _loc(item)
        return {"kind": "", **loc} if loc else None
    if not isinstance(item, dict):
        return None
    loc = _loc(item)
    kind = _s(item.get("kind") or item.get("family") or "", 40).lower()
    if not loc and not kind:
        return None
    out: dict[str, Any] = {"kind": kind}
    out.update(loc)
    return out


def _dedupe_locs(items: list[dict[str, Any]], keys: tuple[str, ...], limit: int) -> list:
    out: list = []
    seen: set[tuple] = set()
    for it in items:
        key = tuple(it.get(k) for k in keys)
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
        if len(out) >= limit:
            break
    return out


def _norm_component(item: Any) -> Optional[dict[str, Any]]:
    if isinstance(item, str):
        name = _s(item, MAX_NAME)
        cid = slugify(name)
        if not cid:
            return None
        return {
            "id": cid,
            "name": name,
            "kind": "",
            "zone": "",
            "role": "",
            "path_hints": [],
            "entrypoints": [],
            "sinks": [],
            "origin": "recon",
        }
    if not isinstance(item, dict):
        return None
    name = _s(item.get("name") or item.get("label") or item.get("id") or "", MAX_NAME)
    cid = slugify(item.get("id")) or slugify(name)
    if not cid:
        return None
    if not name:
        name = cid
    zone_raw = item.get("zone")
    zone = slugify(zone_raw.get("id") if isinstance(zone_raw, dict) else zone_raw, limit=40)
    hints = _str_list(item.get("path_hints") or item.get("paths"), MAX_PATH_HINTS, 200)
    hints = [_relpath(h) for h in hints if _relpath(h)]
    eps = [e for e in (_norm_entrypoint(x) for x in _as_list(item.get("entrypoints"))) if e]
    sinks = [s for s in (_norm_sink(x) for x in _as_list(item.get("sinks"))) if s]
    origin = _s(item.get("origin"), 20).lower()
    out: dict[str, Any] = {
        "id": cid,
        "name": name,
        "kind": _s(item.get("kind") or item.get("type") or "", 40),
        "zone": zone,
        "role": _s(item.get("role") or item.get("description") or item.get("summary") or ""),
        "path_hints": hints,
        "entrypoints": _dedupe_locs(eps, ("label", "path", "line"), MAX_ENTRYPOINTS),
        "sinks": _dedupe_locs(sinks, ("kind", "path", "line"), MAX_SINKS),
        "origin": origin if origin in ORIGINS else "recon",
    }
    zs = _s(item.get("zone_source"), 20).lower()
    if zs in ("heuristic", "recon"):
        out["zone_source"] = zs
    return out


def _merge_component_into(dst: dict[str, Any], src: dict[str, Any]) -> None:
    """Union lists of *src* into *dst*; fill empty text fields. Newer wins handled by caller."""
    for key in ("kind", "zone", "role", "name"):
        if not dst.get(key) and src.get(key):
            dst[key] = src[key]
    if src.get("zone_source") and not dst.get("zone_source"):
        dst["zone_source"] = src["zone_source"]
    dst["path_hints"] = _str_list(
        list(dst.get("path_hints") or []) + list(src.get("path_hints") or []),
        MAX_PATH_HINTS,
    )
    dst["entrypoints"] = _dedupe_locs(
        list(dst.get("entrypoints") or []) + list(src.get("entrypoints") or []),
        ("label", "path", "line"),
        MAX_ENTRYPOINTS,
    )
    dst["sinks"] = _dedupe_locs(
        list(dst.get("sinks") or []) + list(src.get("sinks") or []),
        ("kind", "path", "line"),
        MAX_SINKS,
    )


class _Resolver:
    """Resolve a component reference (id or name, case-insensitive) to its id."""

    def __init__(self, components: list[dict[str, Any]]):
        self._map: dict[str, str] = {}
        for c in components:
            cid = c["id"]
            self._map.setdefault(cid.lower(), cid)
        for c in components:
            name = str(c.get("name") or "").strip().lower()
            if name:
                self._map.setdefault(name, c["id"])
                self._map.setdefault(slugify(name), c["id"])

    def resolve(self, ref: Any) -> Optional[str]:
        s = _s(ref, 200).lower()
        if not s:
            return None
        return self._map.get(s) or self._map.get(slugify(s))

    def normalize(self, ref: Any) -> str:
        """Resolved id, or the trimmed original text when unknown."""
        hit = self.resolve(ref)
        return hit if hit else _s(ref, 200)


def _norm_boundary(item: Any) -> Optional[dict[str, Any]]:
    if not isinstance(item, dict):
        return None
    frm = slugify(item.get("from_zone") or item.get("from") or "", limit=40)
    to = slugify(item.get("to_zone") or item.get("to") or "", limit=40)
    control = _s(item.get("control") or item.get("mechanism") or "", 200)
    if not (frm or to) or not (control or (frm and to)):
        return None
    out: dict[str, Any] = {"from_zone": frm, "to_zone": to, "control": control}
    out.update(_loc(item))
    note = _s(item.get("note") or item.get("description") or "")
    if note:
        out["note"] = note
    return out


def _norm_relation(item: Any, res: _Resolver) -> Optional[dict[str, Any]]:
    if not isinstance(item, dict):
        return None
    frm = res.normalize(item.get("from") or item.get("src") or item.get("source") or "")
    to = res.normalize(item.get("to") or item.get("dst") or item.get("target") or "")
    if not frm or not to or frm == to:
        return None
    rel: dict[str, Any] = {
        "from": frm,
        "to": to,
        "kind": relation_kind(item.get("kind") or item.get("type")),
        "evidence": _evidence(item.get("evidence")),
        "confidence": _confidence(item.get("confidence")),
    }
    if not rel["evidence"]:
        # v1 / model shortcut: path+line on the relation itself
        rel["evidence"] = _evidence({"path": item.get("path"), "line": item.get("line")})
    note = _s(item.get("note") or item.get("description") or item.get("label") or "")
    if not note and isinstance(item.get("evidence"), str) and not rel["evidence"]:
        note = _s(item.get("evidence"))
    if note:
        rel["note"] = note
    return rel


def _norm_flow_end(item: Any, res: _Resolver, *, sink: bool) -> dict[str, Any]:
    if isinstance(item, str):
        loc = _loc(item)
        if loc:
            return loc
        comp = res.resolve(item)
        if comp:
            return {"component": comp}
        return {"kind": _s(item, 40)} if sink else {"label": _s(item, 200)}
    if not isinstance(item, dict):
        return {}
    out: dict[str, Any] = {}
    comp = res.normalize(item.get("component") or "")
    if comp:
        out["component"] = comp
    if sink:
        kind = _s(item.get("kind") or "", 40).lower()
        if kind:
            out["kind"] = kind
    else:
        label = _s(item.get("label") or item.get("name") or "", 200)
        if label:
            out["label"] = label
    out.update(_loc(item))
    return out


def _norm_step(item: Any, res: _Resolver) -> Optional[dict[str, Any]]:
    if isinstance(item, str):
        loc = _loc(item)
        if loc:
            return loc
        s = _s(item)
        return {"note": s} if s else None
    if not isinstance(item, dict):
        return None
    out: dict[str, Any] = {}
    comp = res.normalize(item.get("component") or "")
    if comp:
        out["component"] = comp
    out.update(_loc(item))
    note = _s(item.get("note") or item.get("description") or item.get("label") or "")
    if note:
        out["note"] = note
    return out or None


def _norm_flow(item: Any, res: _Resolver, index: int) -> Optional[dict[str, Any]]:
    if not isinstance(item, dict):
        return None
    source = _norm_flow_end(item.get("source"), res, sink=False)
    sink = _norm_flow_end(item.get("sink"), res, sink=True)
    steps = [s for s in (_norm_step(x, res) for x in _as_list(item.get("steps"))) if s]
    steps = steps[:MAX_STEPS]
    if not source and not sink and not steps:
        return None
    fid = slugify(item.get("id"), limit=60) or f"f{index}"
    crosses = []
    for z in _as_list(item.get("crosses")):
        zs = slugify(z, limit=40)
        if zs and zs not in crosses:
            crosses.append(zs)
    classes = []
    for c in _as_list(item.get("classes")):
        cs = _s(c, 60).lower()
        if cs and cs not in classes:
            classes.append(cs)
    return {
        "id": fid,
        "title": _s(item.get("title") or item.get("name") or "", 200),
        "source": source,
        "steps": steps,
        "sink": sink,
        "crosses": crosses[:8],
        "classes": classes[:MAX_CLASSES],
        "confidence": _confidence(item.get("confidence"), FLOW_CONFIDENCE),
    }


def _empty_v2() -> dict[str, Any]:
    return {
        "schema": SCHEMA_V2,
        "summary": "",
        "zones": [],
        "components": [],
        "boundaries": [],
        "relations": [],
        "flows": [],
        "trust_boundaries": [],
        "input_surfaces": [],
        "hunt_focus": [],
    }


def normalize_architecture_v2(arch: Any) -> dict[str, Any]:
    """Return a v2-shaped copy of *arch* (v1 or v2 input). Never raises.

    Only schema keys are returned (callers that need passthrough of extra
    keys such as ``inventory`` / ``seed_sinks`` should overlay:
    ``{**arch, **normalize_architecture_v2(arch)}``). Idempotent.
    """
    out = _empty_v2()
    if not isinstance(arch, dict):
        return out
    try:
        return _normalize(arch, out)
    except Exception:  # pragma: no cover — defensive; junk never raises
        return _empty_v2()


def _normalize(arch: dict, out: dict[str, Any]) -> dict[str, Any]:
    out["summary"] = _s(arch.get("summary"), MAX_SUMMARY)
    origin = _s(arch.get("origin"), 20).lower()
    if origin in ORIGINS:
        out["origin"] = origin

    zones: list[dict[str, Any]] = []
    zone_idx: dict[str, int] = {}
    for item in _as_list(arch.get("zones")):
        z = _norm_zone(item)
        if not z:
            continue
        if z["id"] in zone_idx:
            continue
        zone_idx[z["id"]] = len(zones)
        zones.append(z)
        if len(zones) >= MAX_ZONES:
            break
    out["zones"] = zones

    comps: list[dict[str, Any]] = []
    comp_idx: dict[str, int] = {}
    for item in _as_list(arch.get("components")):
        c = _norm_component(item)
        if not c:
            continue
        if c["id"] in comp_idx:
            _merge_component_into(comps[comp_idx[c["id"]]], c)
            continue
        if len(comps) >= MAX_COMPONENTS:
            continue
        comp_idx[c["id"]] = len(comps)
        comps.append(c)
    # Component zone → zone id when it names a zone by label/kind
    if zones:
        zmap: dict[str, str] = {}
        for z in zones:
            zmap.setdefault(z["id"], z["id"])
            zmap.setdefault(slugify(z["label"]), z["id"])
        for z in zones:
            zmap.setdefault(z["kind"], z["id"])
    else:
        zmap = {}
    for c in comps:
        if not c["zone"]:
            continue
        if c["zone"] in zmap:
            c["zone"] = zmap[c["zone"]]
            continue
        k = _zone_kind(c["zone"])
        if k:
            c["zone"] = zmap.get(k, k)
    out["components"] = comps
    res = _Resolver(comps)

    bounds = [b for b in (_norm_boundary(x) for x in _as_list(arch.get("boundaries"))) if b]
    out["boundaries"] = _dedupe_dicts(bounds, MAX_BOUNDARIES)

    rels: list[dict[str, Any]] = []
    rel_idx: dict[tuple, int] = {}
    for item in _as_list(arch.get("relations")):
        r = _norm_relation(item, res)
        if not r:
            continue
        key = (r["from"].lower(), r["to"].lower(), r["kind"])
        if key in rel_idx:
            prev = rels[rel_idx[key]]
            if _CONF_RANK[r["confidence"]] > _CONF_RANK[prev["confidence"]]:
                prev["confidence"] = r["confidence"]
            if not prev.get("evidence") and r.get("evidence"):
                prev["evidence"] = r["evidence"]
            continue
        if len(rels) >= MAX_RELATIONS:
            continue
        rel_idx[key] = len(rels)
        rels.append(r)
    out["relations"] = rels

    flows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for i, item in enumerate(_as_list(arch.get("flows")), 1):
        f = _norm_flow(item, res, i)
        if not f:
            continue
        base_id = f["id"]
        n = 2
        while f["id"] in seen_ids:
            f["id"] = f"{base_id}-{n}"
            n += 1
        seen_ids.add(f["id"])
        flows.append(f)
        if len(flows) >= MAX_FLOWS:
            break
    out["flows"] = flows

    out["trust_boundaries"] = _v1_list(arch.get("trust_boundaries"), 30)
    out["input_surfaces"] = _v1_list(arch.get("input_surfaces"))
    out["hunt_focus"] = _v1_list(arch.get("hunt_focus"))
    return out


def is_v2(arch: Any) -> bool:
    return isinstance(arch, dict) and str(arch.get("schema") or "") == SCHEMA_V2


# ---------------------------------------------------------------------------
# Citation validator (read-only, path-jailed)
# ---------------------------------------------------------------------------


class _LineCounter:
    """Path-jailed line counts under *root*; caches per path."""

    MAX_BYTES = 8_000_000

    def __init__(self, root: Path):
        r = Path(root)
        try:
            r = r.resolve()
        except OSError:
            pass
        if r.is_file():
            r = r.parent
        self.root = r
        self._cache: dict[str, Optional[int]] = {}

    def lines(self, rel: str) -> Optional[int]:
        """Line count of *rel*, or None when missing / outside the jail."""
        if rel in self._cache:
            return self._cache[rel]
        self._cache[rel] = n = self._count(rel)
        return n

    def _count(self, rel: str) -> Optional[int]:
        p = str(rel or "").replace("\\", "/").strip()
        if not p or p.startswith("/") or re.match(r"^[A-Za-z]:", p) or "\x00" in p:
            return None
        parts = [x for x in p.split("/") if x not in ("", ".")]
        if not parts or any(x == ".." for x in parts):
            return None
        try:
            cand = self.root.joinpath(*parts).resolve()
            cand.relative_to(self.root)
        except (OSError, ValueError, RuntimeError):
            return None
        try:
            if not cand.is_file():
                return None
            size = cand.stat().st_size
            if size > self.MAX_BYTES:
                return None
            data = cand.read_bytes()
        except OSError:
            return None
        if not data:
            return 0
        n = data.count(b"\n")
        if not data.endswith(b"\n"):
            n += 1
        return n


def _check_loc(obj: dict[str, Any], lc: _LineCounter, stats: dict[str, int]) -> bool:
    """Validate obj's path/line in place. Returns True when path+line is valid.

    Missing/escaping path → path and line removed. Bad line → line removed.
    """
    if not isinstance(obj, dict) or not obj.get("path"):
        return False
    stats["checked"] += 1
    n = lc.lines(str(obj.get("path")))
    if n is None:
        obj.pop("path", None)
        obj.pop("line", None)
        stats["invalid"] += 1
        return False
    ln = obj.get("line")
    if not isinstance(ln, int) or ln < 1:
        obj.pop("line", None)
        stats["invalid"] += 1
        return False
    if ln > n:
        obj.pop("line", None)
        stats["invalid"] += 1
        return False
    stats["valid"] += 1
    return True


def validate_citations(
    arch: Any,
    target_root: Path,
    *,
    report: Optional[dict[str, int]] = None,
) -> dict[str, Any]:
    """Check every ``path:line`` citation against the read-only target tree.

    Returns a normalized v2 copy. Relations / flows whose citations all check
    out become ``cited`` (``mechanical`` relations stay ``mechanical``);
    anything else becomes ``inferred``. Bad lines are removed; paths that do
    not exist or escape *target_root* are removed. Never writes, never raises.
    Optional *report* is filled with ``checked`` / ``valid`` / ``invalid``.
    """
    out = normalize_architecture_v2(arch)
    stats = {"checked": 0, "valid": 0, "invalid": 0}
    try:
        lc = _LineCounter(Path(target_root))
    except Exception:
        lc = None  # type: ignore[assignment]
    if lc is None:
        if report is not None:
            report.update(stats)
        return out

    for z in out["zones"]:
        kept = []
        for ev in z.get("evidence") or []:
            _check_loc(ev, lc, stats)
            if ev.get("path"):
                kept.append(ev)
        if kept:
            z["evidence"] = kept
        else:
            z.pop("evidence", None)
    for c in out["components"]:
        for key in ("entrypoints", "sinks"):
            for item in c.get(key) or []:
                if item.get("path"):
                    _check_loc(item, lc, stats)
    for b in out["boundaries"]:
        if b.get("path"):
            _check_loc(b, lc, stats)

    for r in out["relations"]:
        ev = r.get("evidence") or {}
        ok = _check_loc(ev, lc, stats) if ev.get("path") else False
        if not ev.get("path"):
            ev = {}
        r["evidence"] = ev
        if r["confidence"] == "mechanical":
            continue
        r["confidence"] = "cited" if ok else "inferred"

    for f in out["flows"]:
        results: list[bool] = []
        for end in (f.get("source") or {}, f.get("sink") or {}):
            if end.get("path"):
                results.append(_check_loc(end, lc, stats))
        for step in f.get("steps") or []:
            if step.get("path"):
                results.append(_check_loc(step, lc, stats))
            else:
                results.append(False)  # uncited step
        f["confidence"] = "cited" if results and all(results) else "inferred"

    if report is not None:
        report.update(stats)
    return out


# ---------------------------------------------------------------------------
# Deterministic merge
# ---------------------------------------------------------------------------


def _union(a: list, b: list, limit: int) -> list:
    return _dedupe_dicts(list(a or []) + list(b or []), limit)


def merge_v2(base: Any, newer: Any) -> dict[str, Any]:
    """Merge two maps deterministically (newer wins on text, lists union).

    Components match by id (or by name → id). A ``mechanical`` component that
    recon names is upgraded to origin ``recon``. Relations key on
    (from, to, kind); flows on id. After the merge, relations whose endpoints
    resolve to no component are dropped, and flows whose non-empty
    source/sink component is unknown are dropped (empty endpoints are kept).
    """
    a = normalize_architecture_v2(base)
    b = normalize_architecture_v2(newer)
    out = _empty_v2()
    out["summary"] = b["summary"] or a["summary"]
    def _origin_of(m: dict[str, Any]) -> Optional[str]:
        if m.get("origin"):
            return str(m["origin"])
        has_content = m["components"] or m["summary"] or m["flows"] or m["relations"]
        return "recon" if has_content else None

    origins = {o for o in (_origin_of(a), _origin_of(b)) if o}
    out["origin"] = "mechanical" if origins == {"mechanical"} else "recon"

    # Zones
    zones: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for z in a["zones"] + b["zones"]:
        if z["id"] not in zones:
            zones[z["id"]] = copy.deepcopy(z)
            order.append(z["id"])
            continue
        cur = zones[z["id"]]
        for k in ("label", "kind", "description"):
            if z.get(k):
                cur[k] = z[k]
        ev = _union(cur.get("evidence") or [], z.get("evidence") or [], MAX_EVIDENCE)
        if ev:
            cur["evidence"] = ev
    out["zones"] = [zones[i] for i in order][:MAX_ZONES]

    # Components (base order, then new ones)
    comps: list[dict[str, Any]] = [copy.deepcopy(c) for c in a["components"]]
    res_a = _Resolver(comps)
    by_id = {c["id"]: c for c in comps}
    for c in b["components"]:
        hit = res_a.resolve(c["id"]) or res_a.resolve(c["name"])
        if not hit:
            if len(comps) < MAX_COMPONENTS:
                nc = copy.deepcopy(c)
                comps.append(nc)
                by_id[nc["id"]] = nc
            continue
        cur = by_id[hit]
        was_mech = cur.get("origin") == "mechanical"
        if c.get("origin") == "mechanical" and not was_mech:
            # A mechanical refresh never overwrites recon text; it only fills gaps.
            _merge_component_into(cur, c)
            continue
        for k in ("name", "kind", "role", "zone"):
            if k == "name" and c.get("name") == c.get("id") and cur.get("name"):
                # A part that only cited the id (name defaulted to it) must not
                # clobber a real name with the slug.
                continue
            if c.get(k):
                cur[k] = c[k]
        if c.get("zone"):
            if c.get("origin") == "recon":
                cur["zone_source"] = "recon"
            elif c.get("zone_source"):
                cur["zone_source"] = c["zone_source"]
        _merge_component_into(cur, c)
        if was_mech and c.get("origin") == "recon":
            cur["origin"] = "recon"
    out["components"] = comps
    res = _Resolver(comps)

    out["boundaries"] = _union(a["boundaries"], b["boundaries"], MAX_BOUNDARIES)

    # Relations
    rels: list[dict[str, Any]] = []
    rel_idx: dict[tuple, int] = {}
    for r in a["relations"] + b["relations"]:
        frm = res.resolve(r["from"])
        to = res.resolve(r["to"])
        if not frm or not to or frm == to:
            continue
        r = copy.deepcopy(r)
        r["from"], r["to"] = frm, to
        key = (frm, to, r["kind"])
        if key not in rel_idx:
            if len(rels) >= MAX_RELATIONS:
                continue
            rel_idx[key] = len(rels)
            rels.append(r)
            continue
        cur = rels[rel_idx[key]]
        if r.get("note"):
            cur["note"] = r["note"]
        new_ev = r.get("evidence") or {}
        old_ev = cur.get("evidence") or {}
        # Newer evidence wins only when it is at least as specific, and never
        # over a mechanical edge's own citation.
        if new_ev and cur["confidence"] != "mechanical" and (
            new_ev.get("line") or not old_ev.get("line")
        ):
            cur["evidence"] = new_ev
        if _CONF_RANK[r["confidence"]] > _CONF_RANK[cur["confidence"]]:
            cur["confidence"] = r["confidence"]
    out["relations"] = rels

    # Flows
    flows: dict[str, dict[str, Any]] = {}
    forder: list[str] = []
    for f in a["flows"] + b["flows"]:
        if f["id"] not in flows:
            flows[f["id"]] = copy.deepcopy(f)
            forder.append(f["id"])
            continue
        cur = flows[f["id"]]
        if f.get("title"):
            cur["title"] = f["title"]
        for k in ("source", "sink"):
            if f.get(k):
                cur[k] = copy.deepcopy(f[k])
        if f.get("steps"):
            cur["steps"] = copy.deepcopy(f["steps"])
            cur["confidence"] = f["confidence"]
        cur["crosses"] = _str_list(cur["crosses"] + f["crosses"], 8, 40)
        cur["classes"] = _str_list(cur["classes"] + f["classes"], MAX_CLASSES, 60)
    kept_flows: list[dict[str, Any]] = []
    for fid in forder:
        f = flows[fid]
        drop = False
        for k in ("source", "sink"):
            end = f.get(k) or {}
            if end.get("component"):
                hit = res.resolve(end["component"])
                if not hit:
                    drop = True
                    break
                end["component"] = hit
        if drop:
            continue
        for step in f.get("steps") or []:
            if step.get("component"):
                hit = res.resolve(step["component"])
                if hit:
                    step["component"] = hit
                else:
                    step.pop("component", None)
        kept_flows.append(f)
    out["flows"] = kept_flows[:MAX_FLOWS]

    out["trust_boundaries"] = _union(a["trust_boundaries"], b["trust_boundaries"], 30)
    out["input_surfaces"] = _union(a["input_surfaces"], b["input_surfaces"], MAX_V1_ITEMS)
    out["hunt_focus"] = _union(a["hunt_focus"], b["hunt_focus"], MAX_V1_ITEMS)
    return out


__all__ = [
    "CONFIDENCE_LEVELS",
    "FLOW_CONFIDENCE",
    "RELATION_KINDS",
    "SCHEMA_V2",
    "ZONE_KINDS",
    "ZONE_LABELS",
    "is_v2",
    "merge_v2",
    "normalize_architecture_v2",
    "relation_kind",
    "slugify",
    "validate_citations",
]
