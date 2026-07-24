"""Editable hunt profile collection under config/hunt_profiles/."""

from __future__ import annotations

import json
import os
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Optional

from vulnforge.paths import CONFIG_ROOT, PROJECT_ROOT, hunt_class_seeds_root
from vulnforge.util import utc_now_iso

DEFAULT_COLLECTION_ROOT = CONFIG_ROOT / "hunt_profiles"
# Dual-read: seeds/hunt_classes when present, else prompts/v1/hunt_classes.
SEED_PROMPTS_DIR = hunt_class_seeds_root()

COLLECTION_FORMAT = "vulnforge.hunt_collection/v1"
PROFILE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
MAX_BODY_BYTES = 256 * 1024
PROFILE_META_VERSION = 2

# Migration-only initial active set (former DEFAULT_CLASSES). Not a runtime
# "default profiles" concept after seed.
SEED_ACTIVE_IDS = frozenset(
    {
        "injection",
        "access-control",
        "business-logic",
        "cryptography",
        "wildcard",
    }
)

# Seed metadata for package hunt classes (backward-compatible optional fields).
# angle_ids: 1-based indices into seeds/system/hunting_angles.md
# sink_families: kinds from tools/sink_preindex._SINK_PATTERNS
# specificity: higher wins in stages/dedup cross-class merge
SEED_PROFILE_META: dict[str, dict[str, Any]] = {
    "injection": {
        "description": "Untrusted data to SQL/command/template/path/deserialize interpreters",
        "tags": ["injection", "sqli", "rce", "ssti", "path-traversal"],
        "languages": [],
        "cwe": ["CWE-89", "CWE-78", "CWE-94", "CWE-22", "CWE-502"],
        "angle_ids": [1, 3, 6, 7],
        "sink_families": ["sql", "exec", "template", "deserialize", "path"],
        "specificity": 20,
        "version": PROFILE_META_VERSION,
    },
    "access-control": {
        "description": "IDOR/BOLA, missing authz, mass assignment, unauth mutators",
        "tags": ["authz", "idor", "bola", "bfla", "mass-assignment"],
        "languages": [],
        "cwe": ["CWE-639", "CWE-862", "CWE-863", "CWE-284", "CWE-915"],
        "angle_ids": [4, 5, 9, 12],
        "sink_families": ["auth", "jwt"],
        "specificity": 20,
        "version": PROFILE_META_VERSION,
    },
    "business-logic": {
        "description": "Break money/workflow/quota invariants via allowed APIs",
        "tags": ["logic", "workflow", "race", "pricing", "replay"],
        "languages": [],
        "cwe": ["CWE-840", "CWE-841", "CWE-367"],
        "angle_ids": [1, 4, 5, 9],
        "sink_families": [],
        "specificity": 15,
        "version": PROFILE_META_VERSION,
    },
    "cryptography": {
        "description": "Secret/crypto misuse that forges, decrypts, or breaks integrity",
        "tags": ["crypto", "secrets", "jwt", "tls", "hashing"],
        "languages": [],
        "cwe": ["CWE-327", "CWE-798", "CWE-321", "CWE-347", "CWE-330"],
        "angle_ids": [6, 8, 11, 12],
        "sink_families": ["jwt"],
        "specificity": 20,
        "version": PROFILE_META_VERSION,
    },
    "wildcard": {
        "description": "Residual trust edges and creative cross-class bugs other packs miss",
        "tags": ["wildcard", "creative", "residual"],
        "languages": [],
        "cwe": [],
        "angle_ids": [1, 3, 9, 12],
        "sink_families": [],
        "specificity": 1,
        "version": PROFILE_META_VERSION,
    },
    "ai-llm": {
        "description": "Untrusted text → model/agent → privileged tool or sink",
        "tags": ["llm", "prompt-injection", "agents", "rag", "mcp"],
        "languages": [],
        "cwe": ["CWE-77", "CWE-94", "CWE-918"],
        "angle_ids": [3, 9, 11, 12],
        "sink_families": ["llm"],
        "specificity": 30,
        "version": PROFILE_META_VERSION,
    },
    "chains": {
        "description": "Multi-hop combinations that cross trust boundaries",
        "tags": ["chains", "multi-step", "second-order"],
        "languages": [],
        "cwe": ["CWE-269"],
        "angle_ids": [3, 4, 7, 9],
        "sink_families": [],
        "specificity": 10,
        "version": PROFILE_META_VERSION,
    },
    "client-side": {
        "description": "DOM XSS, postMessage, CORS+credentials, CSWSH, prototype pollution",
        "tags": ["xss", "dom", "cors", "postmessage", "browser"],
        "languages": ["js", "ts", "html"],
        "cwe": ["CWE-79", "CWE-346", "CWE-942", "CWE-1321"],
        "angle_ids": [3, 6, 7, 10],
        "sink_families": ["template"],
        "specificity": 15,
        "version": PROFILE_META_VERSION,
    },
    "feature-abuse": {
        "description": "Abuse export/search/webhooks/import for over-access or SSRF",
        "tags": ["feature-abuse", "ssrf", "export", "webhooks"],
        "languages": [],
        "cwe": ["CWE-918", "CWE-200", "CWE-639"],
        "angle_ids": [8, 9, 11, 12],
        "sink_families": ["ssrf"],
        "specificity": 12,
        "version": PROFILE_META_VERSION,
    },
    "graphql": {
        "description": "GraphQL BOLA, field-level authz gaps, batching/alias abuse",
        "tags": ["graphql", "bola", "batching", "resolvers"],
        "languages": [],
        "cwe": ["CWE-639", "CWE-862", "CWE-770"],
        "angle_ids": [3, 4, 9, 12],
        "sink_families": ["auth"],
        "specificity": 18,
        "version": PROFILE_META_VERSION,
    },
    "memory-safety": {
        "description": "Spatial/temporal memory bugs on native/unsafe attacker-controlled input",
        "tags": ["memory", "native", "overflow", "uaf", "unsafe"],
        "languages": ["c", "cpp", "rust", "objc"],
        "cwe": ["CWE-119", "CWE-416", "CWE-787", "CWE-125"],
        "angle_ids": [1, 2, 6, 7],
        "sink_families": [],
        "specificity": 18,
        "version": PROFILE_META_VERSION,
    },
    "obvious": {
        "description": "High-signal dumb checks: secrets, debug routes, open redirects",
        "tags": ["obvious", "secrets", "debug", "checklist"],
        "languages": [],
        "cwe": ["CWE-798", "CWE-200", "CWE-489", "CWE-601"],
        "angle_ids": [1, 9, 10, 11],
        "sink_families": [],
        "specificity": 5,
        "version": PROFILE_META_VERSION,
    },
    "supply-chain": {
        "description": "Install/build/update trust breaks with real attacker impact",
        "tags": ["supply-chain", "ci", "dependencies", "install-scripts"],
        "languages": [],
        "cwe": ["CWE-829", "CWE-494", "CWE-506"],
        "angle_ids": [3, 8, 11, 12],
        "sink_families": [],
        "specificity": 14,
        "version": PROFILE_META_VERSION,
    },
    "web-protocol-auth": {
        "description": "HTTP framing, cache keys, JWT/OAuth/SAML/session machinery",
        "tags": ["http", "oauth", "jwt", "session", "smuggling"],
        "languages": [],
        "cwe": ["CWE-444", "CWE-287", "CWE-384", "CWE-613"],
        "angle_ids": [2, 6, 9, 12],
        "sink_families": ["auth", "jwt"],
        "specificity": 18,
        "version": PROFILE_META_VERSION,
    },
}


def _default_meta() -> dict[str, Any]:
    return {
        "description": "",
        "tags": [],
        "languages": [],
        "cwe": [],
        "angle_ids": [],
        "sink_families": [],
        "specificity": 0,
        "version": 1,
    }


def _as_str_list(raw: object, *, max_items: int = 32, max_len: int = 64) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.replace(";", ",").split(",")]
        items = [p for p in parts if p]
    elif isinstance(raw, (list, tuple, set)):
        items = [str(x).strip() for x in raw if str(x).strip()]
    else:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for it in items[:max_items]:
        s = it[:max_len]
        if s.lower() in seen:
            continue
        seen.add(s.lower())
        out.append(s)
    return out


def _as_int_list(raw: object, *, max_items: int = 12, lo: int = 1, hi: int = 12) -> list[int]:
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        seq = list(raw)
    elif isinstance(raw, (int, float)):
        seq = [raw]
    elif isinstance(raw, str):
        seq = [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]
    else:
        return []
    out: list[int] = []
    seen: set[int] = set()
    for x in seq:
        try:
            n = int(x)
        except (TypeError, ValueError):
            continue
        if n < lo or n > hi or n in seen:
            continue
        seen.add(n)
        out.append(n)
        if len(out) >= max_items:
            break
    return out


def _as_int(raw: object, default: int = 0, *, lo: int = 0, hi: int = 100) -> int:
    try:
        n = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def _normalize_profile_meta(p: dict[str, Any], *, profile_id: str = "") -> dict[str, Any]:
    """Normalize optional profile metadata; missing keys → empty/zero or seed defaults."""
    seed = SEED_PROFILE_META.get(profile_id or str(p.get("id") or ""), {})
    desc = str(p.get("description") or "").strip()[:500]
    if not desc:
        desc = str(seed.get("description") or "").strip()[:500]

    # Prefer explicit fields; fall back to seed only when key absent (not empty list)
    def pick_list(key: str, caster) -> list:
        if key in p:
            return caster(p.get(key))
        if key in seed:
            return caster(seed.get(key))
        return []

    tags = pick_list("tags", _as_str_list)
    languages = pick_list("languages", _as_str_list)
    cwe = pick_list("cwe", lambda r: _as_str_list(r, max_items=16, max_len=32))
    angle_ids = pick_list("angle_ids", _as_int_list)
    sink_families = pick_list(
        "sink_families",
        lambda r: [x.lower() for x in _as_str_list(r, max_items=16, max_len=32)],
    )
    if "specificity" in p and p.get("specificity") is not None:
        specificity = _as_int(p.get("specificity"), 0)
    elif "specificity" in seed:
        specificity = _as_int(seed.get("specificity"), 0)
    else:
        specificity = 0
    if "version" in p and p.get("version") is not None:
        version = _as_int(p.get("version"), 1, lo=1, hi=999)
    elif "version" in seed:
        version = _as_int(seed.get("version"), 1, lo=1, hi=999)
    else:
        version = 1
    return {
        "description": desc,
        "tags": tags,
        "languages": languages,
        "cwe": cwe,
        "angle_ids": angle_ids,
        "sink_families": sink_families,
        "specificity": specificity,
        "version": version,
    }


def _coerce_tools(value: object) -> Optional[list[str]]:
    """Optional tools allowlist; None means full default hunt tool set."""
    if value is None:
        return None
    if isinstance(value, str):
        parts = [p.strip() for p in value.replace(";", ",").split(",") if p.strip()]
        return parts or None
    if not isinstance(value, list):
        return None
    out = [str(x).strip() for x in value if str(x).strip()]
    return out or None


def _as_meta_str(raw: object, *, max_len: int = 256) -> str:
    """Normalize optional provenance/meta strings for stable JSON."""
    if raw is None:
        return ""
    return str(raw).strip()[:max_len]


def _profile_public_fields(p: dict[str, Any]) -> dict[str, Any]:
    """Stable public profile dict for collection.json / API (no internal keys)."""
    pid = str(p.get("id") or "")
    meta = _normalize_profile_meta(p, profile_id=pid)
    return {
        "id": pid,
        "title": str(p.get("title") or pid).strip()[:120] or pid,
        "description": meta["description"],
        "active": bool(p.get("active")),
        "body_file": f"bodies/{pid}.md",
        "source": str(p.get("source") or "custom")[:32],
        "tags": meta["tags"],
        "languages": meta["languages"],
        "cwe": meta["cwe"],
        "angle_ids": meta["angle_ids"],
        "sink_families": meta["sink_families"],
        "specificity": meta["specificity"],
        "version": meta["version"],
        "tools": _coerce_tools(p.get("tools")),
        # Provenance (always strings for stable collection.json / API)
        "created_at": _as_meta_str(p.get("created_at"), max_len=64),
        "origin_target_id": _as_meta_str(p.get("origin_target_id"), max_len=256),
        "origin_run_id": _as_meta_str(p.get("origin_run_id"), max_len=128),
    }

# Aliases for normalize_class (legacy recon stems).
CLASS_ALIASES: dict[str, str] = {
    "auth": "access-control",
    "authorization": "access-control",
    "authz": "access-control",
    "sqli": "injection",
    "xss": "injection",
    "crypto": "cryptography",
    "business": "business-logic",
    "logic": "business-logic",
    "llm": "ai-llm",
    "ai": "ai-llm",
    "protocol": "web-protocol-auth",
    "http": "web-protocol-auth",
    "oauth": "web-protocol-auth",
    "browser": "client-side",
    "dom": "client-side",
    "memory": "memory-safety",
    "binary": "memory-safety",
    "native": "memory-safety",
    "feature": "feature-abuse",
    "chain": "chains",
    "chained": "chains",
    "supply": "supply-chain",
    "supplychain": "supply-chain",
    "dependency": "supply-chain",
    "dependencies": "supply-chain",
    "sca": "supply-chain",
    "gql": "graphql",
    "graph-ql": "graphql",
}

_root_override: Optional[Path] = None


class HuntProfileError(ValueError):
    """Invalid hunt profile or collection operation."""


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
    env = (os.environ.get("VULNFORGE_HUNT_PROFILES_ROOT") or "").strip()
    if env:
        return Path(env).resolve()
    return DEFAULT_COLLECTION_ROOT


def _collection_path(root: Optional[Path] = None) -> Path:
    return (root or collection_root()) / "collection.json"


def _bodies_dir(root: Optional[Path] = None) -> Path:
    return (root or collection_root()) / "bodies"


def _validate_id(profile_id: str) -> str:
    pid = str(profile_id or "").strip().lower()
    if not PROFILE_ID_RE.match(pid):
        raise HuntProfileError(
            f"invalid profile id {profile_id!r}: use lowercase slug "
            f"[a-z][a-z0-9-]{{0,63}}"
        )
    return pid


def _body_path(profile_id: str, root: Optional[Path] = None) -> Path:
    root = root or collection_root()
    bodies = _bodies_dir(root).resolve()
    path = (bodies / f"{profile_id}.md").resolve()
    if bodies not in path.parents and path != bodies:
        raise HuntProfileError(f"path escape for body: {profile_id}")
    if path.name != f"{profile_id}.md":
        raise HuntProfileError(f"path escape for body: {profile_id}")
    return path


def _title_from_body(body: str, fallback_id: str) -> str:
    # Prefer first markdown H1 after optional frontmatter
    in_fm = False
    saw_fm_start = False
    for line in (body or "").splitlines():
        s = line.strip()
        if not saw_fm_start and s == "---":
            saw_fm_start = True
            in_fm = True
            continue
        if in_fm:
            if s == "---":
                in_fm = False
            continue
        if s.startswith("#"):
            t = s.lstrip("#").strip()
            # "Hunt class: injection" → rest after colon
            if ":" in t:
                t = t.split(":", 1)[1].strip() or t
            if t:
                return t[:120]
    fm = _parse_frontmatter(body)
    if fm.get("name"):
        return str(fm["name"]).strip().replace("-", " ").title()[:120]
    return fallback_id.replace("-", " ").title()


def _description_from_body(body: str) -> str:
    fm = _parse_frontmatter(body)
    desc = str(fm.get("description") or "").strip()
    return desc[:500]


def _parse_frontmatter(body: str) -> dict[str, str]:
    """Minimal YAML-ish frontmatter: --- / key: value / --- (scalars only)."""
    text = body or ""
    if not text.startswith("---"):
        return {}
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    out: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        k = key.strip()
        v = val.strip().strip('"').strip("'")
        if k:
            out[k] = v
    return out


def _empty_collection() -> dict[str, Any]:
    return {
        "format": COLLECTION_FORMAT,
        "updated_at": utc_now_iso(),
        "seeded_from": "seeds/hunt_classes",
        "profiles": [],
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
        raise HuntProfileError(f"corrupt collection.json: {e}") from e
    if not isinstance(raw, dict):
        raise HuntProfileError("collection.json must be an object")
    return raw


def _normalize_collection(raw: dict[str, Any]) -> dict[str, Any]:
    out = _empty_collection()
    if raw.get("format") and raw.get("format") != COLLECTION_FORMAT:
        # Accept missing format on disk from partial writes; reject unknown formats
        if str(raw.get("format")).startswith("vulnforge.hunt_collection/"):
            raise HuntProfileError(f"unsupported collection format: {raw.get('format')}")
    out["format"] = COLLECTION_FORMAT
    out["updated_at"] = str(raw.get("updated_at") or utc_now_iso())
    out["seeded_from"] = str(raw.get("seeded_from") or "seeds/hunt_classes")
    profiles: list[dict[str, Any]] = []
    seen: set[str] = set()
    for p in raw.get("profiles") or []:
        if not isinstance(p, dict):
            continue
        try:
            pid = _validate_id(str(p.get("id") or ""))
        except HuntProfileError:
            continue
        if pid in seen:
            continue
        seen.add(pid)
        entry = dict(p)
        entry["id"] = pid
        entry["title"] = str(p.get("title") or pid).strip()[:120] or pid
        entry["active"] = bool(p.get("active"))
        entry["body_file"] = str(p.get("body_file") or f"bodies/{pid}.md")
        entry["source"] = str(p.get("source") or "custom")[:32]
        profiles.append(_profile_public_fields(entry))
    out["profiles"] = profiles
    return out


def _seed_profiles_from_package() -> list[dict[str, Any]]:
    """Build profile entries + bodies content from package seed library."""
    seed_dir = SEED_PROMPTS_DIR
    if not seed_dir.is_dir():
        raise HuntProfileError(f"seed library missing: {seed_dir}")
    items: list[tuple[str, str]] = []
    for path in sorted(seed_dir.glob("*.md")):
        pid = path.stem.lower()
        if not PROFILE_ID_RE.match(pid):
            continue
        body = path.read_text(encoding="utf-8")
        items.append((pid, body))
    if not items:
        raise HuntProfileError("seed library has no valid hunt class markdown files")

    # Stable order: seed-active first (known order), then rest alpha
    active_order = [
        "injection",
        "access-control",
        "business-logic",
        "cryptography",
        "wildcard",
    ]
    by_id = {pid: body for pid, body in items}
    ordered: list[str] = [p for p in active_order if p in by_id]
    ordered.extend(sorted(p for p in by_id if p not in SEED_ACTIVE_IDS))

    profiles: list[dict[str, Any]] = []
    for pid in ordered:
        body = by_id[pid]
        seed_meta = dict(SEED_PROFILE_META.get(pid, _default_meta()))
        entry = {
            "id": pid,
            "title": _title_from_body(body, pid),
            "active": pid in SEED_ACTIVE_IDS,
            "body_file": f"bodies/{pid}.md",
            "source": "seed",
            **seed_meta,
        }
        # Prefer non-empty description from seed meta; body frontmatter is secondary
        if not entry.get("description"):
            entry["description"] = _description_from_body(body)
        public = _profile_public_fields(entry)
        public["_body"] = body
        profiles.append(public)
    return profiles


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
        for pid, body in bodies.items():
            _validate_id(pid)
            _check_body(body)
            _atomic_write_text(_body_path(pid, root), body)
    # Drop internal keys before write
    clean_profiles = []
    for p in coll["profiles"]:
        clean_profiles.append(_profile_public_fields(p))
    coll["profiles"] = clean_profiles
    _atomic_write_json(_collection_path(root), coll)
    return coll


def _check_body(body: str) -> str:
    if body is None:
        raise HuntProfileError("body_md is required")
    text = str(body)
    if not text.strip():
        raise HuntProfileError("body_md must be non-empty")
    if len(text.encode("utf-8")) > MAX_BODY_BYTES:
        raise HuntProfileError(f"body_md exceeds {MAX_BODY_BYTES} bytes")
    return text


def ensure_collection(root: Optional[Path] = None) -> dict[str, Any]:
    """Load collection, seeding from package prompts if missing."""
    root = root or collection_root()
    existing = _read_collection_raw(root)
    if existing is not None:
        coll = _normalize_collection(existing)
        # Ensure body files exist for listed profiles when possible
        return coll
    seeded = _seed_profiles_from_package()
    bodies = {p["id"]: p.pop("_body") for p in seeded}
    coll = _empty_collection()
    coll["profiles"] = seeded
    return _write_collection(coll, bodies=bodies, root=root)


def seed_body_path(profile_id: str) -> Optional[Path]:
    """Return package seed markdown path for profile_id if it exists."""
    try:
        pid = _validate_id(profile_id)
    except HuntProfileError:
        return None
    path = (SEED_PROMPTS_DIR / f"{pid}.md").resolve()
    seed_root = SEED_PROMPTS_DIR.resolve()
    if seed_root not in path.parents and path != seed_root:
        return None
    if path.name != f"{pid}.md":
        return None
    if path.is_file():
        return path
    return None


def _read_seed_body(profile_id: str) -> Optional[str]:
    path = seed_body_path(profile_id)
    if path is None:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def seed_status(profile_id: str) -> str:
    """Provenance relative to package seed library.

    - seed: package file exists and body matches
    - modified_seed: package file exists but body differs (even if source=custom)
    - else: use stored source field (custom | generated | import | seed | …)
    """
    pid = _validate_id(profile_id)
    seed_body = _read_seed_body(pid)
    current: Optional[str] = None
    try:
        ensure_collection()
        path = _body_path(pid)
        if path.is_file():
            current = path.read_text(encoding="utf-8")
    except HuntProfileError:
        current = None

    if seed_body is not None:
        if current is not None and current == seed_body:
            return "seed"
        return "modified_seed"

    # No package seed file — fall back to stored source.
    source = "custom"
    try:
        coll = ensure_collection()
        for p in coll["profiles"]:
            if p["id"] == pid:
                source = str(p.get("source") or "custom")[:32]
                break
    except HuntProfileError:
        pass
    if source in ("seed", "modified_seed"):
        # Orphan source=seed without package file → treat as custom
        return "custom"
    return source or "custom"


def restore_seed_body(profile_id: str) -> dict[str, Any]:
    """Copy package seed body into the collection and set source=seed."""
    pid = _validate_id(profile_id)
    seed_body = _read_seed_body(pid)
    if seed_body is None:
        raise HuntProfileError(f"no package seed body for profile: {pid}")
    # Ensure profile exists (create from seed if missing).
    coll = ensure_collection()
    exists = any(p["id"] == pid for p in coll["profiles"])
    if not exists:
        seed_meta = dict(SEED_PROFILE_META.get(pid, _default_meta()))
        return save_profile(
            pid,
            body_md=seed_body,
            title=_title_from_body(seed_body, pid),
            description=str(seed_meta.get("description") or _description_from_body(seed_body)),
            active=pid in SEED_ACTIVE_IDS,
            source="seed",
            tags=seed_meta.get("tags"),
            languages=seed_meta.get("languages"),
            cwe=seed_meta.get("cwe"),
            angle_ids=seed_meta.get("angle_ids"),
            sink_families=seed_meta.get("sink_families"),
            specificity=seed_meta.get("specificity"),
            version=seed_meta.get("version"),
            create=True,
        )
    return save_profile(
        pid,
        body_md=seed_body,
        source="seed",
        create=False,
    )


def seed_diff(profile_id: str) -> dict[str, Any]:
    """Compare current body to package seed (if any)."""
    pid = _validate_id(profile_id)
    seed_path = seed_body_path(pid)
    seed_body = _read_seed_body(pid)
    try:
        current = get_body(pid)
    except HuntProfileError:
        current = ""
    has_seed = seed_body is not None
    return {
        "id": pid,
        "has_seed": has_seed,
        "seed_path": str(seed_path) if seed_path else None,
        "seed_status": seed_status(pid),
        "identical": bool(has_seed and current == seed_body),
        "current_body": current,
        "seed_body": seed_body if has_seed else None,
    }


def _enrich_seed_fields(row: dict[str, Any]) -> dict[str, Any]:
    """Attach live seed_status / has_seed (not persisted in collection.json)."""
    pid = str(row.get("id") or "")
    if not pid:
        row["seed_status"] = "custom"
        row["has_seed"] = False
        return row
    try:
        row["seed_status"] = seed_status(pid)
        row["has_seed"] = seed_body_path(pid) is not None
    except HuntProfileError:
        row["seed_status"] = str(row.get("source") or "custom")[:32]
        row["has_seed"] = False
    return row


def list_profiles(*, include_body: bool = False) -> list[dict[str, Any]]:
    coll = ensure_collection()
    out: list[dict[str, Any]] = []
    for p in coll["profiles"]:
        row = dict(p)
        if include_body:
            try:
                row["body_md"] = get_body(p["id"])
            except HuntProfileError:
                row["body_md"] = ""
        out.append(_enrich_seed_fields(row))
    return out


def get_profile(profile_id: str, *, include_body: bool = True) -> dict[str, Any]:
    pid = _validate_id(profile_id)
    coll = ensure_collection()
    for p in coll["profiles"]:
        if p["id"] == pid:
            row = dict(p)
            if include_body:
                row["body_md"] = get_body(pid)
            return _enrich_seed_fields(row)
    raise HuntProfileError(f"unknown hunt profile: {pid}")


def get_body(profile_id: str) -> str:
    pid = _validate_id(profile_id)
    ensure_collection()
    path = _body_path(pid)
    if not path.is_file():
        raise HuntProfileError(f"missing body for profile: {pid}")
    return path.read_text(encoding="utf-8")


def all_class_ids() -> list[str]:
    return [p["id"] for p in ensure_collection()["profiles"]]


def active_class_ids() -> list[str]:
    ids = [p["id"] for p in ensure_collection()["profiles"] if p.get("active")]
    if ids:
        return ids
    # Empty active set: fall back to all registered so planning never deadlocks
    return all_class_ids()


# Run-scoped hunt skill policy (PR-B). Stored under runs.config_json run.* and
# optional recon task payload; does not mutate the global Dev active set.
HUNT_SKILL_MODES = frozenset(
    {"all_active", "seed_active", "custom_only", "explicit"}
)
# Profiles authored outside the package seed library.
CUSTOM_PROFILE_SOURCES = frozenset({"custom", "generated", "import"})


def _normalize_skill_mode(mode: object) -> str:
    m = str(mode or "all_active").strip().lower().replace("-", "_")
    if m not in HUNT_SKILL_MODES:
        return "all_active"
    return m


def _normalize_skill_ids(skill_ids: list[str] | None) -> list[str]:
    if not skill_ids:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for raw in skill_ids:
        s = str(raw or "").strip().lower().replace("_", "-").replace(" ", "-")
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out[:64]


def resolve_run_class_ids(
    mode: str = "all_active",
    skill_ids: list[str] | None = None,
    *,
    prefer_active: bool = True,
) -> list[str]:
    """Resolve hunt class ids for a run under the given skill mode.

    Modes:
    - all_active: same as active_class_ids() (empty active → all registered)
    - seed_active: active (or all if not prefer_active) profiles with source==seed;
      empty when none match — never silently expands to non-seed profiles
    - custom_only: active (or all) with source in {custom, generated, import};
      empty when none — never reintroduces seed profiles
    - explicit: only skill_ids that exist in the collection (order preserved)

    prefer_active: when True (default), seed_active / custom_only require active=True.
    Empty results are intentional (recon may enqueue zero hunts).
    """
    mode_n = _normalize_skill_mode(mode)
    coll = ensure_collection()
    profiles = list(coll.get("profiles") or [])

    if mode_n == "all_active":
        return list(active_class_ids())

    if mode_n == "explicit":
        available = {str(p.get("id") or "") for p in profiles if p.get("id")}
        out: list[str] = []
        for sid in _normalize_skill_ids(skill_ids):
            # Accept registered ids only. Apply CLASS_ALIASES for known short
            # names (sqli→injection) but never silent fallback to wildcard.
            candidate = CLASS_ALIASES.get(sid, sid)
            if candidate in available and candidate not in out:
                out.append(candidate)
        return out

    if mode_n == "seed_active":
        want_sources = {"seed"}
    else:  # custom_only
        want_sources = set(CUSTOM_PROFILE_SOURCES)

    out = []
    for p in profiles:
        pid = str(p.get("id") or "").strip()
        if not pid:
            continue
        src = str(p.get("source") or "custom").strip().lower()
        if src not in want_sources:
            continue
        if prefer_active and not p.get("active"):
            continue
        out.append(pid)
    # No silent fallback to seeds/all when filters yield empty.
    return out


def skill_policy_from_run_cfg(
    cfg: Optional[dict[str, Any]] = None,
    *,
    payload: Optional[dict[str, Any]] = None,
) -> tuple[str, list[str] | None]:
    """Read hunt_skill_mode / hunt_skill_ids from run config and optional payload.

    Payload values override config when present (operator re-run / recon task).
    """
    run = {}
    if isinstance(cfg, dict):
        r = cfg.get("run")
        if isinstance(r, dict):
            run = r
    mode = run.get("hunt_skill_mode")
    ids = run.get("hunt_skill_ids")
    if isinstance(payload, dict):
        if payload.get("hunt_skill_mode") is not None:
            mode = payload.get("hunt_skill_mode")
        if "hunt_skill_ids" in payload:
            ids = payload.get("hunt_skill_ids")
    mode_n = _normalize_skill_mode(mode)
    skill_ids: list[str] | None
    if ids is None:
        skill_ids = None
    elif isinstance(ids, list):
        skill_ids = _normalize_skill_ids(ids)
    else:
        skill_ids = None
    return mode_n, skill_ids


def filter_profiles_for_run(
    mode: str = "all_active",
    skill_ids: list[str] | None = None,
    *,
    prefer_active: bool = True,
    include_body: bool = False,
) -> list[dict[str, Any]]:
    """Filter the hunt profile catalog to ids allowed for a run (recon packet)."""
    mode_n = _normalize_skill_mode(mode)
    allowed = set(
        resolve_run_class_ids(mode_n, skill_ids, prefer_active=prefer_active)
    )
    try:
        rows = list_profiles(include_body=include_body)
    except HuntProfileError:
        return []
    if mode_n == "all_active":
        # Full catalog (active + optional inactive) for default mode.
        return list(rows)
    return [p for p in rows if p.get("id") in allowed]


def catalog_for_ui() -> dict[str, Any]:
    """Hunt skill lists for Coverage / Explorer / Mission UI.

    - all / active: id lists (backward compatible)
    - by_source: seed | custom | generated | import | other
    - profiles: lightweight rows for grouping labels (id, source, active, title)
    """
    coll = ensure_collection()
    all_ids: list[str] = []
    active: list[str] = []
    by_source: dict[str, list[str]] = {
        "seed": [],
        "custom": [],
        "generated": [],
        "import": [],
        "other": [],
    }
    profiles: list[dict[str, Any]] = []
    for p in coll["profiles"]:
        pid = str(p.get("id") or "").strip()
        if not pid:
            continue
        all_ids.append(pid)
        is_active = bool(p.get("active"))
        if is_active:
            active.append(pid)
        src = str(p.get("source") or "custom").strip().lower() or "custom"
        if src not in by_source:
            src_key = "other"
        else:
            src_key = src
        by_source[src_key].append(pid)
        profiles.append(
            {
                "id": pid,
                "source": src,
                "active": is_active,
                "title": str(p.get("title") or pid),
            }
        )
    if not active:
        active = list(all_ids)
    return {
        "all": all_ids,
        "active": active,
        "by_source": by_source,
        "profiles": profiles,
    }


def save_profile(
    profile_id: str,
    *,
    body_md: Optional[str] = None,
    title: Optional[str] = None,
    description: Optional[str] = None,
    active: Optional[bool] = None,
    source: Optional[str] = None,
    tags: Optional[list[str] | str] = None,
    languages: Optional[list[str] | str] = None,
    cwe: Optional[list[str] | str] = None,
    angle_ids: Optional[list[int] | list[str] | str] = None,
    sink_families: Optional[list[str] | str] = None,
    specificity: Optional[int] = None,
    version: Optional[int] = None,
    tools: Optional[list[str] | str] = None,
    clear_tools: bool = False,
    created_at: Optional[str] = None,
    origin_target_id: Optional[str] = None,
    origin_run_id: Optional[str] = None,
    create: bool = False,
) -> dict[str, Any]:
    pid = _validate_id(profile_id)
    coll = ensure_collection()
    profiles = list(coll["profiles"])
    idx = next((i for i, p in enumerate(profiles) if p["id"] == pid), None)

    def _apply_meta(entry: dict[str, Any]) -> None:
        if tags is not None:
            entry["tags"] = _as_str_list(tags)
        if languages is not None:
            entry["languages"] = _as_str_list(languages)
        if cwe is not None:
            entry["cwe"] = _as_str_list(cwe, max_items=16, max_len=32)
        if angle_ids is not None:
            entry["angle_ids"] = _as_int_list(angle_ids)
        if sink_families is not None:
            entry["sink_families"] = [
                x.lower() for x in _as_str_list(sink_families, max_items=16, max_len=32)
            ]
        if specificity is not None:
            entry["specificity"] = _as_int(specificity, 0)
        if version is not None:
            entry["version"] = _as_int(version, 1, lo=1, hi=999)
        if clear_tools:
            entry["tools"] = None
        elif tools is not None:
            entry["tools"] = _coerce_tools(tools)

    if idx is None:
        if not create and body_md is None:
            raise HuntProfileError(f"unknown hunt profile: {pid}")
        if body_md is None:
            body_md = (
                f"---\nname: {pid}\n"
                f"description: >\n"
                f"  Use when hunting {pid.replace('-', ' ')} surfaces/sinks. "
                f"Also when recon or the operator mentions related stack signals. "
                f"Prefer this skill over generic checklists when the impact is class-specific.\n"
                f"---\n\n"
                f"# Hunt class: {pid}\n\n"
                f"## Mission\n\n(describe the attacker goal)\n\n"
                f"## Principles\n\n"
                f"- **Be certain.** Cite files you read.\n"
                f"- **One concrete action + effect.**\n"
                f"- **Honest none.** Nothing solid → `submit_none`.\n\n"
                f"## When to use\n\n- \n\n## When not to use\n\n- \n\n"
                f"## Rules quick reference\n\n"
                f"| Rule | Summary |\n|------|---------|\n|  |  |\n\n"
                f"## Focus\n\n- \n\n## Hunt workflow\n\n1. Inventory\n2. Walk to boundary\n"
                f"3. Prove missing control\n4. Or `submit_none`\n\n"
                f"## Stack cues\n\n```\n\n```\n\n## Required evidence\n\n- \n\n"
                f"## False positives\n\n- \n\n"
                f"## Anti-patterns\n\n"
                f"| Anti-pattern | Why it matters |\n|--------------|----------------|\n|  |  |\n\n"
                f"## Scope\n\n"
                f"This skill covers (narrow domain). Related registered classes — do not invent ids.\n\n"
                f"## Submit checklist\n\n"
                f"1. `write_evidence` then `submit_candidate` with weakness_class: {pid}\n"
                f"2. Or honest `submit_none`\n"
            )
        body = _check_body(body_md)
        desc = (description if description is not None else _description_from_body(body)).strip()[:500]
        # Create: stamp created_at (now if missing); origin only when provided
        ca = _as_meta_str(created_at, max_len=64) if created_at is not None else ""
        if not ca:
            ca = utc_now_iso()
        entry = {
            "id": pid,
            "title": (title or _title_from_body(body, pid)).strip()[:120],
            "description": desc,
            "active": bool(active) if active is not None else False,
            "body_file": f"bodies/{pid}.md",
            "source": (source or "custom")[:32],
            "tags": [],
            "languages": [],
            "cwe": [],
            "angle_ids": [],
            "sink_families": [],
            "specificity": 0,
            "version": 1,
            "tools": None,
            "created_at": ca,
            "origin_target_id": (
                _as_meta_str(origin_target_id, max_len=256)
                if origin_target_id is not None
                else ""
            ),
            "origin_run_id": (
                _as_meta_str(origin_run_id, max_len=128)
                if origin_run_id is not None
                else ""
            ),
        }
        _apply_meta(entry)
        profiles.append(_profile_public_fields(entry))
        coll["profiles"] = profiles
        _write_collection(coll, bodies={pid: body})
        return get_profile(pid)

    entry = dict(profiles[idx])
    bodies: dict[str, str] = {}
    if body_md is not None:
        body = _check_body(body_md)
        bodies[pid] = body
        if title is None and not entry.get("title"):
            entry["title"] = _title_from_body(body, pid)
        if description is None and not entry.get("description"):
            entry["description"] = _description_from_body(body)
    if title is not None:
        entry["title"] = str(title).strip()[:120] or pid
    if description is not None:
        entry["description"] = str(description).strip()[:500]
    if active is not None:
        entry["active"] = bool(active)
    if source is not None:
        entry["source"] = str(source)[:32]
    # Update: only touch provenance when explicitly passed (None preserves)
    if created_at is not None:
        entry["created_at"] = _as_meta_str(created_at, max_len=64)
    if origin_target_id is not None:
        entry["origin_target_id"] = _as_meta_str(origin_target_id, max_len=256)
    if origin_run_id is not None:
        entry["origin_run_id"] = _as_meta_str(origin_run_id, max_len=128)
    _apply_meta(entry)
    # Mark edits of seed profiles as custom unless source forced
    if body_md is not None and entry.get("source") == "seed" and source is None:
        entry["source"] = "custom"
    profiles[idx] = _profile_public_fields(entry)
    coll["profiles"] = profiles
    _write_collection(coll, bodies=bodies if bodies else None)
    return get_profile(pid)


def delete_profile(profile_id: str) -> dict[str, Any]:
    pid = _validate_id(profile_id)
    coll = ensure_collection()
    profiles = [p for p in coll["profiles"] if p["id"] != pid]
    if len(profiles) == len(coll["profiles"]):
        raise HuntProfileError(f"unknown hunt profile: {pid}")
    if not profiles:
        raise HuntProfileError("cannot delete the last hunt profile")
    coll["profiles"] = profiles
    _write_collection(coll)
    body = _body_path(pid)
    if body.is_file():
        try:
            body.unlink()
        except OSError:
            pass
    return {"ok": True, "deleted": pid, "remaining": len(profiles)}


def export_collection() -> dict[str, Any]:
    coll = ensure_collection()
    profiles_out: list[dict[str, Any]] = []
    for p in coll["profiles"]:
        try:
            body = get_body(p["id"])
        except HuntProfileError:
            body = ""
        row = _profile_public_fields(p)
        row["body_md"] = body
        # export uses body_md not body_file
        row.pop("body_file", None)
        profiles_out.append(row)
    return {
        "format": COLLECTION_FORMAT,
        "updated_at": coll.get("updated_at") or utc_now_iso(),
        "seeded_from": coll.get("seeded_from"),
        "profiles": profiles_out,
    }


def import_collection(
    data: dict[str, Any] | list,
    *,
    mode: str = "merge",
) -> dict[str, Any]:
    mode_n = str(mode or "merge").lower().strip()
    if mode_n not in ("merge", "replace"):
        raise HuntProfileError("mode must be 'merge' or 'replace'")

    if isinstance(data, list):
        raw_profiles = data
        fmt = COLLECTION_FORMAT
    elif isinstance(data, dict):
        fmt = data.get("format") or COLLECTION_FORMAT
        if fmt != COLLECTION_FORMAT:
            raise HuntProfileError(f"unsupported collection format: {fmt}")
        raw_profiles = data.get("profiles")
        if raw_profiles is None:
            raise HuntProfileError("import data missing 'profiles'")
    else:
        raise HuntProfileError("import data must be an object or list")

    if not isinstance(raw_profiles, list) or not raw_profiles:
        raise HuntProfileError("import profiles must be a non-empty list")

    incoming: list[dict[str, Any]] = []
    bodies: dict[str, str] = {}
    for p in raw_profiles:
        if not isinstance(p, dict):
            raise HuntProfileError("each profile must be an object")
        pid = _validate_id(str(p.get("id") or ""))
        body = p.get("body_md")
        if body is None or not str(body).strip():
            raise HuntProfileError(f"profile {pid}: body_md required")
        body = _check_body(str(body))
        bodies[pid] = body
        entry = dict(p)
        entry["id"] = pid
        entry["title"] = str(p.get("title") or _title_from_body(body, pid)).strip()[:120]
        if not str(entry.get("description") or "").strip():
            entry["description"] = _description_from_body(body)
        entry["active"] = bool(p.get("active")) if "active" in p else False
        entry["body_file"] = f"bodies/{pid}.md"
        entry["source"] = str(p.get("source") or "import")[:32]
        # Explicit empty meta on import should stick (keys present)
        incoming.append(_profile_public_fields(entry))

    if mode_n == "replace":
        coll = _empty_collection()
        coll["profiles"] = incoming
        # On replace, wipe bodies dir files that are orphaned after write
        root = collection_root()
        written = _write_collection(coll, bodies=bodies, root=root)
        # Remove orphan body files
        bdir = _bodies_dir(root)
        keep = {f"{p['id']}.md" for p in written["profiles"]}
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
            "count": len(written["profiles"]),
            "profiles": [p["id"] for p in written["profiles"]],
        }

    # merge
    coll = ensure_collection()
    by_id = {p["id"]: dict(p) for p in coll["profiles"]}
    for p in incoming:
        by_id[p["id"]] = p
    # Preserve order: existing first, then new ids in import order
    order: list[str] = []
    for p in coll["profiles"]:
        if p["id"] in by_id and p["id"] not in order:
            order.append(p["id"])
    for p in incoming:
        if p["id"] not in order:
            order.append(p["id"])
    coll["profiles"] = [by_id[i] for i in order]
    written = _write_collection(coll, bodies=bodies)
    return {
        "ok": True,
        "mode": "merge",
        "count": len(written["profiles"]),
        "profiles": [p["id"] for p in written["profiles"]],
    }


def reseed_from_package(*, replace: bool = True) -> dict[str, Any]:
    """Replace collection with package seed library (destructive)."""
    if not replace:
        raise HuntProfileError("reseed currently only supports replace=True")
    seeded = _seed_profiles_from_package()
    bodies = {p["id"]: p.pop("_body") for p in seeded}
    coll = _empty_collection()
    coll["profiles"] = seeded
    root = collection_root()
    written = _write_collection(coll, bodies=bodies, root=root)
    bdir = _bodies_dir(root)
    keep = {f"{p['id']}.md" for p in written["profiles"]}
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
        "count": len(written["profiles"]),
        "profiles": [p["id"] for p in written["profiles"]],
    }


def normalize_class(raw: object) -> str:
    """Map recon class ids onto registered profiles; unknown → wildcard/first."""
    if not raw:
        return _fallback_class()
    cls = str(raw).strip().lower().replace("_", "-").replace(" ", "-")
    cls = CLASS_ALIASES.get(cls, cls)
    try:
        available = set(all_class_ids())
    except HuntProfileError:
        available = set()
    if cls in available:
        return cls
    return _fallback_class(available)


def _fallback_class(available: Optional[set[str]] = None) -> str:
    if available is None:
        try:
            available = set(all_class_ids())
        except HuntProfileError:
            available = set()
    if "wildcard" in available:
        return "wildcard"
    if available:
        # Prefer active
        try:
            for a in active_class_ids():
                if a in available:
                    return a
        except HuntProfileError:
            pass
        return sorted(available)[0]
    return "wildcard"


def _lookup_profile_row(profile_id: str) -> Optional[dict[str, Any]]:
    try:
        pid = _validate_id(profile_id)
    except HuntProfileError:
        return None
    try:
        coll = ensure_collection()
    except HuntProfileError:
        return None
    for p in coll["profiles"]:
        if p["id"] == pid:
            return p
    return None


def angle_ids_for_class(cls: str) -> list[int]:
    """Preferred hunting_angles.md indices for a class (profile meta → seed → [])."""
    want = str(cls or "").strip().lower()
    row = _lookup_profile_row(want)
    if row and row.get("angle_ids"):
        return list(row["angle_ids"])
    seed = SEED_PROFILE_META.get(want) or SEED_PROFILE_META.get(CLASS_ALIASES.get(want, want))
    if seed and seed.get("angle_ids"):
        return list(seed["angle_ids"])
    return []


def specificity_for_class(cls: str) -> int:
    """Cross-class merge rank; 0 means caller should use its own fallback map."""
    want = str(cls or "").strip().lower()
    row = _lookup_profile_row(want)
    if row and int(row.get("specificity") or 0) > 0:
        return int(row["specificity"])
    seed = SEED_PROFILE_META.get(want) or SEED_PROFILE_META.get(CLASS_ALIASES.get(want, want))
    if seed and int(seed.get("specificity") or 0) > 0:
        return int(seed["specificity"])
    return 0


def sink_families_for_class(cls: str) -> list[str]:
    """Sink preindex kinds that justify this class on shared paths."""
    want = str(cls or "").strip().lower()
    row = _lookup_profile_row(want)
    if row is not None and "sink_families" in row:
        # Explicit empty list means "no family filter / allow"
        return [str(x).lower() for x in (row.get("sink_families") or [])]
    seed = SEED_PROFILE_META.get(want) or SEED_PROFILE_META.get(CLASS_ALIASES.get(want, want))
    if seed and seed.get("sink_families"):
        return [str(x).lower() for x in seed["sink_families"]]
    return []


def class_sink_families_map() -> dict[str, set[str]]:
    """Merge static-style map from all registered profiles (non-empty sink_families only)."""
    out: dict[str, set[str]] = {}
    try:
        profiles = list_profiles(include_body=False)
    except HuntProfileError:
        profiles = []
    for p in profiles:
        fam = [str(x).lower() for x in (p.get("sink_families") or []) if x]
        if fam:
            out[p["id"]] = set(fam)
    if not out:
        # Seed fallback when collection unavailable
        for pid, meta in SEED_PROFILE_META.items():
            fam = meta.get("sink_families") or []
            if fam:
                out[pid] = {str(x).lower() for x in fam}
    return out
