"""Filesystem JSON library of BenchmarkDef heads + immutable versions.

Durable store under ``<project>/benchmarks/library/`` (not ``project/``).
Seeded once from ``fixtures/ground_truth/*.json`` as hunt benches.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from copy import deepcopy
from pathlib import Path
from typing import Any, Optional

from vulnforge.eval.recall import GROUND_TRUTH_ROOT, load_ground_truth
from vulnforge.paths import PROJECT_ROOT
from vulnforge.util import utc_now_iso

COLLECTION_FORMAT = "vulnforge.benchmark_library/v1"
DEFAULT_LIBRARY_ROOT = PROJECT_ROOT / "benchmarks" / "library"
BENCH_TYPES = frozenset({"recon", "hunt", "finding_report", "poc_dev"})
# Underscore allowed so GT stems (toy_sqli, mono_synth) are valid ids.
DEF_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
MAX_NAME = 200
MAX_REF = 512
MAX_NOTES = 2000
MAX_TAG_LEN = 64
MAX_TAGS = 32
MAX_OVERLAY_BYTES = 32 * 1024

_root_override: Optional[Path] = None


class BenchmarkLibraryError(ValueError):
    """Invalid benchmark library operation."""


def set_library_root(root: Path | str | None) -> None:
    """Override library root (tests). Pass None to clear."""
    global _root_override
    if root is None:
        _root_override = None
    else:
        _root_override = Path(root).resolve()


def reset_library_root_override() -> None:
    set_library_root(None)


def library_root() -> Path:
    if _root_override is not None:
        return _root_override
    env = (os.environ.get("VULNFORGE_BENCHMARKS_LIBRARY_ROOT") or "").strip()
    if env:
        return Path(env).resolve()
    return DEFAULT_LIBRARY_ROOT


def _collection_path(root: Optional[Path] = None) -> Path:
    return (root or library_root()) / "collection.json"


def _versions_dir(root: Optional[Path] = None) -> Path:
    return (root or library_root()) / "versions"


def _validate_id(raw: str) -> str:
    bid = str(raw or "").strip().lower()
    if not DEF_ID_RE.match(bid):
        raise BenchmarkLibraryError(
            f"invalid benchmark id {raw!r}: use lowercase slug "
            f"[a-z][a-z0-9_-]{{0,63}}"
        )
    return bid


def _version_path(def_id: str, version: int, root: Optional[Path] = None) -> Path:
    root = root or library_root()
    bid = _validate_id(def_id)
    if int(version) < 1:
        raise BenchmarkLibraryError(f"invalid version: {version}")
    base = _versions_dir(root).resolve()
    path = (base / bid / f"{int(version)}.json").resolve()
    if base not in path.parents:
        raise BenchmarkLibraryError(f"path escape for version: {bid}/{version}")
    return path


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2) + "\n"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _empty_collection() -> dict[str, Any]:
    return {
        "format": COLLECTION_FORMAT,
        "updated_at": utc_now_iso(),
        "seeded_from": "fixtures/ground_truth",
        "defs": [],
    }


def _as_str_list(raw: object, *, max_items: int = MAX_TAGS, max_len: int = MAX_TAG_LEN) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]
    elif isinstance(raw, (list, tuple, set)):
        parts = [str(x).strip() for x in raw if str(x).strip()]
    else:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for it in parts[:max_items]:
        s = it[:max_len]
        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def _normalize_types(raw: object) -> list[str]:
    items = _as_str_list(raw, max_items=len(BENCH_TYPES), max_len=32)
    out: list[str] = []
    seen: set[str] = set()
    for t in items:
        key = t.strip().lower().replace(" ", "_")
        if key not in BENCH_TYPES or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _normalize_overlay(raw: object) -> dict[str, Any] | str:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        blob = json.dumps(raw, sort_keys=True, ensure_ascii=False)
        if len(blob.encode("utf-8")) > MAX_OVERLAY_BYTES:
            raise BenchmarkLibraryError("config_overlay exceeds size limit")
        return raw
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return {}
        if len(text.encode("utf-8")) > MAX_OVERLAY_BYTES:
            raise BenchmarkLibraryError("config_overlay exceeds size limit")
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
        try:
            import yaml

            parsed = yaml.safe_load(text)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
        return text
    return {}


def _normalize_oracle(raw: object, *, default_type: str = "hunt") -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {"type": default_type, "findings": []}
    findings = raw.get("findings")
    if not isinstance(findings, list):
        findings = []
    otype = str(raw.get("type") or default_type).strip().lower() or default_type
    if otype not in BENCH_TYPES:
        otype = default_type
    clean = [f for f in findings if isinstance(f, dict)]
    return {"type": otype, "findings": clean}


def oracle_snapshot_hash(oracle: dict[str, Any]) -> str:
    blob = json.dumps(oracle, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _load_oracle_from_ref(oracle_ref: str) -> dict[str, Any]:
    ref = str(oracle_ref or "").strip()
    if not ref:
        return {"type": "hunt", "findings": []}
    candidates = [Path(ref)]
    if not Path(ref).is_absolute():
        candidates.append(PROJECT_ROOT / ref)
    for p in candidates:
        if p.is_file():
            try:
                gt = load_ground_truth(p)
                return _normalize_oracle({"type": "hunt", "findings": gt.get("findings")})
            except (OSError, ValueError, json.JSONDecodeError):
                break
    try:
        gt = load_ground_truth(ref)
        return _normalize_oracle({"type": "hunt", "findings": gt.get("findings")})
    except (OSError, ValueError, FileNotFoundError, json.JSONDecodeError):
        return {"type": "hunt", "findings": []}


def _public_def(entry: dict[str, Any]) -> dict[str, Any]:
    types = _normalize_types(entry.get("types"))
    return {
        "id": str(entry.get("id") or ""),
        "name": str(entry.get("name") or entry.get("id") or "")[:MAX_NAME],
        "types": types,
        "target_ref": str(entry.get("target_ref") or "")[:MAX_REF],
        "oracle_ref": str(entry.get("oracle_ref") or "")[:MAX_REF],
        "config_overlay": _normalize_overlay(entry.get("config_overlay")),
        "tags": _as_str_list(entry.get("tags")),
        "created_at": str(entry.get("created_at") or ""),
        "updated_at": str(entry.get("updated_at") or ""),
        "head_version": int(entry.get("head_version") or 1),
        "source": str(entry.get("source") or "custom")[:32],
    }


def _content_fingerprint(defn: dict[str, Any], oracle: dict[str, Any]) -> str:
    payload = {
        "name": defn.get("name"),
        "types": defn.get("types"),
        "target_ref": defn.get("target_ref"),
        "oracle_ref": defn.get("oracle_ref"),
        "config_overlay": defn.get("config_overlay"),
        "tags": defn.get("tags"),
        "oracle_hash": oracle_snapshot_hash(oracle),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _read_collection_raw(root: Optional[Path] = None) -> Optional[dict[str, Any]]:
    path = _collection_path(root)
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise BenchmarkLibraryError(f"corrupt collection.json: {e}") from e
    if not isinstance(raw, dict):
        raise BenchmarkLibraryError("collection.json must be an object")
    return raw


def _normalize_collection(raw: dict[str, Any]) -> dict[str, Any]:
    out = _empty_collection()
    fmt = str(raw.get("format") or COLLECTION_FORMAT)
    if fmt != COLLECTION_FORMAT and fmt.startswith("vulnforge.benchmark_library/"):
        raise BenchmarkLibraryError(f"unsupported collection format: {fmt}")
    out["format"] = COLLECTION_FORMAT
    out["updated_at"] = str(raw.get("updated_at") or utc_now_iso())
    out["seeded_from"] = str(raw.get("seeded_from") or "fixtures/ground_truth")
    defs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw.get("defs") or []:
        if not isinstance(item, dict):
            continue
        try:
            bid = _validate_id(str(item.get("id") or ""))
        except BenchmarkLibraryError:
            continue
        if bid in seen:
            continue
        seen.add(bid)
        entry = dict(item)
        entry["id"] = bid
        defs.append(_public_def(entry))
    out["defs"] = defs
    return out


def _write_collection(coll: dict[str, Any], *, root: Optional[Path] = None) -> dict[str, Any]:
    root = root or library_root()
    root.mkdir(parents=True, exist_ok=True)
    _versions_dir(root).mkdir(parents=True, exist_ok=True)
    coll = _normalize_collection(coll)
    coll["updated_at"] = utc_now_iso()
    coll["format"] = COLLECTION_FORMAT
    _atomic_write_json(_collection_path(root), coll)
    return coll


def _write_version(
    snap: dict[str, Any],
    *,
    root: Optional[Path] = None,
) -> dict[str, Any]:
    path = _version_path(str(snap["def_id"]), int(snap["version"]), root)
    _atomic_write_json(path, snap)
    return snap


def _read_version(def_id: str, version: int, root: Optional[Path] = None) -> dict[str, Any]:
    path = _version_path(def_id, version, root)
    if not path.is_file():
        raise BenchmarkLibraryError(f"unknown benchmark version: {def_id}@{version}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise BenchmarkLibraryError(f"corrupt version {def_id}@{version}: {e}") from e
    if not isinstance(raw, dict):
        raise BenchmarkLibraryError(f"version {def_id}@{version} must be an object")
    return deepcopy(raw)


def _build_version_snapshot(
    defn: dict[str, Any],
    oracle: dict[str, Any],
    *,
    version: int,
    notes: str = "",
) -> dict[str, Any]:
    oracle_n = _normalize_oracle(oracle)
    return {
        "def_id": defn["id"],
        "version": int(version),
        "name": defn["name"],
        "types": list(defn["types"]),
        "target_ref": defn["target_ref"],
        "oracle_ref": defn["oracle_ref"],
        "config_overlay": deepcopy(defn["config_overlay"]),
        "tags": list(defn["tags"]),
        "oracle": deepcopy(oracle_n),
        "oracle_hash": oracle_snapshot_hash(oracle_n),
        "notes": str(notes or "")[:MAX_NOTES],
        "created_at": utc_now_iso(),
        "source": defn.get("source") or "custom",
    }


def _gt_seed_candidates() -> list[Path]:
    if not GROUND_TRUTH_ROOT.is_dir():
        return []
    return sorted(p for p in GROUND_TRUTH_ROOT.glob("*.json") if p.is_file())


def _seed_payload_from_gt(path: Path) -> tuple[dict[str, Any], dict[str, Any], str]:
    bid = _validate_id(path.stem)
    gt = load_ground_truth(path)
    try:
        oracle_ref = str(path.resolve().relative_to(PROJECT_ROOT.resolve()))
    except ValueError:
        oracle_ref = str(path)
    target_ref = str(gt.get("target") or "").strip()
    desc = str(gt.get("description") or "").strip()
    name = bid
    if desc and len(desc) <= MAX_NAME:
        name = desc
    oracle = _normalize_oracle({"type": "hunt", "findings": gt.get("findings")})
    notes = f"seed from {oracle_ref}"
    defn = {
        "id": bid,
        "name": name,
        "types": ["hunt"],
        "target_ref": target_ref[:MAX_REF],
        "oracle_ref": oracle_ref[:MAX_REF],
        "config_overlay": {},
        "tags": ["seed"],
        "source": "seed",
    }
    return defn, oracle, notes


def seed_from_ground_truth(
    *,
    missing_only: bool = True,
    root: Optional[Path] = None,
) -> dict[str, Any]:
    """Import each ``fixtures/ground_truth/*.json`` as a hunt BenchmarkDef.

    Default is skip-if-exists (``missing_only=True``): never duplicates or
    overwrites operator edits. Pass ``missing_only=False`` only to fill an
    empty collection on first init.
    """
    root = root or library_root()
    existing = _read_collection_raw(root)
    if existing is None:
        coll = _empty_collection()
    else:
        coll = _normalize_collection(existing)
    by_id = {d["id"]: d for d in coll["defs"]}
    seeded: list[str] = []
    skipped: list[str] = []
    now = utc_now_iso()
    for path in _gt_seed_candidates():
        try:
            bid = _validate_id(path.stem)
        except BenchmarkLibraryError:
            continue
        if bid in by_id and missing_only:
            skipped.append(bid)
            continue
        defn, oracle, notes = _seed_payload_from_gt(path)
        defn["created_at"] = now
        defn["updated_at"] = now
        defn["head_version"] = 1
        public = _public_def(defn)
        by_id[bid] = public
        _write_version(
            _build_version_snapshot(public, oracle, version=1, notes=notes),
            root=root,
        )
        seeded.append(bid)
    # Preserve existing order; append new seed ids alpha.
    order = [d["id"] for d in coll["defs"] if d["id"] in by_id]
    for bid in sorted(by_id):
        if bid not in order:
            order.append(bid)
    coll["defs"] = [by_id[i] for i in order]
    _write_collection(coll, root=root)
    return {
        "ok": True,
        "seeded": seeded,
        "skipped": skipped,
        "count": len(coll["defs"]),
        "ids": [d["id"] for d in coll["defs"]],
    }


def ensure_library(root: Optional[Path] = None) -> dict[str, Any]:
    """Load the library, seeding from ground_truth when collection is missing.

    First init (no ``collection.json``) imports every GT file. Later
    ``ensure_library`` calls only load — use ``seed_from_ground_truth`` /
    ``POST /api/benchmarks/seed`` to add missing seed ids without clobbering.
    """
    root = root or library_root()
    existing = _read_collection_raw(root)
    if existing is not None:
        return _normalize_collection(existing)
    seed_from_ground_truth(missing_only=False, root=root)
    loaded = _read_collection_raw(root)
    if loaded is None:
        return _write_collection(_empty_collection(), root=root)
    return _normalize_collection(loaded)


def list_defs() -> list[dict[str, Any]]:
    coll = ensure_library()
    return [deepcopy(d) for d in coll["defs"]]


def get_def(def_id: str, *, include_oracle: bool = True) -> dict[str, Any]:
    bid = _validate_id(def_id)
    coll = ensure_library()
    for d in coll["defs"]:
        if d["id"] == bid:
            row = deepcopy(d)
            if include_oracle:
                try:
                    snap = _read_version(bid, int(row["head_version"]))
                    row["oracle"] = deepcopy(snap.get("oracle") or {"type": "hunt", "findings": []})
                    row["oracle_hash"] = snap.get("oracle_hash") or oracle_snapshot_hash(row["oracle"])
                except BenchmarkLibraryError:
                    row["oracle"] = {"type": "hunt", "findings": []}
                    row["oracle_hash"] = oracle_snapshot_hash(row["oracle"])
            return row
    raise BenchmarkLibraryError(f"unknown benchmark: {bid}")


def _require_types(types: list[str]) -> list[str]:
    if not types:
        raise BenchmarkLibraryError(
            "types must be a non-empty subset of "
            "{recon, hunt, finding_report, poc_dev}"
        )
    return types


def create_def(
    def_id: str,
    *,
    name: str,
    types: list[str] | None,
    target_ref: str = "",
    oracle_ref: str = "",
    config_overlay: object = None,
    tags: object = None,
    oracle: object = None,
    notes: str = "",
    source: str = "custom",
) -> dict[str, Any]:
    bid = _validate_id(def_id)
    coll = ensure_library()
    if any(d["id"] == bid for d in coll["defs"]):
        raise BenchmarkLibraryError(f"benchmark already exists: {bid}")
    types_n = _require_types(_normalize_types(types))
    name_n = str(name or "").strip()[:MAX_NAME] or bid
    overlay = _normalize_overlay(config_overlay)
    now = utc_now_iso()
    defn = _public_def(
        {
            "id": bid,
            "name": name_n,
            "types": types_n,
            "target_ref": str(target_ref or "")[:MAX_REF],
            "oracle_ref": str(oracle_ref or "")[:MAX_REF],
            "config_overlay": overlay,
            "tags": _as_str_list(tags),
            "created_at": now,
            "updated_at": now,
            "head_version": 1,
            "source": (source or "custom")[:32],
        }
    )
    if oracle is not None:
        oracle_n = _normalize_oracle(oracle)
    else:
        oracle_n = _load_oracle_from_ref(defn["oracle_ref"])
    snap = _build_version_snapshot(defn, oracle_n, version=1, notes=notes)
    _write_version(snap)
    coll["defs"].append(defn)
    _write_collection(coll)
    return get_def(bid)


def update_def(
    def_id: str,
    *,
    name: Optional[str] = None,
    types: object = None,
    target_ref: Optional[str] = None,
    oracle_ref: Optional[str] = None,
    config_overlay: object = None,
    tags: object = None,
    oracle: object = None,
    notes: str = "",
) -> dict[str, Any]:
    bid = _validate_id(def_id)
    current = get_def(bid, include_oracle=True)
    new = deepcopy(current)
    if name is not None:
        new["name"] = str(name).strip()[:MAX_NAME] or bid
    if types is not None:
        new["types"] = _require_types(_normalize_types(types))
    if target_ref is not None:
        new["target_ref"] = str(target_ref)[:MAX_REF]
    if oracle_ref is not None:
        new["oracle_ref"] = str(oracle_ref)[:MAX_REF]
    if config_overlay is not None:
        new["config_overlay"] = _normalize_overlay(config_overlay)
    if tags is not None:
        new["tags"] = _as_str_list(tags)
    old_oracle = _normalize_oracle(current.get("oracle"))
    if oracle is not None:
        new_oracle = _normalize_oracle(oracle)
    elif oracle_ref is not None:
        new_oracle = _load_oracle_from_ref(new["oracle_ref"])
    else:
        new_oracle = old_oracle
    if _content_fingerprint(current, old_oracle) == _content_fingerprint(new, new_oracle):
        return current
    next_ver = int(current["head_version"]) + 1
    new["head_version"] = next_ver
    new["updated_at"] = utc_now_iso()
    # Keep original created_at / source
    public = _public_def(new)
    public["created_at"] = current["created_at"]
    public["source"] = current.get("source") or "custom"
    snap = _build_version_snapshot(public, new_oracle, version=next_ver, notes=notes)
    _write_version(snap)
    coll = ensure_library()
    defs = []
    for d in coll["defs"]:
        if d["id"] == bid:
            defs.append(public)
        else:
            defs.append(d)
    coll["defs"] = defs
    _write_collection(coll)
    return get_def(bid)


def delete_def(def_id: str) -> dict[str, Any]:
    bid = _validate_id(def_id)
    coll = ensure_library()
    defs = [d for d in coll["defs"] if d["id"] != bid]
    if len(defs) == len(coll["defs"]):
        raise BenchmarkLibraryError(f"unknown benchmark: {bid}")
    coll["defs"] = defs
    _write_collection(coll)
    vdir = (_versions_dir() / bid).resolve()
    base = _versions_dir().resolve()
    if base in vdir.parents and vdir.is_dir():
        shutil.rmtree(vdir, ignore_errors=True)
    return {"ok": True, "deleted": bid, "remaining": len(defs)}


def list_versions(def_id: str) -> list[dict[str, Any]]:
    bid = _validate_id(def_id)
    get_def(bid, include_oracle=False)  # 404 if missing
    vdir = (_versions_dir() / bid)
    if not vdir.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for path in sorted(vdir.glob("*.json"), key=lambda p: int(p.stem) if p.stem.isdigit() else 0):
        if not path.stem.isdigit():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(raw, dict):
            continue
        out.append(
            {
                "def_id": bid,
                "version": int(raw.get("version") or path.stem),
                "name": raw.get("name"),
                "types": list(raw.get("types") or []),
                "target_ref": raw.get("target_ref") or "",
                "oracle_ref": raw.get("oracle_ref") or "",
                "oracle_hash": raw.get("oracle_hash") or "",
                "notes": raw.get("notes") or "",
                "created_at": raw.get("created_at") or "",
            }
        )
    out.sort(key=lambda r: int(r["version"]))
    return out


def get_version(def_id: str, version: int) -> dict[str, Any]:
    """Return the frozen snapshot. Never mutates the def head."""
    bid = _validate_id(def_id)
    get_def(bid, include_oracle=False)
    return _read_version(bid, int(version))
