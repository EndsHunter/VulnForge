"""Editable tool draft collection under config/tool_drafts/."""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, Optional

from vulnforge.util import utc_now_iso

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DRAFTS_ROOT = PROJECT_ROOT / "config" / "tool_drafts"

TOOL_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,47}$")
MAX_TEXT_BYTES = 256 * 1024
MAX_IMPL_BYTES = 128 * 1024
MAX_SPEC_BYTES = 64 * 1024

VALID_STATUSES = frozenset(
    {"draft", "generated", "validated", "integrated", "rejected"}
)
VALID_STAGES = frozenset({"recon", "hunt", "develop_poc"})
VALID_RISK = frozenset({"read_only", "evidence_write", "exec"})
VALID_SOURCES = frozenset({"blank", "tool_gap", "extend_existing"})

_root_override: Optional[Path] = None


class ToolDraftError(ValueError):
    """Invalid tool draft or collection operation."""


def set_drafts_root(root: Path | str | None) -> None:
    global _root_override
    if root is None:
        _root_override = None
    else:
        _root_override = Path(root).resolve()


def reset_drafts_root_override() -> None:
    set_drafts_root(None)


def drafts_root() -> Path:
    if _root_override is not None:
        return _root_override
    env = (os.environ.get("VULNFORGE_TOOL_DRAFTS_ROOT") or "").strip()
    if env:
        return Path(env).resolve()
    return DEFAULT_DRAFTS_ROOT


def _index_path(root: Optional[Path] = None) -> Path:
    return (root or drafts_root()) / "index.json"


def _draft_dir(draft_id: str, root: Optional[Path] = None) -> Path:
    root = root or drafts_root()
    base = root.resolve()
    path = (base / draft_id).resolve()
    if base not in path.parents and path != base:
        raise ToolDraftError(f"path escape for draft: {draft_id}")
    if path.name != draft_id:
        raise ToolDraftError(f"path escape for draft: {draft_id}")
    return path


def _validate_id(draft_id: str) -> str:
    did = str(draft_id or "").strip().lower().replace("-", "_")
    if not TOOL_ID_RE.match(did):
        raise ToolDraftError(
            f"invalid tool id {draft_id!r}: use lowercase slug "
            f"[a-z][a-z0-9_]{{0,47}}"
        )
    return did


def _atomic_write_json(path: Path, data: Any) -> None:
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


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _empty_index() -> dict[str, Any]:
    return {
        "format": "vulnforge.tool_drafts/v1",
        "updated_at": utc_now_iso(),
        "drafts": [],
    }


def ensure_index(root: Optional[Path] = None) -> dict[str, Any]:
    root = root or drafts_root()
    root.mkdir(parents=True, exist_ok=True)
    path = _index_path(root)
    if not path.is_file():
        idx = _empty_index()
        _atomic_write_json(path, idx)
        return idx
    try:
        raw = _read_json(path)
    except (OSError, json.JSONDecodeError) as e:
        raise ToolDraftError(f"corrupt tool drafts index: {e}") from e
    if not isinstance(raw, dict):
        raise ToolDraftError("index.json must be an object")
    drafts = raw.get("drafts")
    if not isinstance(drafts, list):
        drafts = []
    raw["drafts"] = drafts
    raw["format"] = "vulnforge.tool_drafts/v1"
    return raw


def _write_index(idx: dict[str, Any], root: Optional[Path] = None) -> None:
    root = root or drafts_root()
    idx = dict(idx)
    idx["updated_at"] = utc_now_iso()
    idx["format"] = "vulnforge.tool_drafts/v1"
    _atomic_write_json(_index_path(root), idx)


def _default_meta(draft_id: str, **kwargs: Any) -> dict[str, Any]:
    stages = kwargs.get("stages") or ["hunt"]
    stages = [s for s in stages if s in VALID_STAGES] or ["hunt"]
    risk = str(kwargs.get("risk_class") or "read_only")
    if risk not in VALID_RISK:
        risk = "read_only"
    source = str(kwargs.get("source") or "blank")
    if source not in VALID_SOURCES:
        source = "blank"
    now = utc_now_iso()
    return {
        "schema_version": 1,
        "id": draft_id,
        "title": str(kwargs.get("title") or draft_id).strip()[:120] or draft_id,
        "description": str(kwargs.get("description") or "").strip()[:500],
        "status": "draft",
        "source": source,
        "source_gap": kwargs.get("source_gap"),
        "stages": stages,
        "risk_class": risk,
        "prefer_extend": kwargs.get("prefer_extend"),
        "module": f"vulnforge.tools.{draft_id}",
        "function_names": [draft_id],
        "profiles": ["code_static"],
        "created_at": now,
        "updated_at": now,
        "validated_at": None,
        "integrated_at": None,
        "integrated_paths": [],
        "model_id": None,
        "operator_notes": str(kwargs.get("operator_notes") or ""),
        "validation_override": None,
    }


def _default_brief(brief: str, **kwargs: Any) -> dict[str, Any]:
    return {
        "brief": str(brief or "").strip(),
        "slots": {
            "problem_statement": str(kwargs.get("problem_statement") or brief or "").strip(),
            "non_goals": str(
                kwargs.get("non_goals")
                or "No host shell; no target writes; no unrestricted network."
            ).strip(),
            "io_contract": str(kwargs.get("io_contract") or "").strip(),
            "safety_constraints": str(
                kwargs.get("safety_constraints")
                or "Use resolve_target_path / soft jail for paths; return {ok: bool}."
            ).strip(),
            "prefer_extend": kwargs.get("prefer_extend"),
        },
        "suggested_id": kwargs.get("suggested_id"),
    }


def _file_map(ddir: Path) -> dict[str, str]:
    """Load text artifacts as strings (missing → empty)."""
    out: dict[str, str] = {}
    for name in (
        "spec.md",
        "impl.py",
        "handler_snippet.py",
        "test_stub.py",
    ):
        p = ddir / name
        out[name] = p.read_text(encoding="utf-8") if p.is_file() else ""
    for name in ("meta.json", "brief.json", "schema.json", "wireup.json", "validation_report.json"):
        p = ddir / name
        if p.is_file():
            try:
                out[name] = p.read_text(encoding="utf-8")
            except OSError:
                out[name] = ""
        else:
            out[name] = ""
    return out


def _index_entry_from_meta(meta: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": meta.get("id"),
        "title": meta.get("title"),
        "status": meta.get("status"),
        "source": meta.get("source"),
        "risk_class": meta.get("risk_class"),
        "stages": meta.get("stages") or [],
        "updated_at": meta.get("updated_at"),
        "source_gap": (meta.get("source_gap") or {}).get("tool_or_capability")
        if isinstance(meta.get("source_gap"), dict)
        else None,
    }


def list_drafts() -> list[dict[str, Any]]:
    idx = ensure_index()
    root = drafts_root()
    out: list[dict[str, Any]] = []
    for row in idx.get("drafts") or []:
        if not isinstance(row, dict):
            continue
        did = str(row.get("id") or "")
        if not did:
            continue
        ddir = root / did
        meta_path = ddir / "meta.json"
        if meta_path.is_file():
            try:
                meta = _read_json(meta_path)
                out.append(_index_entry_from_meta(meta))
                continue
            except (OSError, json.JSONDecodeError):
                pass
        out.append(dict(row))
    return out


def get_draft(draft_id: str, *, include_files: bool = True) -> dict[str, Any]:
    did = _validate_id(draft_id)
    ddir = _draft_dir(did)
    meta_path = ddir / "meta.json"
    if not meta_path.is_file():
        raise ToolDraftError(f"unknown tool draft: {did}")
    try:
        meta = _read_json(meta_path)
    except (OSError, json.JSONDecodeError) as e:
        raise ToolDraftError(f"corrupt draft meta: {e}") from e
    result: dict[str, Any] = {"meta": meta, "id": did}
    brief_path = ddir / "brief.json"
    if brief_path.is_file():
        try:
            result["brief"] = _read_json(brief_path)
        except (OSError, json.JSONDecodeError):
            result["brief"] = {}
    else:
        result["brief"] = {}
    if include_files:
        files = _file_map(ddir)
        result["files"] = files
        # Parsed convenience
        for key, fname in (
            ("schema", "schema.json"),
            ("wireup", "wireup.json"),
            ("validation_report", "validation_report.json"),
        ):
            raw = files.get(fname) or ""
            if raw.strip():
                try:
                    result[key] = json.loads(raw)
                except json.JSONDecodeError:
                    result[key] = None
            else:
                result[key] = None
        result["spec_md"] = files.get("spec.md") or ""
        result["impl_py"] = files.get("impl.py") or ""
        result["handler_snippet"] = files.get("handler_snippet.py") or ""
        result["test_stub"] = files.get("test_stub.py") or ""
    return result


def create_draft(
    *,
    brief: str,
    suggested_id: Optional[str] = None,
    source: str = "blank",
    source_gap: Any = None,
    stages: Optional[list[str]] = None,
    risk_class: str = "read_only",
    prefer_extend: Optional[str] = None,
    title: Optional[str] = None,
    description: Optional[str] = None,
    slots: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    brief_s = str(brief or "").strip()
    if not brief_s and source != "tool_gap":
        raise ToolDraftError("brief is required")
    if not brief_s and isinstance(source_gap, dict):
        brief_s = str(
            source_gap.get("suggestion")
            or source_gap.get("tool_or_capability")
            or "tool gap"
        ).strip()

    raw_id = suggested_id or (
        source_gap.get("tool_or_capability") if isinstance(source_gap, dict) else None
    ) or "new_tool"
    # Normalize capability ids like "unknown:foo" or "wishlist:bar"
    raw_id = str(raw_id).split(":")[-1]
    did = _validate_id(str(raw_id).replace("-", "_"))
    # Allocate free id
    root = drafts_root()
    ensure_index(root)
    base = did
    n = 2
    while (root / did).exists():
        suffix = f"_{n}"
        stem = base[: max(1, 48 - len(suffix))]
        did = f"{stem}{suffix}"
        if not TOOL_ID_RE.match(did):
            did = f"tool_{n}"
        n += 1
        if n > 200:
            raise ToolDraftError("could not allocate free tool draft id")

    ddir = _draft_dir(did, root)
    ddir.mkdir(parents=True, exist_ok=False)

    slot_kwargs = dict(slots or {})
    if prefer_extend:
        slot_kwargs["prefer_extend"] = prefer_extend
    meta = _default_meta(
        did,
        title=title or did,
        description=description or brief_s[:500],
        source=source,
        source_gap=source_gap,
        stages=stages,
        risk_class=risk_class,
        prefer_extend=prefer_extend,
    )
    brief_obj = _default_brief(
        brief_s,
        suggested_id=did,
        prefer_extend=prefer_extend,
        **{k: slot_kwargs[k] for k in (
            "problem_statement",
            "non_goals",
            "io_contract",
            "safety_constraints",
        ) if k in slot_kwargs},
    )
    if slot_kwargs:
        brief_obj["slots"].update({k: v for k, v in slot_kwargs.items() if v is not None})

    _atomic_write_json(ddir / "meta.json", meta)
    _atomic_write_json(ddir / "brief.json", brief_obj)
    _atomic_write_text(ddir / "spec.md", "")
    _atomic_write_text(ddir / "impl.py", "")
    _atomic_write_json(ddir / "schema.json", {"tools": []})
    _atomic_write_json(ddir / "wireup.json", {})
    _atomic_write_text(ddir / "handler_snippet.py", "")
    _atomic_write_text(ddir / "test_stub.py", "")

    idx = ensure_index(root)
    entries = [e for e in (idx.get("drafts") or []) if isinstance(e, dict) and e.get("id") != did]
    entries.append(_index_entry_from_meta(meta))
    idx["drafts"] = entries
    _write_index(idx, root)
    return get_draft(did)


def _sync_index_meta(meta: dict[str, Any]) -> None:
    root = drafts_root()
    idx = ensure_index(root)
    did = meta.get("id")
    entries = []
    found = False
    for e in idx.get("drafts") or []:
        if isinstance(e, dict) and e.get("id") == did:
            entries.append(_index_entry_from_meta(meta))
            found = True
        elif isinstance(e, dict):
            entries.append(e)
    if not found:
        entries.append(_index_entry_from_meta(meta))
    idx["drafts"] = entries
    _write_index(idx, root)


def update_draft(
    draft_id: str,
    *,
    brief: Optional[str] = None,
    slots: Optional[dict[str, Any]] = None,
    meta_updates: Optional[dict[str, Any]] = None,
    spec_md: Optional[str] = None,
    impl_py: Optional[str] = None,
    schema: Optional[dict[str, Any]] = None,
    wireup: Optional[dict[str, Any]] = None,
    handler_snippet: Optional[str] = None,
    test_stub: Optional[str] = None,
    status: Optional[str] = None,
) -> dict[str, Any]:
    did = _validate_id(draft_id)
    ddir = _draft_dir(did)
    meta_path = ddir / "meta.json"
    if not meta_path.is_file():
        raise ToolDraftError(f"unknown tool draft: {did}")
    meta = _read_json(meta_path)

    if meta_updates:
        for k, v in meta_updates.items():
            if k in ("id", "created_at"):
                continue
            if k == "stages" and isinstance(v, list):
                meta["stages"] = [s for s in v if s in VALID_STAGES] or meta.get("stages")
            elif k == "risk_class" and str(v) in VALID_RISK:
                meta["risk_class"] = str(v)
            elif k in meta or k in (
                "title",
                "description",
                "prefer_extend",
                "operator_notes",
                "model_id",
                "source_gap",
            ):
                meta[k] = v

    if status is not None:
        st = str(status)
        if st not in VALID_STATUSES:
            raise ToolDraftError(f"invalid status: {status}")
        meta["status"] = st

    content_touch = any(
        x is not None
        for x in (spec_md, impl_py, schema, wireup, handler_snippet, test_stub)
    )
    # Content edits invalidate validation.
    if content_touch and meta.get("status") in ("validated", "generated"):
        if meta.get("status") == "validated":
            meta["status"] = "generated"
            meta["validated_at"] = None

    if brief is not None or slots is not None:
        brief_path = ddir / "brief.json"
        try:
            brief_obj = _read_json(brief_path) if brief_path.is_file() else _default_brief("")
        except (OSError, json.JSONDecodeError):
            brief_obj = _default_brief("")
        if brief is not None:
            brief_obj["brief"] = str(brief).strip()
        if slots:
            brief_obj.setdefault("slots", {}).update(slots)
        _atomic_write_json(brief_path, brief_obj)

    if spec_md is not None:
        if len(spec_md.encode("utf-8")) > MAX_SPEC_BYTES:
            raise ToolDraftError(f"spec.md exceeds {MAX_SPEC_BYTES} bytes")
        _atomic_write_text(ddir / "spec.md", spec_md)
    if impl_py is not None:
        if len(impl_py.encode("utf-8")) > MAX_IMPL_BYTES:
            raise ToolDraftError(f"impl.py exceeds {MAX_IMPL_BYTES} bytes")
        _atomic_write_text(ddir / "impl.py", impl_py)
    if schema is not None:
        _atomic_write_json(ddir / "schema.json", schema)
    if wireup is not None:
        _atomic_write_json(ddir / "wireup.json", wireup)
    if handler_snippet is not None:
        _atomic_write_text(ddir / "handler_snippet.py", handler_snippet)
    if test_stub is not None:
        _atomic_write_text(ddir / "test_stub.py", test_stub)

    meta["updated_at"] = utc_now_iso()
    _atomic_write_json(meta_path, meta)
    _sync_index_meta(meta)
    return get_draft(did)


def write_validation_report(draft_id: str, report: dict[str, Any]) -> None:
    did = _validate_id(draft_id)
    ddir = _draft_dir(did)
    _atomic_write_json(ddir / "validation_report.json", report)
    meta_path = ddir / "meta.json"
    if meta_path.is_file():
        meta = _read_json(meta_path)
        if report.get("ok"):
            meta["status"] = "validated"
            meta["validated_at"] = utc_now_iso()
        elif meta.get("status") not in ("integrated", "rejected"):
            # Keep generated/draft; clear validated
            if meta.get("status") == "validated":
                meta["status"] = "generated"
            meta["validated_at"] = None
        meta["updated_at"] = utc_now_iso()
        _atomic_write_json(meta_path, meta)
        _sync_index_meta(meta)


def mark_generated(draft_id: str, *, model_id: Optional[str] = None) -> None:
    did = _validate_id(draft_id)
    ddir = _draft_dir(did)
    meta = _read_json(ddir / "meta.json")
    if meta.get("status") not in ("integrated", "rejected"):
        meta["status"] = "generated"
    if model_id:
        meta["model_id"] = model_id
    meta["validated_at"] = None
    meta["updated_at"] = utc_now_iso()
    _atomic_write_json(ddir / "meta.json", meta)
    _sync_index_meta(meta)


def mark_integrated(draft_id: str, paths: list[str]) -> None:
    did = _validate_id(draft_id)
    ddir = _draft_dir(did)
    meta = _read_json(ddir / "meta.json")
    meta["status"] = "integrated"
    meta["integrated_at"] = utc_now_iso()
    meta["integrated_paths"] = list(paths)
    meta["updated_at"] = utc_now_iso()
    _atomic_write_json(ddir / "meta.json", meta)
    _sync_index_meta(meta)


def reject_draft(draft_id: str, reason: str = "") -> dict[str, Any]:
    did = _validate_id(draft_id)
    ddir = _draft_dir(did)
    if not (ddir / "meta.json").is_file():
        raise ToolDraftError(f"unknown tool draft: {did}")
    meta = _read_json(ddir / "meta.json")
    meta["status"] = "rejected"
    if reason:
        meta["operator_notes"] = (
            str(meta.get("operator_notes") or "") + f"\n[rejected] {reason}"
        ).strip()
    meta["updated_at"] = utc_now_iso()
    _atomic_write_json(ddir / "meta.json", meta)
    _sync_index_meta(meta)
    return get_draft(did, include_files=False)


def delete_draft(draft_id: str) -> dict[str, Any]:
    did = _validate_id(draft_id)
    ddir = _draft_dir(did)
    if not ddir.is_dir():
        raise ToolDraftError(f"unknown tool draft: {did}")
    shutil.rmtree(ddir)
    idx = ensure_index()
    idx["drafts"] = [
        e for e in (idx.get("drafts") or []) if not (isinstance(e, dict) and e.get("id") == did)
    ]
    _write_index(idx)
    return {"ok": True, "deleted": did}


def export_draft(draft_id: str) -> dict[str, Any]:
    """Full draft package as JSON for download."""
    d = get_draft(draft_id, include_files=True)
    return {
        "format": "vulnforge.tool_draft/v1",
        "exported_at": utc_now_iso(),
        "meta": d.get("meta"),
        "brief": d.get("brief"),
        "spec_md": d.get("spec_md"),
        "impl_py": d.get("impl_py"),
        "schema": d.get("schema"),
        "wireup": d.get("wireup"),
        "handler_snippet": d.get("handler_snippet"),
        "test_stub": d.get("test_stub"),
        "validation_report": d.get("validation_report"),
    }


def export_all_drafts() -> dict[str, Any]:
    """Export every tool draft as a collection for setup transfer."""
    drafts: list[dict[str, Any]] = []
    for row in list_drafts():
        did = str(row.get("id") or "").strip()
        if not did:
            continue
        try:
            pkg = export_draft(did)
            pkg.pop("format", None)
            pkg.pop("exported_at", None)
            drafts.append(pkg)
        except ToolDraftError:
            continue
    return {
        "format": "vulnforge.tool_drafts/v1",
        "exported_at": utc_now_iso(),
        "drafts": drafts,
        "count": len(drafts),
    }


def import_draft(data: dict[str, Any], *, replace_existing: bool = True) -> dict[str, Any]:
    """Upsert a single draft package (from export_draft)."""
    if not isinstance(data, dict):
        raise ToolDraftError("draft import must be an object")
    meta_in = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    raw_id = meta_in.get("id") or data.get("id")
    if not raw_id and isinstance(data.get("brief"), dict):
        raw_id = data["brief"].get("suggested_id")
    if not raw_id:
        raise ToolDraftError("draft import missing id")
    did = _validate_id(str(raw_id))
    ddir = _draft_dir(did)
    exists = ddir.is_dir() and (ddir / "meta.json").is_file()
    if exists and not replace_existing:
        return {"ok": True, "id": did, "skipped": True}

    if not exists:
        ddir.mkdir(parents=True, exist_ok=True)

    brief_in = data.get("brief") if isinstance(data.get("brief"), dict) else {}
    title = str(meta_in.get("title") or did)
    description = str(meta_in.get("description") or "")[:500]
    source = str(meta_in.get("source") or "import")
    if source not in VALID_SOURCES:
        source = "blank"
    stages = meta_in.get("stages") if isinstance(meta_in.get("stages"), list) else ["hunt"]
    risk = str(meta_in.get("risk_class") or "read_only")
    if risk not in VALID_RISK:
        risk = "read_only"

    if exists:
        meta = _read_json(ddir / "meta.json")
    else:
        meta = _default_meta(
            did,
            title=title,
            description=description,
            source=source,
            source_gap=meta_in.get("source_gap"),
            stages=stages,
            risk_class=risk,
            prefer_extend=meta_in.get("prefer_extend"),
        )
    # Overlay export meta (keep id / created_at)
    for k, v in meta_in.items():
        if k in ("id", "created_at"):
            continue
        if k == "stages" and isinstance(v, list):
            meta["stages"] = [s for s in v if s in VALID_STAGES] or meta.get("stages")
        elif k == "risk_class" and str(v) in VALID_RISK:
            meta["risk_class"] = str(v)
        elif k == "status" and str(v) in VALID_STATUSES:
            meta["status"] = str(v)
        else:
            meta[k] = v
    meta["id"] = did
    meta["updated_at"] = utc_now_iso()
    if "created_at" not in meta or not meta.get("created_at"):
        meta["created_at"] = utc_now_iso()

    if brief_in:
        brief_obj = dict(brief_in)
    else:
        brief_obj = _default_brief(
            str((data.get("brief") if isinstance(data.get("brief"), str) else "") or ""),
            suggested_id=did,
        )
    brief_obj.setdefault("suggested_id", did)

    _atomic_write_json(ddir / "meta.json", meta)
    _atomic_write_json(ddir / "brief.json", brief_obj)

    spec = data.get("spec_md")
    if spec is not None:
        _atomic_write_text(ddir / "spec.md", str(spec))
    elif not (ddir / "spec.md").is_file():
        _atomic_write_text(ddir / "spec.md", "")

    impl = data.get("impl_py")
    if impl is not None:
        _atomic_write_text(ddir / "impl.py", str(impl))
    elif not (ddir / "impl.py").is_file():
        _atomic_write_text(ddir / "impl.py", "")

    if data.get("schema") is not None:
        _atomic_write_json(ddir / "schema.json", data.get("schema") or {"tools": []})
    elif not (ddir / "schema.json").is_file():
        _atomic_write_json(ddir / "schema.json", {"tools": []})

    if data.get("wireup") is not None:
        _atomic_write_json(ddir / "wireup.json", data.get("wireup") or {})
    elif not (ddir / "wireup.json").is_file():
        _atomic_write_json(ddir / "wireup.json", {})

    if data.get("handler_snippet") is not None:
        _atomic_write_text(ddir / "handler_snippet.py", str(data.get("handler_snippet") or ""))
    if data.get("test_stub") is not None:
        _atomic_write_text(ddir / "test_stub.py", str(data.get("test_stub") or ""))
    if data.get("validation_report") is not None:
        _atomic_write_json(ddir / "validation_report.json", data.get("validation_report"))

    _sync_index_meta(meta)
    return {"ok": True, "id": did, "created": not exists}


def import_drafts_collection(
    data: dict[str, Any] | list,
    *,
    mode: str = "merge",
) -> dict[str, Any]:
    """Import a tool_drafts collection or list of draft packages."""
    mode_n = str(mode or "merge").lower().strip()
    if mode_n not in ("merge", "replace"):
        raise ToolDraftError("mode must be 'merge' or 'replace'")

    if isinstance(data, list):
        raw = data
    elif isinstance(data, dict):
        fmt = data.get("format") or ""
        if fmt and fmt not in (
            "vulnforge.tool_drafts/v1",
            "vulnforge.tool_draft/v1",
        ):
            if not str(fmt).startswith("vulnforge.tool_draft"):
                # allow nested section without format
                pass
        if fmt == "vulnforge.tool_draft/v1" or (
            "meta" in data and "drafts" not in data
        ):
            raw = [data]
        else:
            raw = data.get("drafts")
            if raw is None:
                raise ToolDraftError("import data missing 'drafts'")
    else:
        raise ToolDraftError("import data must be an object or list")

    if not isinstance(raw, list):
        raise ToolDraftError("drafts must be a list")

    if mode_n == "replace":
        for row in list(list_drafts()):
            did = str(row.get("id") or "").strip()
            if did:
                try:
                    delete_draft(did)
                except ToolDraftError:
                    pass

    imported: list[str] = []
    errors: list[str] = []
    for item in raw:
        if not isinstance(item, dict):
            errors.append("non-object draft skipped")
            continue
        try:
            r = import_draft(item, replace_existing=True)
            if r.get("id"):
                imported.append(str(r["id"]))
        except ToolDraftError as e:
            errors.append(str(e))

    return {
        "ok": True,
        "mode": mode_n,
        "count": len(imported),
        "drafts": imported,
        "errors": errors[:20],
    }


def save_prompt_override(draft_id: str, name: str, content: str) -> None:
    did = _validate_id(draft_id)
    ddir = _draft_dir(did)
    safe = re.sub(r"[^a-z0-9_.-]", "", name.lower())
    if not safe.endswith(".md"):
        safe = safe + ".md"
    podir = ddir / "prompt_overrides"
    podir.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(podir / safe, content)


def load_prompt_override(draft_id: str, name: str) -> Optional[str]:
    did = _validate_id(draft_id)
    ddir = _draft_dir(did)
    safe = re.sub(r"[^a-z0-9_.-]", "", name.lower())
    if not safe.endswith(".md"):
        safe = safe + ".md"
    path = ddir / "prompt_overrides" / safe
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return None
