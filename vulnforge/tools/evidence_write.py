"""Write evidence packs under runs/.../evidence/<id>/ only."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vulnforge.util import normalize_relpath

# Single path segment only â€” no separators, no traversal.
_SAFE_EVIDENCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

MIN_EVIDENCE_FILE_BYTES = 20


class InvalidEvidenceId(ValueError):
    """evidence_id failed sanitization."""


def sanitize_evidence_id(evidence_id: str | None, *, default: str | None = None) -> str:
    """
    Return a single safe path segment for use under evidence_root.

    Rejects empty, '..', absolute paths, path separators, and unsafe characters.
    """
    raw = evidence_id if evidence_id is not None and str(evidence_id).strip() != "" else default
    if raw is None or str(raw).strip() == "":
        raise InvalidEvidenceId("missing evidence_id")
    eid = str(raw).strip()
    if "\0" in eid:
        raise InvalidEvidenceId("evidence_id contains null byte")
    # Path separators (posix/windows) and absolute / drive forms
    if "/" in eid or "\\" in eid:
        raise InvalidEvidenceId("evidence_id must not contain path separators")
    if ":" in eid:
        raise InvalidEvidenceId("evidence_id must not contain ':'")
    if eid in (".", "..") or ".." in eid:
        raise InvalidEvidenceId("evidence_id must not contain '..'")
    # pathlib absolute (e.g. Windows drive if colon slipped through, or rooted)
    if Path(eid).is_absolute():
        raise InvalidEvidenceId("evidence_id must not be absolute")
    if not _SAFE_EVIDENCE_ID.match(eid):
        raise InvalidEvidenceId("evidence_id has invalid characters")
    return eid


def _under_root(root: Path, candidate: Path) -> bool:
    """True if candidate resolves under root (or is root)."""
    root_r = root.resolve()
    cand_r = candidate.resolve()
    try:
        cand_r.relative_to(root_r)
        return True
    except ValueError:
        return False


def evidence_dir(ctx: dict, evidence_id: str | None = None) -> Path:
    """
    Resolve and create evidence/<id>/ under evidence_root.

    Raises InvalidEvidenceId / ValueError if id escapes root.
    """
    root = Path(ctx["evidence_root"])
    root.mkdir(parents=True, exist_ok=True)
    root_r = root.resolve()
    default = str(ctx.get("task_id") or "default")
    eid = sanitize_evidence_id(evidence_id, default=default)
    d = (root_r / eid).resolve()
    try:
        rel = d.relative_to(root_r)
    except ValueError as e:
        raise InvalidEvidenceId("evidence_id escapes evidence_root") from e
    # Must be a direct child segment of evidence_root
    if d == root_r or len(rel.parts) != 1:
        raise InvalidEvidenceId("evidence_id escapes evidence_root")
    d.mkdir(parents=True, exist_ok=True)
    return d


def assert_evidence_disjoint_from_target(ctx: dict) -> None:
    """Raise ValueError if evidence_root is missing or lands under target_root.

    Agents must never write into the audit target tree. Evidence packs live under
    run_dir/evidence only; mis-set ctx is rejected here rather than writing.
    """
    target_raw = ctx.get("target_root")
    evidence_raw = ctx.get("evidence_root")
    if not evidence_raw:
        raise ValueError("evidence_root required")
    if not target_raw:
        # No target in ctx (unlikely for hunt/develop_poc) — still require a root.
        return
    target = Path(str(target_raw)).resolve()
    evidence = Path(str(evidence_raw)).resolve()
    if evidence == target:
        raise ValueError("evidence_root must not equal target_root")
    try:
        evidence.relative_to(target)
        raise ValueError("evidence_root must not be under target_root")
    except ValueError as e:
        if "must not" in str(e):
            raise
        # evidence is not under target — OK
        pass
    try:
        target.relative_to(evidence)
        raise ValueError("target_root must not be under evidence_root")
    except ValueError as e:
        if "must not" in str(e):
            raise
        pass


def _resolve_pack_id(ctx: dict, evidence_id: str | None = None) -> str:
    """Prefer explicit id, then session / default pack id."""
    if evidence_id is not None and str(evidence_id).strip():
        return sanitize_evidence_id(str(evidence_id).strip())
    default = (
        ctx.get("default_evidence_id")
        or (ctx.get("session") or {}).get("evidence_id")
        or str(ctx.get("task_id") or "default")
    )
    return sanitize_evidence_id(str(default))


def write_evidence(
    ctx: dict,
    relpath: str,
    content: str,
    evidence_id: str | None = None,
    *,
    append: bool = False,
) -> dict[str, Any]:
    try:
        assert_evidence_disjoint_from_target(ctx)
        rel = normalize_relpath(relpath)
        if not rel or rel.startswith("..") or ".." in Path(rel).parts:
            return {"ok": False, "error": "invalid relpath"}
        max_b = int((ctx.get("cfg") or {}).get("tools", {}).get("max_evidence_bytes", 1048576))
        root = Path(ctx["evidence_root"]).resolve()
        d = evidence_dir(ctx, evidence_id)
        if not _under_root(root, d):
            return {"ok": False, "error": "evidence_id escapes evidence_root"}
        dest = (d / rel).resolve()
        if not _under_root(d, dest):
            return {"ok": False, "error": "path escape"}
        dest.parent.mkdir(parents=True, exist_ok=True)

        new_bytes = content.encode("utf-8")
        if append and dest.is_file():
            try:
                existing = dest.read_bytes()
            except OSError as e:
                return {"ok": False, "error": f"cannot read existing for append: {e}"}
            data = existing + new_bytes
            mode = "append"
        else:
            data = new_bytes
            mode = "write"

        if len(data) > max_b:
            return {"ok": False, "error": f"evidence too large ({len(data)} > {max_b})"}
        if len(data) < MIN_EVIDENCE_FILE_BYTES:
            return {
                "ok": False,
                "error": (
                    f"evidence too small ({len(data)} < {MIN_EVIDENCE_FILE_BYTES} bytes); "
                    "write a non-vacuous PoC note"
                ),
            }
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(dest)
        sess = ctx.setdefault("session", {})
        sess.setdefault("evidence_files", []).append(str(Path(d.name) / rel))
        sess["evidence_id"] = d.name
        # Session-scoped auth for submit_candidate (no cross-task free-ride).
        written = sess.setdefault("evidence_ids_written", [])
        if d.name not in written:
            written.append(d.name)
        sess.setdefault("tools_used", []).append("write_evidence")
        return {
            "ok": True,
            "path": rel,
            "evidence_id": d.name,
            "mode": mode,
            "bytes": len(data),
        }
    except InvalidEvidenceId as e:
        return {"ok": False, "error": f"invalid evidence_id: {e}"}
    except ValueError as e:
        # Disjoint-root guard and other validation
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def list_evidence(
    ctx: dict,
    evidence_id: str | None = None,
    *,
    max_entries: int | None = None,
) -> dict[str, Any]:
    """List files under this task's evidence pack (not the audit target)."""
    try:
        assert_evidence_disjoint_from_target(ctx)
        root = Path(ctx["evidence_root"]).resolve()
        eid = _resolve_pack_id(ctx, evidence_id)
        d = (root / eid).resolve()
        if not _under_root(root, d) or d == root or len(d.relative_to(root).parts) != 1:
            return {"ok": False, "error": "invalid evidence_id"}
        if not d.is_dir():
            return {
                "ok": True,
                "evidence_id": eid,
                "files": [],
                "file_count": 0,
                "hint": "Pack does not exist yet — write_evidence creates it.",
            }
        cap = max_entries or int(
            (ctx.get("cfg") or {}).get("tools", {}).get("max_list_entries", 200)
        )
        cap = max(1, int(cap))
        files: list[dict[str, Any]] = []
        truncated = False
        for p in sorted(d.rglob("*")):
            if not p.is_file():
                continue
            if p.name.endswith(".tmp"):
                continue
            try:
                rel = normalize_relpath(str(p.relative_to(d)))
                size = p.stat().st_size
            except (ValueError, OSError):
                continue
            files.append({"path": rel, "bytes": size})
            if len(files) >= cap:
                truncated = True
                break
        sess = ctx.setdefault("session", {})
        sess.setdefault("tools_used", []).append("list_evidence")
        return {
            "ok": True,
            "evidence_id": eid,
            "files": files,
            "file_count": len(files),
            "truncated": truncated,
        }
    except InvalidEvidenceId as e:
        return {"ok": False, "error": f"invalid evidence_id: {e}"}
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def read_evidence(
    ctx: dict,
    relpath: str,
    evidence_id: str | None = None,
    *,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    """Read a file from the evidence pack only (never the audit target)."""
    try:
        assert_evidence_disjoint_from_target(ctx)
        rel = normalize_relpath(relpath)
        if not rel or rel.startswith("..") or ".." in Path(rel).parts:
            return {"ok": False, "error": "invalid relpath"}
        root = Path(ctx["evidence_root"]).resolve()
        eid = _resolve_pack_id(ctx, evidence_id)
        d = (root / eid).resolve()
        if not _under_root(root, d) or d == root or len(d.relative_to(root).parts) != 1:
            return {"ok": False, "error": "invalid evidence_id"}
        if not d.is_dir():
            return {
                "ok": False,
                "error": "pack not found",
                "evidence_id": eid,
                "hint": "write_evidence first, or list_evidence to see packs.",
            }
        dest = (d / rel).resolve()
        if not _under_root(d, dest):
            return {"ok": False, "error": "path escape"}
        if not dest.is_file():
            return {
                "ok": False,
                "error": "file not found",
                "path": rel,
                "evidence_id": eid,
                "hint": "Use list_evidence to see pack files.",
            }
        budget = int(
            max_bytes
            if max_bytes is not None
            else (ctx.get("cfg") or {}).get("tools", {}).get("max_read_bytes", 65536)
        )
        budget = max(1024, min(budget, 262144))
        data = dest.read_bytes()
        truncated = len(data) > budget
        if truncated:
            data = data[:budget]
        text = data.decode("utf-8", errors="replace")
        sess = ctx.setdefault("session", {})
        sess.setdefault("tools_used", []).append("read_evidence")
        return {
            "ok": True,
            "path": rel,
            "evidence_id": eid,
            "content": text,
            "bytes": dest.stat().st_size,
            "truncated": truncated,
        }
    except InvalidEvidenceId as e:
        return {"ok": False, "error": f"invalid evidence_id: {e}"}
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def evidence_exists(
    evidence_root: Path,
    evidence_id: str,
    relpath: str | None = None,
    *,
    min_file_bytes: int = 0,
) -> bool:
    """
    True if a non-escaping evidence pack exists under evidence_root.

    When relpath is set, that file must exist under the pack.
    When min_file_bytes > 0 and relpath is None, require at least one file
    under the pack with size >= min_file_bytes.
    """
    try:
        eid = sanitize_evidence_id(evidence_id)
    except InvalidEvidenceId:
        return False
    root = Path(evidence_root).resolve()
    d = (root / eid).resolve()
    if not _under_root(root, d) or d == root:
        return False
    try:
        if len(d.relative_to(root).parts) != 1:
            return False
    except ValueError:
        return False
    if not d.is_dir():
        return False
    if relpath:
        rel = normalize_relpath(relpath)
        if not rel or ".." in Path(rel).parts:
            return False
        p = (d / rel).resolve()
        if not _under_root(d, p):
            return False
        if not p.is_file():
            return False
        if min_file_bytes > 0 and p.stat().st_size < min_file_bytes:
            return False
        return True
    # Pack-level: any file meeting min size (default: any entry if min_file_bytes==0)
    if min_file_bytes <= 0:
        return any(d.iterdir())
    for p in d.rglob("*"):
        if p.is_file():
            try:
                if p.stat().st_size >= min_file_bytes:
                    return True
            except OSError:
                continue
    return False
