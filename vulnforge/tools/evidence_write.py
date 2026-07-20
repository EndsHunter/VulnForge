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


def write_evidence(
    ctx: dict,
    relpath: str,
    content: str,
    evidence_id: str | None = None,
) -> dict[str, Any]:
    try:
        assert_evidence_disjoint_from_target(ctx)
        rel = normalize_relpath(relpath)
        if not rel or rel.startswith("..") or ".." in Path(rel).parts:
            return {"ok": False, "error": "invalid relpath"}
        max_b = int((ctx.get("cfg") or {}).get("tools", {}).get("max_evidence_bytes", 1048576))
        data = content.encode("utf-8")
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
        root = Path(ctx["evidence_root"]).resolve()
        d = evidence_dir(ctx, evidence_id)
        if not _under_root(root, d):
            return {"ok": False, "error": "evidence_id escapes evidence_root"}
        dest = (d / rel).resolve()
        if not _under_root(d, dest):
            return {"ok": False, "error": "path escape"}
        dest.parent.mkdir(parents=True, exist_ok=True)
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
        return {"ok": True, "path": rel, "evidence_id": d.name}
    except InvalidEvidenceId as e:
        return {"ok": False, "error": f"invalid evidence_id: {e}"}
    except ValueError as e:
        # Disjoint-root guard and other validation
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
