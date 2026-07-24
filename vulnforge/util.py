"""
Shared helpers: paths, hashing, ids, events log.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


_SAFE_NAME = re.compile(r"[^a-zA-Z0-9._-]+")

# Common binary extensions (used to reject non-source targets at init)
PE_EXTENSIONS = frozenset({".exe", ".dll"})


def is_pe_file(path: Path) -> bool:
    """True when path exists as a file with a PE extension (.exe/.dll)."""
    try:
        p = Path(path)
        return p.is_file() and p.suffix.lower() in PE_EXTENSIONS
    except OSError:
        return False


def target_tool_root(path: Path) -> Path:
    """Directory agents list/read under. File targets use their parent."""
    p = Path(path)
    return p if p.is_dir() else p.parent


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_relpath(path: str) -> str:
    """Normalize to forward-slash relative path for DB keys."""
    p = path.replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    return p


def target_id_from_path(target: Path) -> str:
    """Stable slug for runs/<target_id>/."""
    resolved = target.resolve()
    name = _SAFE_NAME.sub("-", resolved.name).strip("-._") or "target"
    h = hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()[:8]
    return f"{name}-{h}"


def next_run_id(runs_root: Path, target_id: str) -> str:
    """Allocate next run-NNN directory name under runs_root/target_id/."""
    base = runs_root / target_id
    if not base.is_dir():
        return "run-001"
    existing: list[int] = []
    for p in base.iterdir():
        if p.is_dir() and p.name.startswith("run-"):
            suffix = p.name[4:]
            if suffix.isdigit():
                existing.append(int(suffix))
    n = max(existing, default=0) + 1
    return f"run-{n:03d}"


def hash_file(path: Path) -> str:
    """SHA-256 hex digest of file contents."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def meta_fingerprint(path: Path) -> str:
    """Size+mtime fingerprint used when full hashing is capped on large trees."""
    st = path.stat()
    return f"meta:{st.st_size}:{int(st.st_mtime)}"


def match_manifest_fingerprint(path: Path, expected: str) -> bool:
    """Compare a live file to a value stored in ``target_manifest.json``.

    Manifest entries are either a content SHA-256 hex digest (first N files at
    init) or ``meta:size:mtime`` when the hash budget was exceeded. Always
    re-hashing a meta-fingerprinted path would false-positive as mutation.
    """
    if not expected:
        return False
    if expected.startswith("meta:"):
        try:
            return meta_fingerprint(path) == expected
        except OSError:
            return False
    try:
        return hash_file(path) == expected
    except OSError:
        return False


def _ignored(rel: str, ignore_globs: Iterable[str]) -> bool:
    """Simple glob-ish ignore: ** and * support via pathlib match on rel and parts."""
    from fnmatch import fnmatch

    rel_n = normalize_relpath(rel)
    for g in ignore_globs:
        g_n = g.replace("\\", "/")
        if fnmatch(rel_n, g_n):
            return True
        # also match basename-only patterns
        if fnmatch(Path(rel_n).name, g_n):
            return True
        # **/name patterns: match if any path suffix matches
        if g_n.startswith("**/") and fnmatch(rel_n, g_n[3:]):
            return True
        if g_n.endswith("/**") and (
            rel_n == g_n[:-3] or rel_n.startswith(g_n[:-2])
        ):
            return True
    return False


def build_single_file_manifest(target: Path, *, progress: Any = None) -> dict[str, Any]:
    """Manifest for a single source-file target."""
    target = target.resolve()
    if not target.is_file():
        raise FileNotFoundError(f"target is not a file: {target}")

    kind = "single_file"
    label = "file"

    def _prog(**kw: Any) -> None:
        if callable(progress):
            try:
                progress(kw)
            except Exception:
                pass

    _prog(
        phase="inventory",
        status="running",
        message=f"Hashing {label} {target.name}",
        files_seen=0,
        percent=10,
    )
    digest = hash_file(target)
    name = target.name
    _prog(
        phase="inventory",
        status="running",
        message=f"File inventory done: {name}",
        files_seen=1,
        hashed=1,
        percent=100,
    )
    try:
        size = target.stat().st_size
    except OSError:
        size = None
    out: dict[str, Any] = {
        "target": str(target),
        "kind": kind,
        "generated_at": utc_now_iso(),
        "file_count": 1,
        "files": {name: digest},
        "hashed_files": 1,
        "incomplete": False,
        "max_hash_files": 1,
        "max_list_files": 1,
        "single_file": {
            "name": name,
            "path": str(target),
            "sha256": digest,
            "size": size,
            "suffix": target.suffix.lower(),
        },
    }
    return out


def build_target_manifest(
    target: Path,
    ignore_globs: Iterable[str] | None = None,
    *,
    max_hash_files: int = 2_000,
    max_list_files: int = 12_000,
    progress: Any = None,
) -> dict[str, Any]:
    """Inventory target tree for mutation detection.

    Full SHA-256 of every file is too slow for huge trees (Desktop can be
    100k+ files). Defaults cap listing and hashing so init stays interactive:

    - first ``max_hash_files`` get content hashes
    - further listed files get size+mtime fingerprints
    - walk stops after ``max_list_files`` files (manifest marked incomplete)

    ``progress`` is an optional callable(dict) for status UI (phase, files_seen,
    percent, message). Incomplete manifests are honest for large targets.

    Single files are supported: PE → kind=single_binary; other files → single_file.
    """
    target = target.resolve()
    if target.is_file():
        return build_single_file_manifest(target, progress=progress)
    globs = list(ignore_globs or [])
    files: dict[str, str] = {}
    if not target.is_dir():
        raise FileNotFoundError(f"target is not a directory: {target}")

    def _prog(**kw: Any) -> None:
        if callable(progress):
            try:
                progress(kw)
            except Exception:
                pass

    truncated = False
    hashed = 0
    stack: list[Path] = [target]
    seen_dirs = 0
    max_dirs = max(max_list_files * 4, 20_000)
    last_report = 0
    _prog(
        phase="inventory",
        status="running",
        message=f"Scanning {target}",
        files_seen=0,
        percent=0,
    )
    while stack:
        d = stack.pop()
        seen_dirs += 1
        if seen_dirs > max_dirs:
            truncated = True
            break
        try:
            entries = list(d.iterdir())
        except OSError:
            continue
        subdirs = []
        for path in entries:
            try:
                if path.is_dir():
                    rel_d = normalize_relpath(str(path.relative_to(target)))
                    if not _ignored(rel_d + "/", globs) and not _ignored(
                        rel_d + "/**", globs
                    ):
                        name = path.name
                        if name in {
                            ".git",
                            "node_modules",
                            "__pycache__",
                            ".venv",
                            "venv",
                            ".cache",
                            "AppData",
                        }:
                            continue
                        subdirs.append(path)
                elif path.is_file():
                    rel = normalize_relpath(str(path.relative_to(target)))
                    if _ignored(rel, globs):
                        continue
                    if len(files) >= max_list_files:
                        truncated = True
                        stack.clear()
                        break
                    try:
                        if hashed < max_hash_files:
                            files[rel] = hash_file(path)
                            hashed += 1
                        else:
                            files[rel] = meta_fingerprint(path)
                    except OSError:
                        continue
                    n = len(files)
                    if n - last_report >= 100 or n in (1, 10, 50):
                        last_report = n
                        pct = min(99, int(100 * n / max(max_list_files, 1)))
                        _prog(
                            phase="inventory",
                            status="running",
                            message=f"Indexed {n} files (hashed {hashed})",
                            files_seen=n,
                            hashed=hashed,
                            dirs_seen=seen_dirs,
                            percent=pct,
                        )
            except OSError:
                continue
        for sd in reversed(sorted(subdirs, key=lambda p: p.name.lower())):
            stack.append(sd)
        if truncated:
            break

    incomplete = truncated or hashed < len(files)
    _prog(
        phase="inventory",
        status="running",
        message=(
            f"Inventory done: {len(files)} files"
            + (" (capped / incomplete)" if incomplete else "")
        ),
        files_seen=len(files),
        hashed=hashed,
        percent=100 if not incomplete else min(99, int(100 * len(files) / max_list_files)),
    )
    return {
        "target": str(target),
        "generated_at": utc_now_iso(),
        "file_count": len(files),
        "files": files,
        "hashed_files": hashed,
        "incomplete": incomplete,
        "max_hash_files": max_hash_files,
        "max_list_files": max_list_files,
    }


def hash_prompt_bundle(prompts_root: Path) -> str:
    """Pin package seed content via sorted relative file hashes.

    Pass ``paths.effective_prompt_pin_root()`` (``seeds/`` when present) so
    prompt_pin tracks system + hunt_classes + recon_agents seeds.
    """
    prompts_root = prompts_root.resolve()
    h = hashlib.sha256()
    if not prompts_root.is_dir():
        raise FileNotFoundError(prompts_root)
    for path in sorted(prompts_root.rglob("*")):
        if not path.is_file():
            continue
        # Skip README noise so pin tracks prompt bodies primarily.
        if path.name.upper() == "README.MD":
            continue
        rel = normalize_relpath(str(path.relative_to(prompts_root)))
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(hash_file(path).encode("ascii"))
        h.update(b"\0")
    return h.hexdigest()


def append_event(run_dir: Path, event: dict) -> None:
    """Append one JSON line to events.jsonl (best-effort under concurrent agents)."""
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / "events.jsonl"
    payload = {"ts": utc_now_iso(), **event}
    line = json.dumps(payload, ensure_ascii=False) + "\n"
    # Single write of a full line is usually atomic enough for concurrent
    # multi-lease workers; fall back silently on rare OSError.
    try:
        with path.open("a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
    except OSError:
        pass


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))
