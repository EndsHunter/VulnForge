"""Proposed-fix patches: parse, check, and materialize into a scratch tree.

Used by ``develop_fix`` (writes ``evidence/<pack>/fix.patch``) and
``verify_fix`` (re-checks a finding against a patched tree).

Safety contract:

- The audit target is only ever **read**. Nothing here writes under it.
- Patch paths are relative, have no ``..`` / ``.git`` / backslash / NUL, and no
  path component may be a symlink (in the source tree or the scratch copy).
- Hunks apply by exact context. A hunk may sit at a different line than its
  header says, but only if its context matches exactly one place.
- Renames, copies, and binary patches are refused, not silently dropped.
- Git revisions are read with ``ls-tree`` + ``cat-file`` (raw blobs). That
  never runs checkout filters or hooks from a hostile repo config.
"""

from __future__ import annotations

import difflib
import os
import re
import shutil
import stat
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

FIX_PATCH_RELPATH = "fix.patch"
FIX_NOTES_RELPATH = "fix_notes.md"
FIX_CHECK_RELPATH = "fix_check.json"
VERIFY_FIX_RELPATH = "verify_fix.json"

FIX_VERDICTS = ("fixed", "still_vulnerable", "inconclusive")

# Scratch trees for verify_fix live here (never under evidence/, never the target).
SCRATCH_SUBDIR = Path("scratch") / "verify_fix"

DEFAULT_MAX_TREE_BYTES = 1024 * 1024 * 1024  # 1 GiB
DEFAULT_MAX_TREE_FILES = 200_000

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_REFUSED_HEADERS = (
    ("GIT binary patch", "binary_patch_refused"),
    ("Binary files ", "binary_patch_refused"),
    ("rename from ", "rename_refused"),
    ("rename to ", "rename_refused"),
    ("copy from ", "copy_refused"),
    ("copy to ", "copy_refused"),
)
_SAFE_REV_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/~^@{}\-]{0,199}$")


class PatchError(ValueError):
    """Patch is malformed, unsafe, or does not apply."""


@dataclass
class Hunk:
    old_start: int
    old_len: int
    new_start: int
    new_len: int
    # (tag, text, has_newline); tag in {" ", "-", "+"}
    lines: list[tuple[str, str, bool]] = field(default_factory=list)


@dataclass
class FilePatch:
    old_path: str | None  # None = new file (/dev/null)
    new_path: str | None  # None = deleted file (/dev/null)
    hunks: list[Hunk] = field(default_factory=list)

    @property
    def path(self) -> str:
        return str(self.new_path or self.old_path or "")

    @property
    def op(self) -> str:
        if self.old_path is None:
            return "add"
        if self.new_path is None:
            return "delete"
        return "modify"


# --------------------------------------------------------------------------- paths


def safe_relpath(raw: str) -> str:
    """Validate a tree-relative path. Raises PatchError when unsafe."""
    p = str(raw or "")
    if not p or "\x00" in p:
        raise PatchError("empty_or_nul_path")
    if "\\" in p:
        raise PatchError(f"backslash_in_path:{p}")
    if p.startswith("/") or re.match(r"^[A-Za-z]:", p):
        raise PatchError(f"absolute_path:{p}")
    parts = [x for x in p.split("/") if x not in ("", ".")]
    if not parts:
        raise PatchError(f"empty_path:{p}")
    for part in parts:
        if part == "..":
            raise PatchError(f"path_escape:{p}")
        if part.lower() == ".git":
            raise PatchError(f"git_dir_path:{p}")
    return "/".join(parts)


def _header_path(raw: str) -> str | None:
    """Path from a ---/+++ header line body; None for /dev/null."""
    s = raw.rstrip("\r\n")
    # Optional tab-separated timestamp (diff -u style).
    if "\t" in s:
        s = s.split("\t", 1)[0]
    s = s.strip()
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        raise PatchError(f"quoted_path_refused:{s}")
    if s == "/dev/null":
        return None
    return s


def _strip_prefixes(old: str | None, new: str | None) -> tuple[str | None, str | None]:
    """Strip git-style a/ b/ prefixes when both sides use them."""
    old_ok = old is None or old.startswith("a/")
    new_ok = new is None or new.startswith("b/")
    if old_ok and new_ok and not (old is None and new is None):
        old = old[2:] if old is not None else None
        new = new[2:] if new is not None else None
    return old, new


def _walk_no_symlinks(root: Path, rel: str) -> Path:
    """root/rel with no symlink component (lstat each). Raises PatchError."""
    cur = root
    parts = rel.split("/")
    for i, part in enumerate(parts):
        cur = cur / part
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            # Remaining components do not exist yet (new file) — fine.
            return root.joinpath(*parts)
        except OSError as e:
            raise PatchError(f"stat_failed:{rel}:{e}") from e
        if stat.S_ISLNK(st.st_mode):
            raise PatchError(f"symlink_in_path:{'/'.join(parts[: i + 1])}")
    return cur


def read_tree_file(root: Path, rel: str) -> bytes | None:
    """Bytes of a regular file under root (no symlink components), else None."""
    rel = safe_relpath(rel)
    p = _walk_no_symlinks(Path(root), rel)
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(st.st_mode):
        raise PatchError(f"not_regular_file:{rel}")
    fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as fh:
        return fh.read()


# --------------------------------------------------------------------------- parse


def parse_patch(text: str) -> list[FilePatch]:
    """Parse a unified diff. Raises PatchError on anything unsafe or malformed."""
    if not isinstance(text, str) or not text.strip():
        raise PatchError("empty_patch")
    lines = text.splitlines(keepends=True)
    files: list[FilePatch] = []
    cur: FilePatch | None = None
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        for prefix, err in _REFUSED_HEADERS:
            if line.startswith(prefix):
                raise PatchError(err)
        if line.startswith("--- ") and i + 1 < n and lines[i + 1].startswith("+++ "):
            old = _header_path(line[4:])
            new = _header_path(lines[i + 1][4:])
            if old is None and new is None:
                raise PatchError("both_sides_dev_null")
            old, new = _strip_prefixes(old, new)
            old = safe_relpath(old) if old is not None else None
            new = safe_relpath(new) if new is not None else None
            if old is not None and new is not None and old != new:
                raise PatchError(f"rename_refused:{old}->{new}")
            cur = FilePatch(old_path=old, new_path=new)
            files.append(cur)
            i += 2
            continue
        m = _HUNK_RE.match(line)
        if m:
            if cur is None:
                raise PatchError("hunk_before_file_header")
            hunk = Hunk(
                old_start=int(m.group(1)),
                old_len=int(m.group(2)) if m.group(2) is not None else 1,
                new_start=int(m.group(3)),
                new_len=int(m.group(4)) if m.group(4) is not None else 1,
            )
            i += 1
            old_seen = new_seen = 0
            while i < n and (old_seen < hunk.old_len or new_seen < hunk.new_len):
                body = lines[i]
                if body.startswith("\\"):
                    i += 1
                    continue
                tag = body[:1]
                text_part = body[1:]
                if body in ("\n", "\r\n"):
                    # Context line whose leading space was stripped by an editor.
                    tag, text_part = " ", body
                if tag not in (" ", "-", "+"):
                    raise PatchError(f"bad_hunk_line:{body[:60]!r}")
                has_nl = text_part.endswith("\n")
                content = text_part.rstrip("\r\n")
                if i + 1 < n and lines[i + 1].startswith("\\"):
                    has_nl = False
                hunk.lines.append((tag, content, has_nl))
                if tag in (" ", "-"):
                    old_seen += 1
                if tag in (" ", "+"):
                    new_seen += 1
                i += 1
            if old_seen != hunk.old_len or new_seen != hunk.new_len:
                raise PatchError(
                    f"hunk_count_mismatch:{cur.path}@-{hunk.old_start}"
                )
            # Trailing "\ No newline" after the last hunk line.
            while i < n and lines[i].startswith("\\"):
                i += 1
            cur.hunks.append(hunk)
            continue
        # Anything else (git "diff --git", "index", mode lines, prose) is ignored.
        i += 1
    if not files:
        raise PatchError("no_file_headers")
    seen: set[str] = set()
    for fp in files:
        if not fp.hunks:
            raise PatchError(f"no_hunks:{fp.path}")
        if fp.path in seen:
            raise PatchError(f"duplicate_file:{fp.path}")
        seen.add(fp.path)
    return files


# --------------------------------------------------------------------------- apply


def _split_lines(data: bytes) -> tuple[list[str], str, bool]:
    text = data.decode("utf-8")
    nl = "\r\n" if "\r\n" in text else "\n"
    raw = text.splitlines(keepends=True)
    ends_nl = bool(raw) and raw[-1].endswith(("\n", "\r"))
    return [ln.rstrip("\r\n") for ln in raw], nl, ends_nl


def _find_unique(haystack: list[str], needle: list[str], start: int) -> list[int]:
    if not needle:
        return []
    hits: list[int] = []
    last = len(haystack) - len(needle)
    first = needle[0]
    for idx in range(max(0, start), last + 1):
        if haystack[idx] == first and haystack[idx : idx + len(needle)] == needle:
            hits.append(idx)
            if len(hits) > 1:
                break
    return hits


def apply_file_patch(original: bytes | None, fp: FilePatch) -> tuple[bytes | None, list[int]]:
    """Apply one file's hunks. Returns (new_bytes or None for delete, offsets)."""
    if fp.op == "add":
        if original is not None:
            raise PatchError(f"add_target_exists:{fp.path}")
        lines: list[str] = []
        nl, ends_nl = "\n", True
    else:
        if original is None:
            raise PatchError(f"missing_file:{fp.path}")
        try:
            lines, nl, ends_nl = _split_lines(original)
        except UnicodeDecodeError as e:
            raise PatchError(f"non_utf8_file:{fp.path}") from e
    out: list[str] = []
    cursor = 0
    offsets: list[int] = []
    for h in fp.hunks:
        old = [t for tag, t, _ in h.lines if tag in (" ", "-")]
        new = [t for tag, t, _ in h.lines if tag in (" ", "+")]
        if not old:
            # Pure insertion: header old_start is the line after which to insert.
            pos = h.old_start
            if pos < cursor or pos > len(lines):
                raise PatchError(f"insert_out_of_range:{fp.path}@-{h.old_start}")
        else:
            expected = h.old_start - 1
            if lines[expected : expected + len(old)] == old and expected >= cursor:
                pos = expected
            else:
                hits = _find_unique(lines, old, cursor)
                if not hits:
                    raise PatchError(f"context_mismatch:{fp.path}@-{h.old_start}")
                if len(hits) > 1:
                    raise PatchError(f"ambiguous_context:{fp.path}@-{h.old_start}")
                pos = hits[0]
        offsets.append(pos - (h.old_start - 1 if old else h.old_start))
        out.extend(lines[cursor:pos])
        out.extend(new)
        cursor = pos + len(old)
        # Track the newline state of the very last line written.
        last_new = [x for x in h.lines if x[0] in (" ", "+")]
        if cursor >= len(lines) and last_new:
            ends_nl = last_new[-1][2]
    out.extend(lines[cursor:])
    if fp.op == "delete":
        if out:
            raise PatchError(f"delete_leaves_content:{fp.path}")
        return None, offsets
    if not out:
        return b"", offsets
    text = nl.join(out) + (nl if ends_nl else "")
    return text.encode("utf-8"), offsets


def apply_patch_in_memory(
    root: Path, files: list[FilePatch]
) -> dict[str, tuple[bytes | None, list[int]]]:
    """Read originals from root (read-only) and apply every file patch."""
    out: dict[str, tuple[bytes | None, list[int]]] = {}
    for fp in files:
        # For an add this reads the new path: it must not exist yet, and
        # read_tree_file refuses a symlink component on the way there.
        original = read_tree_file(root, fp.old_path or fp.path)
        out[fp.path] = apply_file_patch(original, fp)
    return out


def check_patch(root: Path, text: str) -> dict[str, Any]:
    """Parse and dry-run a patch against root. Never writes anything."""
    result: dict[str, Any] = {
        "schema": "vulnforge.fix_check.v1",
        "parse_ok": False,
        "applies": False,
        "files": [],
        "errors": [],
    }
    try:
        files = parse_patch(text)
    except PatchError as e:
        result["errors"].append(str(e))
        return result
    result["parse_ok"] = True
    summaries: list[dict[str, Any]] = []
    for fp in files:
        added = sum(1 for h in fp.hunks for t, _, _ in h.lines if t == "+")
        removed = sum(1 for h in fp.hunks for t, _, _ in h.lines if t == "-")
        summaries.append(
            {
                "path": fp.path,
                "op": fp.op,
                "hunks": len(fp.hunks),
                "added": added,
                "removed": removed,
            }
        )
    result["files"] = summaries
    try:
        applied = apply_patch_in_memory(Path(root), files)
    except PatchError as e:
        result["errors"].append(str(e))
        return result
    for s in summaries:
        s["offsets"] = applied.get(s["path"], (None, []))[1]
    result["applies"] = True
    return result


# --------------------------------------------------------------------------- scratch trees


def scratch_root(run_dir: Path) -> Path:
    return Path(run_dir) / SCRATCH_SUBDIR


def new_scratch_dir(run_dir: Path, task_id: Any) -> Path:
    """Create a fresh, task-owned scratch directory under run_dir."""
    base = scratch_root(run_dir)
    base.mkdir(parents=True, exist_ok=True)
    d = base / f"task-{task_id}-{uuid.uuid4().hex[:8]}"
    d.mkdir()
    return d


def remove_scratch_dir(run_dir: Path, path: Path) -> bool:
    """rmtree only a directory that sits inside run_dir/scratch/verify_fix/."""
    try:
        base = scratch_root(run_dir).resolve()
        real = Path(path).resolve()
    except OSError:
        return False
    if real == base or base not in real.parents:
        return False
    if Path(path).is_symlink() or not real.is_dir():
        return False
    shutil.rmtree(real, ignore_errors=True)
    return True


def _copy_tree(
    src: Path,
    dest: Path,
    *,
    max_bytes: int = DEFAULT_MAX_TREE_BYTES,
    max_files: int = DEFAULT_MAX_TREE_FILES,
) -> dict[str, Any]:
    """Copy regular files and dirs only. Symlinks and .git are skipped."""
    src = Path(src).resolve()
    total = 0
    count = 0
    skipped_symlinks = 0
    dest.mkdir(parents=True, exist_ok=True)
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        dp = Path(dirpath)
        rel_dir = dp.relative_to(src)
        keep_dirs = []
        for d in dirnames:
            if d == ".git":
                continue
            if (dp / d).is_symlink():
                skipped_symlinks += 1
                continue
            keep_dirs.append(d)
        dirnames[:] = keep_dirs
        (dest / rel_dir).mkdir(parents=True, exist_ok=True)
        for fn in filenames:
            sp = dp / fn
            try:
                st = os.lstat(sp)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                skipped_symlinks += 1
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            count += 1
            total += st.st_size
            if count > max_files or total > max_bytes:
                raise PatchError(
                    f"tree_too_large:files={count},bytes={total} "
                    "(pass patched_path to an existing patched checkout instead)"
                )
            shutil.copyfile(sp, dest / rel_dir / fn, follow_symlinks=False)
            try:
                os.chmod(dest / rel_dir / fn, stat.S_IMODE(st.st_mode) & 0o755)
            except OSError:
                pass
    return {"files": count, "bytes": total, "skipped_symlinks": skipped_symlinks}


def _write_no_follow(dest_root: Path, rel: str, data: bytes | None) -> None:
    rel = safe_relpath(rel)
    target = _walk_no_symlinks(dest_root, rel)
    real_root = dest_root.resolve()
    if data is None:
        if target.exists():
            os.unlink(target)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    # Re-check after mkdir: no component may be a symlink.
    _walk_no_symlinks(dest_root, rel)
    if real_root not in target.parent.resolve().parents and target.parent.resolve() != real_root:
        raise PatchError(f"write_escapes_tree:{rel}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o644)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def materialize_patched_tree(
    target_root: Path,
    patch_text: str,
    dest: Path,
    *,
    max_bytes: int = DEFAULT_MAX_TREE_BYTES,
) -> dict[str, Any]:
    """Copy target_root to dest (read-only source), then apply the patch in dest."""
    files = parse_patch(patch_text)
    applied = apply_patch_in_memory(Path(target_root), files)
    copy_info = _copy_tree(Path(target_root), Path(dest), max_bytes=max_bytes)
    for rel, (data, _off) in applied.items():
        _write_no_follow(Path(dest), rel, data)
    return {
        "source": "fix_patch",
        "copy": copy_info,
        "patched_files": sorted(applied),
    }


# --------------------------------------------------------------------------- git


def _git_env() -> dict[str, str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if k in ("PATH", "HOME", "LANG", "LC_ALL", "SYSTEMROOT", "TMPDIR")
    }
    env.update(
        {
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
    )
    return env


def _git_base(repo: Path) -> list[str]:
    return [
        "git",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.file.allow=never",
        "-C",
        str(repo),
    ]


def _git(repo: Path, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        _git_base(repo) + list(args),
        capture_output=True,
        timeout=timeout,
        env=_git_env(),
        check=False,
    )


def validate_git_rev(rev: str) -> str:
    r = str(rev or "").strip()
    if not r or r.startswith("-") or not _SAFE_REV_RE.match(r) or ".." in r:
        raise PatchError(f"invalid_git_rev:{rev!r}")
    return r


def resolve_git_commit(repo: Path, rev: str) -> str:
    r = validate_git_rev(rev)
    cp = _git(repo, "rev-parse", "--verify", "--end-of-options", f"{r}^{{commit}}")
    if cp.returncode != 0:
        msg = (cp.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        raise PatchError(f"git_rev_not_found:{r}:{msg[0] if msg else cp.returncode}")
    sha = cp.stdout.decode("ascii", "replace").strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", sha):
        raise PatchError(f"git_rev_parse_unexpected:{sha[:80]}")
    return sha


def git_prefix(repo: Path) -> str:
    """Path of repo (a dir inside a work tree) relative to the work-tree top."""
    cp = _git(repo, "rev-parse", "--show-prefix")
    if cp.returncode != 0:
        return ""
    return cp.stdout.decode("utf-8", "replace").strip().strip("/")


def export_git_tree(
    repo: Path,
    rev: str,
    dest: Path,
    *,
    subdir: str = "",
    max_bytes: int = DEFAULT_MAX_TREE_BYTES,
    max_files: int = DEFAULT_MAX_TREE_FILES,
) -> dict[str, Any]:
    """Write the blobs of ``rev[:subdir]`` into dest. Read-only on repo.

    Uses raw blobs (no smudge/textconv filters, no attributes, no hooks).
    Symlinks and submodules are skipped and counted.
    """
    repo = Path(repo)
    if not repo.is_dir():
        raise PatchError(f"repo_not_dir:{repo}")
    sha = resolve_git_commit(repo, rev)
    sub = safe_relpath(subdir) if subdir else ""
    treeish = f"{sha}:{sub}" if sub else sha
    cp = _git(repo, "ls-tree", "-r", "-z", "--full-tree", treeish, timeout=120)
    if cp.returncode != 0:
        msg = (cp.stderr or b"").decode("utf-8", "replace").strip()
        raise PatchError(f"git_ls_tree_failed:{msg[:200]}")
    entries: list[tuple[str, str, str]] = []
    skipped = 0
    for rec in cp.stdout.split(b"\x00"):
        if not rec:
            continue
        meta, _, path_b = rec.partition(b"\t")
        mode, typ, obj = meta.decode("ascii", "replace").split(" ")
        path = path_b.decode("utf-8", "surrogateescape")
        if typ != "blob" or mode not in ("100644", "100755"):
            skipped += 1
            continue
        try:
            rel = safe_relpath(path)
        except PatchError:
            skipped += 1
            continue
        entries.append((mode, obj, rel))
    if len(entries) > max_files:
        raise PatchError(f"tree_too_large:files={len(entries)}")
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    total = 0
    proc = subprocess.Popen(
        _git_base(repo) + ["cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=_git_env(),
    )
    try:
        assert proc.stdin is not None and proc.stdout is not None
        for mode, obj, rel in entries:
            proc.stdin.write(obj.encode("ascii") + b"\n")
            proc.stdin.flush()
            header = proc.stdout.readline().decode("ascii", "replace").split()
            if len(header) != 3 or header[1] != "blob":
                raise PatchError(f"git_cat_file_failed:{rel}")
            size = int(header[2])
            total += size
            if total > max_bytes:
                raise PatchError(f"tree_too_large:bytes>{max_bytes}")
            data = proc.stdout.read(size)
            proc.stdout.read(1)  # trailing LF
            _write_no_follow(dest, rel, data)
            if mode == "100755":
                try:
                    os.chmod(dest / rel, 0o755)
                except OSError:
                    pass
    finally:
        try:
            if proc.stdin:
                proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    return {
        "source": "git_rev",
        "rev": rev,
        "commit": sha,
        "subdir": sub,
        "files": len(entries),
        "bytes": total,
        "skipped_non_regular": skipped,
    }


# --------------------------------------------------------------------------- cited diffs


def _citation_range(c: dict) -> tuple[int, int] | None:
    try:
        start = int(c.get("start_line") or c.get("line") or 0)
    except (TypeError, ValueError):
        start = 0
    try:
        end = int(c.get("end_line") or start)
    except (TypeError, ValueError):
        end = start
    if start <= 0:
        return None
    return start, max(start, end)


def cited_region_diff(
    original_root: Path,
    patched_root: Path,
    citations: Iterable[dict],
    *,
    pad: int = 2,
    max_diff_chars: int = 4000,
) -> dict[str, Any]:
    """Compare cited files between the original and the patched tree.

    ``region_changed`` is True when a change overlaps a cited line range (in
    original-file line numbers, +/- pad). A change elsewhere in the same file
    sets ``file_changed`` only.
    """
    by_path: dict[str, list[tuple[int, int] | None]] = {}
    for c in citations or []:
        if not isinstance(c, dict):
            continue
        p = str(c.get("path") or "").strip().lstrip("./")
        if not p:
            continue
        try:
            p = safe_relpath(p)
        except PatchError:
            continue
        by_path.setdefault(p, []).append(_citation_range(c))
    files: list[dict[str, Any]] = []
    for path, ranges in by_path.items():
        entry: dict[str, Any] = {"path": path}
        try:
            a = read_tree_file(original_root, path)
            b = read_tree_file(patched_root, path)
        except PatchError as e:
            entry["error"] = str(e)
            files.append(entry)
            continue
        entry["exists_original"] = a is not None
        entry["exists_patched"] = b is not None
        if a is None or b is None:
            entry["file_changed"] = a != b
            entry["region_changed"] = a is not None and b is None
            files.append(entry)
            continue
        entry["file_changed"] = a != b
        if a == b:
            entry["region_changed"] = False
            files.append(entry)
            continue
        al = a.decode("utf-8", "replace").splitlines()
        bl = b.decode("utf-8", "replace").splitlines()
        ops = difflib.SequenceMatcher(None, al, bl, autojunk=False).get_opcodes()
        changed_ranges = [(i1, i2) for tag, i1, i2, _j1, _j2 in ops if tag != "equal"]
        region = False
        known = [r for r in ranges if r is not None]
        if not known:
            # No line numbers: any change in the cited file counts as the region.
            region = bool(changed_ranges)
        for lo, hi in known:
            lo0 = max(0, lo - 1 - pad)
            hi0 = hi + pad  # exclusive, 0-based
            for i1, i2 in changed_ranges:
                if i1 == i2:  # pure insertion at i1
                    if lo0 <= i1 <= hi0:
                        region = True
                elif i1 < hi0 and i2 > lo0:
                    region = True
        entry["region_changed"] = region
        diff = "".join(
            difflib.unified_diff(
                [x + "\n" for x in al],
                [x + "\n" for x in bl],
                fromfile=f"original/{path}",
                tofile=f"patched/{path}",
                n=3,
            )
        )
        if len(diff) > max_diff_chars:
            diff = diff[:max_diff_chars] + "\n…[diff truncated]\n"
        entry["diff"] = diff
        files.append(entry)
    any_changed = any(f.get("file_changed") for f in files)
    any_region = any(f.get("region_changed") for f in files)
    return {
        "files": files,
        "cited_files": len(files),
        "any_file_changed": any_changed,
        "any_region_changed": any_region,
        "cited_code_unchanged": bool(files) and not any_changed,
    }
