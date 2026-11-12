"""Suggest likely owners for a finding from the target's git history (issue #190).

Signals (all read-only, all at ``HEAD``):

* ``git blame`` on the cited line ranges
* recent authors of the cited file (``git log -- <file>``)
* recent authors of the module (codemap module, else the file's directory)
* CODEOWNERS (first of ``.github/CODEOWNERS``, ``CODEOWNERS``, ``docs/CODEOWNERS``)

The target is untrusted code under audit, so every git call goes through
:func:`_run_git`: no shell, scrubbed ``GIT_*`` env, no system/global config,
repo-config keys that can execute programs or write files pinned on the
command line, literal pathspecs, no network, a timeout that kills the whole
process group. Nothing reads the working tree or the index, and nothing is
written to the target, the finding, or ``harness.db``.

Opt-in: ``owners.enabled`` (YAML) or the Settings toggle. Suggestions are
heuristics from history, not an assignment. Without ``--follow`` a rename drops
earlier authors.
"""

from __future__ import annotations

import hashlib
import os
import posixpath
import re
import shutil
import signal
import subprocess
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable

from vulnforge.util import utc_now_iso

SCHEMA = "vulnforge/finding-owners@1"
NOTE = (
    "Suggested from git history at HEAD and CODEOWNERS; not an assignment. "
    "Renames are not followed, so authors before a rename are missing."
)

OWNERS_DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "redact_in_exports": True,
    # Accept a target that is a subdirectory of a larger repo (monorepo).
    "allow_parent_repo": False,
    "max_commits": 50,
    "max_suggestions": 5,
    "timeout_seconds": 10,
    "export_budget_seconds": 60,
}

CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
CODEOWNERS_MAX_BYTES = 1 << 20
CODEOWNERS_MAX_RULES = 5000
# Bounds what one hostile rule can add to a report or issue body.
CODEOWNERS_MAX_OWNERS_PER_RULE = 50
RENDER_MAX_CODEOWNERS = 20
MAX_CITATIONS = 10
MAX_RANGE_LINES = 400
# A cited file bigger than this gets no blame (history signals still apply).
MAX_BLOB_BYTES = 8 << 20
# Hard cap on any one git command's stdout.
MAX_OUTPUT_BYTES = 16 << 20

# Weights for the three history signals (CODEOWNERS is reported separately).
W_BLAME, W_FILE, W_MODULE = 0.6, 0.25, 0.15

# Repo config keys pinned on the command line. ``-c`` beats .git/config per
# key; anything that can run a program, write a file, read outside the repo or
# reach the network is pinned here.
_DEVNULL = os.devnull
_GIT_PINS: tuple[str, ...] = (
    "core.fsmonitor=false",
    "core.useBuiltinFSMonitor=false",
    "core.untrackedCache=false",
    "core.pager=cat",
    f"core.hooksPath={_DEVNULL}",
    f"core.attributesFile={_DEVNULL}",
    "core.sshCommand=",
    "core.gitProxy=",
    "core.askPass=",
    "credential.helper=",
    "diff.external=",
    "log.showSignature=false",
    f"mailmap.file={_DEVNULL}",
    "mailmap.blob=",
    "trace2.eventTarget=0",
    "trace2.normalTarget=0",
    "trace2.perfTarget=0",
    "protocol.allow=never",
    "gc.auto=0",
    "maintenance.auto=false",
)

_SHA_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


class OwnersError(Exception):
    """A git step failed; ``reason`` is the stable code shown to operators."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# --------------------------------------------------------------------------
# config


def owners_config(cfg: dict | None) -> dict[str, Any]:
    """Effective ``owners`` block (defaults < YAML ``owners`` < UI overlay)."""
    raw = (cfg or {}).get("owners") if isinstance(cfg, dict) else None
    out = dict(OWNERS_DEFAULTS)
    if isinstance(raw, dict):
        out.update({k: raw[k] for k in OWNERS_DEFAULTS if k in raw})
    for key in ("enabled", "redact_in_exports", "allow_parent_repo"):
        out[key] = _as_bool(out[key], OWNERS_DEFAULTS[key])
    for key, lo, hi in (
        ("max_commits", 1, 1000),
        ("max_suggestions", 1, 50),
        ("timeout_seconds", 1, 300),
        ("export_budget_seconds", 1, 3600),
    ):
        try:
            out[key] = max(lo, min(hi, int(out[key])))
        except (TypeError, ValueError):
            out[key] = OWNERS_DEFAULTS[key]
    return out


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("1", "true", "yes", "on"):
            return True
        if v in ("0", "false", "no", "off", ""):
            return False
        return default
    if value is None:
        return default
    return bool(value)


def unavailable(reason: str, detail: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {
        "schema": SCHEMA,
        "available": False,
        "reason": reason,
        "computed_at": utc_now_iso(),
        "codeowners": None,
        "suggestions": [],
        "blame": [],
        "note": NOTE,
    }
    if detail:
        out["detail"] = detail[:300]
    return out


# --------------------------------------------------------------------------
# git runner


def _git_env(ceiling: str | None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": _DEVNULL,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_LITERAL_PATHSPECS": "1",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
            "LC_ALL": "C",
        }
    )
    if ceiling:
        env["GIT_CEILING_DIRECTORIES"] = ceiling
    return env


def _run_git(
    cwd: Path,
    args: list[str],
    *,
    timeout: float,
    ceiling: str | None = None,
    max_bytes: int = MAX_OUTPUT_BYTES,
) -> bytes:
    """Run one read-only git command; return stdout or raise :class:`OwnersError`.

    stdout is read in chunks and the process group is killed as soon as it
    passes ``max_bytes``, so a huge blob or line never lands in memory.
    """
    git = shutil.which("git")
    if not git:
        raise OwnersError("git_missing")
    argv = [git, "--no-pager"]
    for pin in _GIT_PINS:
        argv += ["-c", pin]
    argv += ["-C", str(cwd), *args]
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_env(ceiling),
            shell=False,
            start_new_session=True,
        )
    except OSError as exc:
        raise OwnersError("git_missing", str(exc)) from exc

    try:
        if os.name == "posix":
            out, err, code = _drain_select(proc, timeout=timeout, max_bytes=max_bytes)
        else:  # pragma: no cover - no select() on Windows pipes
            out, err, code = _drain_communicate(proc, timeout=timeout, max_bytes=max_bytes)
    except OwnersError as exc:
        raise OwnersError(exc.reason, " ".join(args[:2])) from None
    if code != 0:
        msg = err.decode("utf-8", errors="replace").strip()
        low = msg.lower()
        if "dubious ownership" in low or "safe.directory" in low:
            raise OwnersError("unsafe_repository", msg)
        if "not a git repository" in low:
            raise OwnersError("not_a_git_repo", msg)
        raise OwnersError("git_error", msg)
    return out


def _drain_select(
    proc: subprocess.Popen, *, timeout: float, max_bytes: int
) -> tuple[bytes, bytes, int]:
    """Read both pipes from this thread with non-blocking fds.

    No reader threads: a writer outside the process group that keeps a pipe
    open cannot wedge us, because we never block in read() or close().
    """
    import selectors

    deadline = time.monotonic() + max(0.5, float(timeout))
    bufs = {proc.stdout.fileno(): bytearray(), proc.stderr.fileno(): bytearray()}
    caps = {proc.stdout.fileno(): max_bytes, proc.stderr.fileno(): 65536}
    out_fd = proc.stdout.fileno()
    sel = selectors.DefaultSelector()
    try:
        for fd in bufs:
            os.set_blocking(fd, False)
            sel.register(fd, selectors.EVENT_READ)
        open_fds = set(bufs)
        while open_fds:
            left = deadline - time.monotonic()
            if left <= 0:
                _kill_group(proc)
                raise OwnersError("timeout")
            for key, _ev in sel.select(timeout=min(left, 0.5)):
                fd = key.fd
                try:
                    chunk = os.read(fd, 65536)
                except BlockingIOError:
                    continue
                except OSError:
                    chunk = b""
                if not chunk:
                    sel.unregister(fd)
                    open_fds.discard(fd)
                    continue
                buf = bufs[fd]
                room = caps[fd] - len(buf)
                if len(chunk) > room:
                    if fd == out_fd:
                        _kill_group(proc)
                        raise OwnersError("too_large")
                    chunk = chunk[: max(0, room)]  # stderr: keep draining, drop excess
                buf.extend(chunk)
        left = max(0.1, deadline - time.monotonic())
        try:
            code = proc.wait(timeout=left)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            raise OwnersError("timeout")
        return bytes(bufs[out_fd]), bytes(bufs[proc.stderr.fileno()]), code
    finally:
        sel.close()
        _close_pipes(proc)


def _drain_communicate(
    proc: subprocess.Popen, *, timeout: float, max_bytes: int
) -> tuple[bytes, bytes, int]:  # pragma: no cover - Windows fallback
    try:
        out, err = proc.communicate(timeout=max(0.5, float(timeout)))
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        raise OwnersError("timeout")
    if len(out) > max_bytes:
        raise OwnersError("too_large")
    return out, err[:65536], proc.returncode


def _close_pipes(proc: subprocess.Popen) -> None:
    # Safe: nothing else reads these streams, so close() never waits on a lock.
    for stream in (proc.stdout, proc.stderr):
        try:
            if stream is not None:
                stream.close()
        except OSError:
            pass


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        if hasattr(os, "killpg"):
            os.killpg(proc.pid, signal.SIGKILL)
        else:  # pragma: no cover - Windows
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        proc.wait(timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        pass


# --------------------------------------------------------------------------
# path + identity hygiene


def safe_relpath(path: Any) -> str | None:
    """Normalise a target-relative citation path; ``None`` if unsafe."""
    if not isinstance(path, str):
        return None
    p = path.strip()
    if not p or _CTRL_RE.search(p):
        return None
    p = p.replace("\\", "/")
    if p.startswith("/") or re.match(r"^[A-Za-z]:", p):
        return None
    p = posixpath.normpath(p)
    if p in (".", "") or p.startswith("../") or p == ".." or "/../" in f"/{p}/":
        return None
    return p


def clean_identity(value: Any, *, limit: int = 200) -> str:
    """Strip control characters (field/record separators, newlines) from git text."""
    s = _CTRL_RE.sub(" ", str(value or "")).strip()
    return s[:limit]


def _identity_key(name: str, email: str) -> str:
    return (email or name).strip().lower()


def _is_bot(name: str, email: str) -> bool:
    return "[bot]" in name.lower() or "[bot]" in email.lower()


# --------------------------------------------------------------------------
# CODEOWNERS


class CodeownersPattern:
    """Compiled CODEOWNERS glob. Matching is linear (no regex, no backtracking).

    The matcher tracks the set of path positions reachable after each token,
    so a hostile pattern like ``**a**a**a…`` costs O(tokens × path length).
    """

    __slots__ = ("pattern", "tokens", "only_direct")

    def __init__(self, pattern: str, tokens: list[tuple[str, str]], only_direct: bool) -> None:
        self.pattern = pattern
        self.tokens = tokens
        self.only_direct = only_direct

    def match(self, path: str, deadline: float | None = None) -> bool:
        n = len(path)
        reach = [False] * (n + 1)
        reach[0] = True
        for step, (kind, ch) in enumerate(self.tokens):
            if deadline is not None and step % 16 == 0 and time.monotonic() > deadline:
                raise OwnersError("timeout", "CODEOWNERS match")
            nxt = [False] * (n + 1)
            if kind == "lit":
                for i in range(n):
                    if reach[i] and path[i] == ch:
                        nxt[i + 1] = True
            elif kind == "any1":  # ?
                for i in range(n):
                    if reach[i] and path[i] != "/":
                        nxt[i + 1] = True
            elif kind == "star":  # * — any run without a slash
                carry = False
                for i in range(n + 1):
                    carry = carry or reach[i]
                    if carry:
                        nxt[i] = True
                    if i < n and path[i] == "/":
                        carry = False
            elif kind == "dstar":  # ** — anything
                carry = False
                for i in range(n + 1):
                    carry = carry or reach[i]
                    nxt[i] = carry
            elif kind == "dirs":  # **/ — zero or more leading directories
                carry = False
                for i in range(n + 1):
                    if reach[i]:
                        nxt[i] = True
                        carry = True
                    if carry and i < n and path[i] == "/":
                        nxt[i + 1] = True
            reach = nxt
            if not any(reach):
                return False
        if reach[n]:
            return True
        if self.only_direct:
            return False
        # a matched directory owns everything beneath it
        return any(reach[i] and path[i] == "/" for i in range(n))


def _glob_tokens(body: str) -> list[tuple[str, str]]:
    toks: list[tuple[str, str]] = []
    i = 0
    n = len(body)
    while i < n:
        seg_start = i == 0 or body[i - 1] == "/"
        if seg_start and body.startswith("**/", i):
            while body.startswith("**/", i):
                i += 3
            toks.append(("dirs", ""))
            continue
        if body[i] == "*":
            j = i
            while j < n and body[j] == "*":
                j += 1
            # gitignore: ** is "any depth" only as a whole segment; else it is *
            whole = seg_start and j == n and j - i == 2
            toks.append(("dstar" if whole else "star", ""))
            i = j
            continue
        c = body[i]
        if c == "?":
            toks.append(("any1", ""))
        elif c == "\\" and i + 1 < n:
            i += 1
            toks.append(("lit", body[i]))
        else:
            toks.append(("lit", c))
        i += 1
    # adjacent wildcards add nothing; keep the token list short
    out: list[tuple[str, str]] = []
    for t in toks:
        if out and t[0] in ("star", "dstar") and out[-1][0] in ("star", "dstar"):
            if t[0] == "dstar":
                out[-1] = t
            continue
        out.append(t)
    return out


def compile_codeowners_pattern(pattern: str) -> CodeownersPattern | None:
    """GitHub CODEOWNERS pattern → matcher over a repo-relative path.

    * a ``/`` anywhere but the end anchors at the repo root
    * otherwise the pattern matches at any depth
    * a match on a directory owns everything under it, except a final ``/*``
      (including ``/*`` itself), which owns only direct entries
    * ``!`` negation is not supported by GitHub → ``None``
    """
    pat = pattern.strip()
    if not pat or pat.startswith("!") or len(pat) > 512:
        return None
    anchored = "/" in pat.rstrip("/")
    only_direct = pat.endswith("/*") and not pat.endswith("/**")
    body = pat.strip("/")
    if not body:
        return None
    tokens = _glob_tokens(body)
    if not anchored:
        tokens = [("dirs", "")] + tokens
    return CodeownersPattern(pat, tokens, only_direct)


_CO_TOKEN_RE = re.compile(r"(?:\\.|\S)+")


def parse_codeowners(text: str) -> list[tuple[str, CodeownersPattern, list[str]]]:
    rules: list[tuple[str, CodeownersPattern, list[str]]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # backslash escapes a space or a leading # inside the pattern
        tokens = _CO_TOKEN_RE.findall(line)
        pattern = tokens[0]
        owners: list[str] = []
        for tok in tokens[1:]:
            if tok.startswith("#"):
                break
            if len(owners) < CODEOWNERS_MAX_OWNERS_PER_RULE:
                owners.append(clean_identity(tok, limit=120))
        rx = compile_codeowners_pattern(pattern)
        if rx is None:
            continue
        rules.append((pattern, rx, owners))
        if len(rules) >= CODEOWNERS_MAX_RULES:
            break
    return rules


def match_codeowners(
    rules: list[tuple[str, CodeownersPattern, list[str]]],
    repo_path: str,
    *,
    deadline: float | None = None,
) -> tuple[str, list[str]] | None:
    """Last matching rule wins; a rule with no owners clears ownership.

    Raises ``OwnersError("timeout")`` past ``deadline`` (monotonic seconds).
    """
    hit: tuple[str, list[str]] | None = None
    for idx, (pattern, rx, owners) in enumerate(rules):
        if deadline is not None and idx % 32 == 0 and time.monotonic() > deadline:
            raise OwnersError("timeout", "CODEOWNERS match")
        if rx.match(repo_path, deadline):
            hit = (pattern, owners)
    if hit is None or not hit[1]:
        return None
    return hit


# --------------------------------------------------------------------------
# resolver


class OwnerResolver:
    """Per-request / per-export resolver. Caches git output for one target."""

    def __init__(
        self,
        target_root: str | Path,
        owners_cfg: dict | None = None,
        *,
        deadline: float | None = None,
    ) -> None:
        self.cfg = owners_config({"owners": owners_cfg or {}})
        self.target_raw = str(target_root or "")
        self.deadline = deadline
        self._repo: tuple[Path, str, str] | OwnersError | None = None
        self._cache: dict[tuple, Any] = {}
        self._codeowners: tuple[str, list] | None | OwnersError = None
        self._codeowners_loaded = False

    # -- low level -------------------------------------------------------

    def _timeout(self) -> float:
        t = float(self.cfg["timeout_seconds"])
        if self.deadline is not None:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise OwnersError("budget_exhausted")
            t = min(t, left)
        return t

    def _git(self, args: list[str], **kw: Any) -> bytes:
        toplevel, _head, _prefix = self.repo()
        return _run_git(toplevel, args, timeout=self._timeout(), **kw)

    def repo(self) -> tuple[Path, str, str]:
        """(toplevel, head_sha, target prefix inside the repo) or raise."""
        if isinstance(self._repo, OwnersError):
            raise self._repo
        if self._repo is not None:
            return self._repo
        try:
            self._repo = self._discover()
        except OwnersError as exc:
            self._repo = exc
            raise
        return self._repo

    def _discover(self) -> tuple[Path, str, str]:
        if not self.target_raw:
            raise OwnersError("no_target")
        try:
            root = Path(self.target_raw).resolve(strict=True)
        except (OSError, RuntimeError):
            raise OwnersError("target_missing")
        if not root.is_dir():
            raise OwnersError("target_missing")
        allow_parent = bool(self.cfg["allow_parent_repo"])
        ceiling = None if allow_parent else str(root.parent)
        raw = _run_git(
            root,
            ["rev-parse", "--show-toplevel"],
            timeout=self._timeout(),
            ceiling=ceiling,
        )
        top_s = raw.decode("utf-8", errors="replace").strip()
        if not top_s:
            raise OwnersError("not_a_git_repo")
        try:
            toplevel = Path(top_s).resolve(strict=True)
        except (OSError, RuntimeError):
            raise OwnersError("unsafe_repository", "toplevel missing")
        if toplevel == root:
            prefix = ""
        else:
            try:
                prefix = root.relative_to(toplevel).as_posix()
            except ValueError:
                raise OwnersError("unsafe_repository", "work tree is outside the target")
            if not allow_parent:
                raise OwnersError("unsafe_repository", "work tree is outside the target")
        try:
            head = (
                _run_git(
                    toplevel,
                    ["rev-parse", "--verify", "-q", "HEAD^{commit}"],
                    timeout=self._timeout(),
                )
                .decode("ascii", errors="replace")
                .strip()
            )
        except OwnersError as exc:
            if exc.reason == "git_error":
                raise OwnersError("no_head")
            raise
        if not _SHA_RE.match(head):
            raise OwnersError("no_head")
        return toplevel, head, prefix

    def repo_path(self, rel: str) -> str:
        _top, _head, prefix = self.repo()
        return f"{prefix}/{rel}" if prefix else rel

    # -- signals ---------------------------------------------------------

    def _blob_line_count(self, rpath: str) -> int | None:
        key = ("lines", rpath)
        if key in self._cache:
            return self._cache[key]
        _top, head, _p = self.repo()
        try:
            size = int(self._git(["cat-file", "-s", f"{head}:{rpath}"]).strip() or 0)
        except OwnersError as exc:
            if exc.reason == "git_error":
                self._cache[key] = None
                return None
            raise
        except ValueError:
            self._cache[key] = None
            return None
        if size > MAX_BLOB_BYTES:
            self._cache[key] = -1  # tracked, too big to blame
            return -1
        data = self._git(["cat-file", "blob", f"{head}:{rpath}"], max_bytes=MAX_BLOB_BYTES)
        n = data.count(b"\n") + (0 if not data or data.endswith(b"\n") else 1)
        self._cache[key] = n
        return n

    def blame(self, rpath: str, ranges: list[tuple[int, int]]) -> list[tuple[str, str, int]]:
        """Return ``[(name, email, author_time)]`` per blamed line (mailmapped)."""
        if not ranges:
            return []
        key = ("blame", rpath, tuple(ranges))
        if key in self._cache:
            return self._cache[key]
        _top, head, _p = self.repo()
        # blame.ignoreRevsFile is multi-valued and sorted, so no -c value can
        # reset it; --no-ignore-revs-file drops every configured file.
        args = ["blame", "--line-porcelain", "--no-textconv", "--no-ignore-revs-file", "-w"]
        for a, b in ranges:
            args += ["-L", f"{a},{b}"]
        args += [head, "--", rpath]
        out = self._git(args).decode("utf-8", errors="replace")
        lines: list[tuple[str, str, int]] = []
        name = email = ""
        when = 0
        for ln in out.split("\n"):
            if ln.startswith("\t"):
                lines.append((name, email, when))
                name = email = ""
                when = 0
            elif ln.startswith("author "):
                name = clean_identity(ln[7:])
            elif ln.startswith("author-mail "):
                email = clean_identity(ln[12:].strip().strip("<>"))
            elif ln.startswith("author-time "):
                try:
                    when = int(ln[12:].strip())
                except ValueError:
                    when = 0
        self._cache[key] = lines
        return lines

    def log_authors(self, rpath: str) -> list[tuple[str, str, int]]:
        """Recent non-merge commit authors touching ``rpath`` (file or dir)."""
        key = ("log", rpath)
        if key in self._cache:
            return self._cache[key]
        _top, head, _p = self.repo()
        args = [
            "log",
            f"-n{int(self.cfg['max_commits'])}",
            "--no-merges",
            "--use-mailmap",
            "--no-textconv",
            "--no-ext-diff",
            "--format=%aN%x00%aE%x00%at%x1e",
            head,
            "--",
            rpath or ".",
        ]
        out = self._git(args).decode("utf-8", errors="replace")
        rows = parse_log_records(out)
        self._cache[key] = rows
        return rows

    def codeowners(self) -> tuple[str, list] | None:
        """(file, rules) for the first CODEOWNERS present at HEAD, else None."""
        if self._codeowners_loaded:
            if isinstance(self._codeowners, OwnersError):
                raise self._codeowners
            return self._codeowners  # type: ignore[return-value]
        _top, head, _p = self.repo()
        found: tuple[str, list] | None = None
        for cand in CODEOWNERS_PATHS:
            try:
                size_raw = self._git(["cat-file", "-s", f"{head}:{cand}"])
            except OwnersError as exc:
                if exc.reason == "git_error":
                    continue
                raise
            try:
                size = int(size_raw.strip() or 0)
            except ValueError:
                continue
            if size > CODEOWNERS_MAX_BYTES:
                found = (cand, [])
                break
            text = self._git(["cat-file", "blob", f"{head}:{cand}"]).decode(
                "utf-8", errors="replace"
            )
            found = (cand, parse_codeowners(text))
            break
        self._codeowners = found
        self._codeowners_loaded = True
        return found

    def _codeowners_hit(self, rules: list, rpath: str) -> tuple[str, list[str]] | None:
        key = ("co", rpath)
        if key not in self._cache:
            self._cache[key] = match_codeowners(
                rules, rpath, deadline=time.monotonic() + self._timeout()
            )
        return self._cache[key]

    # -- public ----------------------------------------------------------

    def suggest(self, body: dict, *, module_path: str | None = None) -> dict[str, Any]:
        """Owners dict for one finding body. Never raises."""
        try:
            return self._suggest(body if isinstance(body, dict) else {}, module_path)
        except OwnersError as exc:
            return unavailable(exc.reason, exc.detail)
        except Exception as exc:  # pragma: no cover - defensive
            from vulnforge.errors import note_swallowed

            note_swallowed(exc, context="findings.owners.suggest")
            return unavailable("error", str(exc))

    def _suggest(self, body: dict, module_path: str | None) -> dict[str, Any]:
        cites = finding_citations(body)
        if not cites:
            return unavailable("no_citations")
        _top, head, _prefix = self.repo()
        primary_rel = cites[0][0]

        # 1) blame over cited lines, grouped by file
        by_file: dict[str, list[tuple[int, int]]] = {}
        for rel, start, end in cites:
            by_file.setdefault(rel, [])
            if start is not None:
                by_file[rel].append((start, end if end is not None else start))
        blame_out: list[dict[str, Any]] = []
        blame_counts: dict[str, int] = {}
        idents: dict[str, dict[str, Any]] = {}
        tracked: set[str] = set()

        def ident(name: str, email: str, when: int) -> str | None:
            if _is_bot(name, email):
                return None
            k = _identity_key(name, email)
            if not k:
                return None
            row = idents.setdefault(
                k,
                {
                    "name": name,
                    "email": email,
                    "blame_lines": 0,
                    "file_commits": 0,
                    "module_commits": 0,
                    "last_commit_at": 0,
                },
            )
            if when > row["last_commit_at"]:
                row["last_commit_at"] = when
                if name:
                    row["name"] = name
            return k

        for rel, ranges in by_file.items():
            rpath = self.repo_path(rel)
            nlines = self._blob_line_count(rpath)
            if nlines is None:
                continue
            tracked.add(rel)
            if nlines < 0:
                blame_out.append({"path": rel, "ranges": [], "authors": [], "skipped": "too_large"})
                continue
            clamped: list[tuple[int, int]] = []
            for a, b in ranges:
                a, b = max(1, min(a, b)), max(a, b)
                if a > nlines:
                    continue
                b = min(b, nlines, a + MAX_RANGE_LINES - 1)
                clamped.append((a, b))
            if not clamped:
                continue
            lines = self.blame(rpath, clamped)
            per: dict[str, dict[str, Any]] = {}
            for name, email, when in lines:
                k = ident(name, email, when)
                if k is None:
                    continue
                blame_counts[k] = blame_counts.get(k, 0) + 1
                p = per.setdefault(k, {"name": name, "email": email, "lines": 0})
                p["lines"] += 1
            blame_out.append(
                {
                    "path": rel,
                    "ranges": [list(r) for r in clamped],
                    "authors": sorted(per.values(), key=lambda x: -x["lines"]),
                }
            )
        if primary_rel not in tracked and not tracked:
            return unavailable("untracked", primary_rel)

        # 2) file authors (primary file)
        file_counts: dict[str, int] = {}
        if primary_rel in tracked:
            for name, email, when in self.log_authors(self.repo_path(primary_rel)):
                k = ident(name, email, when)
                if k is not None:
                    file_counts[k] = file_counts.get(k, 0) + 1

        # 3) module authors
        module = safe_relpath(module_path) if module_path else None
        if module is None:
            parent = posixpath.dirname(primary_rel)
            module = parent or None
        module_counts: dict[str, int] = {}
        if module:
            for name, email, when in self.log_authors(self.repo_path(module)):
                k = ident(name, email, when)
                if k is not None:
                    module_counts[k] = module_counts.get(k, 0) + 1

        for k, n in blame_counts.items():
            idents[k]["blame_lines"] = n
        for k, n in file_counts.items():
            idents[k]["file_commits"] = n
        for k, n in module_counts.items():
            idents[k]["module_commits"] = n

        totals = (
            (W_BLAME, sum(blame_counts.values()), "blame_lines"),
            (W_FILE, sum(file_counts.values()), "file_commits"),
            (W_MODULE, sum(module_counts.values()), "module_commits"),
        )
        wsum = sum(w for w, t, _f in totals if t) or 1.0
        ranked = []
        for row in idents.values():
            score = sum(w * row[f] / t for w, t, f in totals if t) / wsum
            if score <= 0:
                continue
            ranked.append((round(score, 4), int(row["last_commit_at"]), row))
        ranked.sort(key=lambda x: (-x[0], -x[1], x[2]["name"]))
        suggestions = []
        for score, ts, row in ranked[: int(self.cfg["max_suggestions"])]:
            out = dict(row)
            out["score"] = score
            out["last_commit_at"] = (
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)) if ts else ""
            )
            suggestions.append(out)

        # 4) CODEOWNERS (declared, not heuristic)
        co_out = None
        co = self.codeowners()
        if co is not None:
            co_file, rules = co
            hit = self._codeowners_hit(rules, self.repo_path(primary_rel))
            if hit is not None:
                co_out = {"file": co_file, "pattern": hit[0], "owners": list(hit[1])}

        return {
            "schema": SCHEMA,
            "available": True,
            "reason": "",
            "computed_at": utc_now_iso(),
            "repo_head": head,
            "path": primary_rel,
            "module": module or "",
            "codeowners": co_out,
            "suggestions": suggestions,
            "blame": blame_out,
            "note": NOTE,
        }


def parse_log_records(out: str) -> list[tuple[str, str, int]]:
    """Parse ``%aN%x00%aE%x00%at%x1e`` records; stray separators cannot spoof rows."""
    rows: list[tuple[str, str, int]] = []
    for rec in out.split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        parts = rec.split("\x00")
        if len(parts) != 3:
            continue
        name, email, at = parts
        try:
            when = int(at.strip())
        except ValueError:
            continue
        rows.append((clean_identity(name), clean_identity(email), when))
    return rows


def finding_citations(body: dict) -> list[tuple[str, int | None, int | None]]:
    """Safe ``(relpath, start, end)`` citations; sink path first when present."""
    out: list[tuple[str, int | None, int | None]] = []
    seen: set[tuple] = set()
    raw: list[Any] = []
    if body.get("sink_path"):
        raw.append({"path": body.get("sink_path"), "start_line": body.get("sink_line")})
    raw.extend(c for c in (body.get("citations") or []) if isinstance(c, dict))
    for c in raw:
        rel = safe_relpath(c.get("path"))
        if rel is None:
            continue
        start = _int_or_none(c.get("start_line"))
        end = _int_or_none(c.get("end_line"))
        if start is not None and start < 1:
            start = None
        if start is None:
            end = None
        key = (rel, start, end)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
        if len(out) >= MAX_CITATIONS:
            break
    return out


def _int_or_none(v: Any) -> int | None:
    if v is None or v == "" or isinstance(v, bool):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------
# module from codemap


def nearest_module(codemap: dict | None, path: str) -> str | None:
    """Longest codemap module path that contains ``path`` (not the root)."""
    if not isinstance(codemap, dict) or not path:
        return None
    best = ""
    for m in codemap.get("modules") or []:
        if not isinstance(m, dict):
            continue
        mp = str(m.get("path") or "").strip().strip("/")
        if not mp or mp == ".":
            continue
        if (path == mp or path.startswith(mp + "/")) and len(mp) > len(best):
            best = mp
    return best or None


# --------------------------------------------------------------------------
# redaction + rendering


def pseudonym(identity: str, salt: str) -> str:
    """Stable per-run pseudonym. Not anonymisation: a known identity can be checked."""
    h = hashlib.sha256(f"{salt}\x00{identity.strip().lower()}".encode("utf-8")).hexdigest()
    return f"owner-{h[:16]}"


def redact_owners(owners: dict | None, salt: str) -> dict | None:
    """Replace every identity (authors, emails, CODEOWNERS tokens) with pseudonyms."""
    if not isinstance(owners, dict):
        return owners
    out = deepcopy(owners)
    out["redacted"] = True
    for row in out.get("suggestions") or []:
        key = _identity_key(str(row.get("name") or ""), str(row.get("email") or ""))
        row["name"] = pseudonym(key, salt)
        row["email"] = ""
    for b in out.get("blame") or []:
        for a in b.get("authors") or []:
            key = _identity_key(str(a.get("name") or ""), str(a.get("email") or ""))
            a["name"] = pseudonym(key, salt)
            a["email"] = ""
    co = out.get("codeowners")
    if isinstance(co, dict):
        co["owners"] = [pseudonym(str(o), salt) for o in co.get("owners") or []]
    return out


def _ident_label(row: dict) -> str:
    name = str(row.get("name") or "")
    email = str(row.get("email") or "")
    if name and email:
        return f"{name} <{email}>"
    return name or email or "?"


def owners_flat(owners: dict | None) -> str:
    """One-line summary for CSV/XLSX cells and Markdown bullets."""
    if not isinstance(owners, dict):
        return ""
    if not owners.get("available"):
        reason = owners.get("reason") or "unavailable"
        return "" if reason == "disabled" else f"(unavailable: {reason})"
    parts: list[str] = []
    co = owners.get("codeowners")
    if isinstance(co, dict) and co.get("owners"):
        parts.append("CODEOWNERS " + " ".join(_capped(co["owners"])))
    for s in owners.get("suggestions") or []:
        bits = []
        if s.get("blame_lines"):
            bits.append(f"blame {s['blame_lines']}")
        if s.get("file_commits"):
            bits.append(f"file {s['file_commits']}")
        if s.get("module_commits"):
            bits.append(f"module {s['module_commits']}")
        parts.append(f"{_ident_label(s)} ({', '.join(bits) or 'history'})")
    return "; ".join(parts) or "(no owners found)"


def _capped(items: list) -> list[str]:
    shown = [str(x) for x in items[:RENDER_MAX_CODEOWNERS]]
    if len(items) > len(shown):
        shown.append(f"(+{len(items) - len(shown)} more)")
    return shown


def owners_markdown(owners: dict | None) -> list[str]:
    """Markdown bullets for issue trackers / reports.

    Every identity is wrapped in backticks so a ``@user`` from CODEOWNERS or an
    author name never becomes a live mention on GitHub.
    """
    if not isinstance(owners, dict) or not owners.get("available"):
        flat = owners_flat(owners)
        return [f"- _{flat}_"] if flat else []
    lines: list[str] = []
    co = owners.get("codeowners")
    if isinstance(co, dict) and co.get("owners"):
        shown = list(co["owners"])[:RENDER_MAX_CODEOWNERS]
        who = " ".join(f"`{_md_code(o)}`" for o in shown)
        if len(co["owners"]) > len(shown):
            who += f" (+{len(co['owners']) - len(shown)} more)"
        lines.append(f"- CODEOWNERS (`{_md_code(co.get('pattern'))}`): {who}")
    for s in owners.get("suggestions") or []:
        bits = []
        if s.get("blame_lines"):
            bits.append(f"blame {s['blame_lines']} lines")
        if s.get("file_commits"):
            bits.append(f"{s['file_commits']} file commits")
        if s.get("module_commits"):
            bits.append(f"{s['module_commits']} module commits")
        lines.append(f"- `{_md_code(_ident_label(s))}` — {', '.join(bits) or 'history'}")
    if not lines:
        lines.append("- _no owners found_")
    return lines


def _md_code(s: Any) -> str:
    return clean_identity(s).replace("`", "'")


def csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection in an untrusted cell."""
    s = "" if value is None else str(value)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


# --------------------------------------------------------------------------
# convenience for routes / exports


def suggest_for_finding(
    target_root: str | Path,
    body: dict,
    owners_cfg: dict | None,
    *,
    codemap: dict | None = None,
    resolver: OwnerResolver | None = None,
) -> dict[str, Any]:
    cfg = owners_config({"owners": owners_cfg or {}})
    if not cfg["enabled"]:
        return unavailable("disabled")
    res = resolver or OwnerResolver(target_root, cfg)
    cites = finding_citations(body if isinstance(body, dict) else {})
    module = nearest_module(codemap, cites[0][0]) if cites else None
    return res.suggest(body, module_path=module)


def attach_owners(
    rows: Iterable[dict[str, Any]],
    target_root: str | Path,
    owners_cfg: dict | None,
    *,
    codemap: dict | None = None,
    redact: bool = True,
    salt: str = "",
    cache: dict | None = None,
) -> None:
    """Set ``_owners`` + ``suggested_owners`` on export rows (budgeted)."""
    cfg = owners_config({"owners": owners_cfg or {}})
    cache = cache if cache is not None else {}
    res: OwnerResolver | None = None
    for r in rows:
        fid = r.get("id")
        if fid in cache:
            owners = cache[fid]
        else:
            if res is None:
                res = OwnerResolver(
                    target_root,
                    cfg,
                    deadline=time.monotonic() + float(cfg["export_budget_seconds"]),
                )
            owners = suggest_for_finding(
                target_root, r.get("_body") or {}, cfg, codemap=codemap, resolver=res
            )
            if redact:
                owners = redact_owners(owners, salt)
            cache[fid] = owners
        r["_owners"] = owners
        r["suggested_owners"] = owners_flat(owners)


__all__ = [
    "CODEOWNERS_PATHS",
    "OWNERS_DEFAULTS",
    "OwnerResolver",
    "OwnersError",
    "SCHEMA",
    "attach_owners",
    "clean_identity",
    "compile_codeowners_pattern",
    "csv_safe",
    "finding_citations",
    "match_codeowners",
    "nearest_module",
    "owners_config",
    "owners_flat",
    "owners_markdown",
    "parse_codeowners",
    "parse_log_records",
    "pseudonym",
    "redact_owners",
    "safe_relpath",
    "suggest_for_finding",
    "unavailable",
]
