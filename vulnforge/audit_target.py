"""Operator audit target: a local path or a public GitHub URL."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol
from urllib.parse import unquote, urlsplit

from vulnforge.file_lock import open_exclusive
from vulnforge.util import PE_EXTENSIONS

Focus = Literal["repo", "tree", "blob"]

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")

READY_REL = Path(".git") / "vulnforge-ready"

_GIT_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_NO_REPLACE_OBJECTS": "1",
}
_GIT_CONFIG = (
    "core.hooksPath=/dev/null",
    "core.sshCommand=",
    "credential.helper=",
    "submodule.recurse=false",
    "protocol.file.allow=never",
    "protocol.allow=never",
    "protocol.https.allow=always",
)


class TargetError(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class LocalSpec:
    """Not a URL. ``raw`` is unstripped so an empty string stays CWD."""

    raw: str


@dataclass(frozen=True)
class GitHubSpec:
    """Public github.com repo. ``rest`` stays unsplit (refs may contain slashes)."""

    owner: str
    repo: str
    rest: str
    focus: Focus

    @property
    def clone_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}.git"


TargetSpec = LocalSpec | GitHubSpec


@dataclass(frozen=True)
class ResolvedTarget:
    path: Path
    spec: TargetSpec
    commit_sha: str | None
    display: str
    subpath: tuple[str, ...] = ()


class GitFetcher(Protocol):
    def resolve_commit(self, spec: GitHubSpec) -> tuple[str, tuple[str, ...]]:
        """Return (40-char lowercase sha, subpath components)."""

    def fetch_commit(self, spec: GitHubSpec, sha: str, dest: Path) -> None:
        """Populate empty ``dest`` with commit ``sha``. No hooks, no submodules."""


def github_cache_root(runs_root: Path) -> Path:
    return Path(runs_root) / ".vf-github"


def parse_target(raw: str) -> TargetSpec:
    """Classify an operator string. No filesystem, git, or network."""
    if raw.startswith("git@"):
        raise TargetError(
            "ssh_url",
            "SSH GitHub URLs are not supported; use https://github.com/owner/repo",
        )
    if "://" in raw:
        return _parse_github(raw)
    return LocalSpec(raw=raw)


def resolve_init_target(
    raw: str,
    *,
    cache_root: Path,
    git: GitFetcher | None = None,
) -> ResolvedTarget:
    """Parse, then return an existing local file or directory."""
    spec = parse_target(raw)
    if isinstance(spec, LocalSpec):
        return _resolve_local(spec)
    fetcher = git if git is not None else _LiveGit()
    return _materialize_github(
        spec,
        cache_root=cache_root,
        git=fetcher,
        display=raw,
    )


def _sha_ok(text: str) -> bool:
    return _SHA_RE.fullmatch(text) is not None


def _require_sha(sha: str) -> str:
    lowered = str(sha or "").strip().lower()
    if not _sha_ok(lowered):
        raise TargetError("bad_sha", "git did not return a commit sha")
    return lowered


def _split_subpath(tail: str) -> tuple[str, ...]:
    if not tail:
        return ()
    parts = tuple(tail.split("/"))
    for part in parts:
        if part in ("", ".", "..") or "\\" in part or "\x00" in part:
            raise TargetError("unsafe_path", "GitHub path must not contain .. or backslashes")
    return parts


def _sha_prefix(rest: str) -> tuple[str, tuple[str, ...]] | None:
    if len(rest) >= 40 and _sha_ok(rest[:40].lower()) and (len(rest) == 40 or rest[40] == "/"):
        tail = rest[41:] if len(rest) > 40 else ""
        return rest[:40].lower(), _split_subpath(tail)
    return None


def _parse_github(url: str) -> GitHubSpec:
    parsed = urlsplit(url.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme != "https":
        raise TargetError("forbidden_scheme", "Only https://github.com URLs are supported")
    if parsed.username is not None or parsed.password is not None:
        raise TargetError("userinfo", "GitHub URLs must not include a username or token")
    host = (parsed.hostname or "").lower()
    if host == "gist.github.com" or parsed.path.lower().startswith("/gist/") or parsed.path.lower() == "/gist":
        raise TargetError("gist", "GitHub gists are not supported")
    if host != "github.com" or parsed.port is not None:
        raise TargetError("forbidden_host", "Only https://github.com URLs are supported")
    if parsed.query:
        raise TargetError("query", "GitHub URL must not include a query string")

    path = unquote(parsed.path or "")
    if "\\" in path or "\x00" in path:
        raise TargetError("unsafe_path", "GitHub path must not contain .. or backslashes")
    path = path.strip().rstrip("/")
    if path.startswith("/"):
        path = path[1:]
    if not path or "//" in path:
        raise TargetError("unknown_github_url", "GitHub URL must be a repo, /tree/, or /blob/ path")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise TargetError("unsafe_path", "GitHub path must not contain .. or backslashes")
    if len(parts) < 2:
        raise TargetError("unknown_github_url", "GitHub URL must be a repo, /tree/, or /blob/ path")

    owner, repo = parts[0], parts[1]
    if repo.lower().endswith(".git"):
        repo = repo[: -len(".git")]
    if not _segment_ok(owner, owner=True) or not _segment_ok(repo, owner=False):
        raise TargetError("unknown_github_url", "GitHub URL must be a repo, /tree/, or /blob/ path")

    if len(parts) == 2:
        return GitHubSpec(owner=owner, repo=repo, rest="", focus="repo")

    kind = parts[2]
    if kind not in ("tree", "blob"):
        raise TargetError("unknown_github_url", "GitHub URL must be a repo, /tree/, or /blob/ path")
    rest_parts = parts[3:]
    if not rest_parts:
        raise TargetError("empty_ref", "GitHub /tree/ or /blob/ URL is missing a ref")
    focus: Focus = "tree" if kind == "tree" else "blob"
    return GitHubSpec(owner=owner, repo=repo, rest="/".join(rest_parts), focus=focus)


def _segment_ok(name: str, *, owner: bool) -> bool:
    if not name or name in (".", "..") or "/" in name or "@" in name:
        return False
    pattern = _OWNER_RE if owner else _REPO_RE
    return pattern.fullmatch(name) is not None


def _resolve_local(spec: LocalSpec) -> ResolvedTarget:
    raw = spec.raw
    try:
        path = Path(raw).expanduser().resolve()
    except OSError as exc:
        raise TargetError("not_found", f"target not found: {raw}") from exc
    if not path.exists():
        raise TargetError("not_found", f"target not found: {path}")
    if not path.is_file() and not path.is_dir():
        raise TargetError("not_file", f"target not found or not a directory/file: {path}")
    return ResolvedTarget(path=path, spec=spec, commit_sha=None, display=raw, subpath=())


def _confine(clone_root: Path, subpath: tuple[str, ...], *, kind: Literal["file", "dir"]) -> Path:
    _split_subpath("/".join(subpath))
    root_real = Path(os.path.realpath(clone_root))
    logical = root_real.joinpath(*subpath)
    real = Path(os.path.realpath(logical))
    try:
        real.relative_to(root_real)
    except ValueError as exc:
        raise TargetError("unsafe_path", "GitHub path escapes the snapshot") from exc
    if not real.exists():
        raise TargetError("not_found", f"target not found: {logical}")
    if kind == "file" and not real.is_file():
        raise TargetError("wrong_kind", f"GitHub blob URL did not resolve to a file: {logical}")
    if kind == "dir" and not real.is_dir():
        raise TargetError("wrong_kind", f"GitHub tree URL did not resolve to a directory: {logical}")
    return real


def _is_ready(dest: Path, sha: str) -> bool:
    if dest.is_symlink() or not dest.is_dir():
        return False
    marker = dest / READY_REL
    try:
        text = marker.read_text(encoding="utf-8")
    except OSError:
        return False
    return text.strip() == sha


def _discard(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or path.is_file():
        path.unlink()
        return
    shutil.rmtree(path)


def _blob_pe(spec: GitHubSpec, subpath: tuple[str, ...]) -> bool:
    if spec.focus != "blob" or not subpath:
        return False
    return Path(subpath[-1]).suffix.lower() in PE_EXTENSIONS


def _materialize_github(
    spec: GitHubSpec,
    *,
    cache_root: Path,
    git: GitFetcher,
    display: str,
) -> ResolvedTarget:
    sha, subpath = git.resolve_commit(spec)
    sha = _require_sha(sha)
    subpath = _split_subpath("/".join(subpath))
    if _blob_pe(spec, subpath):
        raise TargetError(
            "pe_binary",
            f"PE binaries are not supported (source analysis only): {display}",
        )

    root = Path(cache_root).expanduser().resolve()
    parent = root / spec.owner / spec.repo
    parent.mkdir(parents=True, exist_ok=True)
    dest = parent / sha
    staging = parent / f".{sha}.partial"
    lock_path = parent / f"{sha}.lock"
    lock = open_exclusive(lock_path)
    try:
        if not _is_ready(dest, sha):
            _discard(dest)
            _discard(staging)
            staging.mkdir(parents=True, exist_ok=False)
            try:
                git.fetch_commit(spec, sha, staging)
            except TargetError:
                raise
            except Exception as exc:
                raise TargetError("git_failed", f"git failed: {exc}") from exc
            marker = staging / READY_REL
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text(sha + "\n", encoding="utf-8")
            try:
                os.rename(staging, dest)
            except OSError as exc:
                raise TargetError("git_failed", f"could not publish snapshot: {exc}") from exc
    finally:
        lock.close()

    kind: Literal["file", "dir"] = "file" if spec.focus == "blob" else "dir"
    path = _confine(dest, subpath, kind=kind)
    return ResolvedTarget(
        path=path,
        spec=spec,
        commit_sha=sha,
        display=display,
        subpath=subpath,
    )


def _git_env() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(_GIT_ENV)
    return env


def _git_argv(args: list[str]) -> list[str]:
    argv = ["git"]
    for item in _GIT_CONFIG:
        argv.extend(["-c", item])
    argv.extend(args)
    return argv


def _match_ls_remote(text: str, rest: str) -> tuple[str, tuple[str, ...]]:
    names: dict[str, tuple[str, str, bool]] = {}
    head: tuple[str, bool] | None = None
    for line in text.splitlines():
        if "\t" not in line:
            continue
        sha_raw, ref = line.split("\t", 1)
        sha = sha_raw.strip().lower()
        ref = ref.strip()
        if not _sha_ok(sha):
            continue
        peeled = ref.endswith("^{}")
        base = ref[:-3] if peeled else ref
        if base == "HEAD":
            if head is None or (peeled and not head[1]):
                head = (sha, peeled)
            continue
        if base.startswith("refs/heads/"):
            name = base[len("refs/heads/") :]
            kind = "heads"
        elif base.startswith("refs/tags/"):
            name = base[len("refs/tags/") :]
            kind = "tags"
        else:
            continue
        if not name:
            continue
        prev = names.get(name)
        if prev is None or _prefer_ref(peeled, kind, prev):
            names[name] = (sha, kind, peeled)

    if rest == "":
        if head is None:
            raise TargetError("ref_not_found", "No GitHub ref matches that URL")
        return head[0], ()

    best_name = ""
    best: tuple[str, str, bool] | None = None
    for name, info in names.items():
        if rest == name or rest.startswith(name + "/"):
            if len(name) > len(best_name):
                best_name = name
                best = info
    if best is None:
        raise TargetError("ref_not_found", "No GitHub ref matches that URL")
    if rest == best_name:
        return best[0], ()
    return best[0], _split_subpath(rest[len(best_name) + 1 :])


def _prefer_ref(peeled: bool, kind: str, prev: tuple[str, str, bool]) -> bool:
    _prev_sha, prev_kind, prev_peeled = prev
    if peeled and not prev_peeled:
        return True
    if prev_peeled and not peeled:
        return False
    return kind == "heads" and prev_kind != "heads"


class _LiveGit:
    def resolve_commit(self, spec: GitHubSpec) -> tuple[str, tuple[str, ...]]:
        hit = _sha_prefix(spec.rest)
        if hit is not None:
            return hit
        text = self._run(
            ["ls-remote", "--", spec.clone_url, "HEAD", "refs/heads/*", "refs/tags/*"],
            timeout=60,
        )
        return _match_ls_remote(text, spec.rest)

    def fetch_commit(self, spec: GitHubSpec, sha: str, dest: Path) -> None:
        sha = _require_sha(sha)
        dest_s = os.fspath(Path(dest))
        self._run(["init", dest_s], timeout=60)
        self._run(["-C", dest_s, "remote", "add", "origin", spec.clone_url], timeout=60)
        self._run(["-C", dest_s, "fetch", "--depth", "1", "origin", sha], timeout=300)
        self._run(["-C", dest_s, "checkout", "--force", "FETCH_HEAD"], timeout=300)

    def _run(self, args: list[str], *, timeout: int) -> str:
        argv = _git_argv(args)
        try:
            proc = subprocess.run(
                argv,
                env=_git_env(),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                stdin=subprocess.DEVNULL,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TargetError("git_timeout", "git timed out") from exc
        except OSError as exc:
            raise TargetError("git_failed", "git failed to start") from exc
        if proc.returncode != 0:
            lines = (proc.stderr or proc.stdout or "").strip().splitlines()
            line = lines[-1] if lines else f"exit {proc.returncode}"
            if len(line) > 300:
                line = line[:300]
            raise TargetError("git_failed", f"git failed: {line}")
        return proc.stdout or ""
