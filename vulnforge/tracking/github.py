"""GitHub Issues sink (#189).

Transports:

* ``gh``    — ``gh api`` subprocess (argv list, no shell). gh holds its own
  credentials; VulnForge never sees the token.
* ``token`` — urllib against ``https://api.github.com`` with
  ``VF_GITHUB_TOKEN`` / ``GITHUB_TOKEN`` from the environment. The token lives
  only in the request header; it is never logged, returned, or put on argv.

Dedupe never uses the search API (index lag, drops HTML comments). A remote
lookup lists issues carrying the ``vulnforge`` label and matches the exact
visible marker line. Every update first fetches the issue and refuses to patch
one that does not carry the marker for this ``stable_key``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Optional

from vulnforge.tracking.base import (
    ExternalIssue,
    TrackingError,
    TrackPayload,
    TrackResult,
    body_has_marker,
)

API_ROOT = "https://api.github.com"
TRACK_LABEL = "vulnforge"
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
TOKEN_ENV_VARS = ("VF_GITHUB_TOKEN", "GITHUB_TOKEN")
SCAN_MAX_PAGES = 10
_TIMEOUT_S = 30

# Module-level hooks so tests can block/replace process + network access here
# without patching the global subprocess / urllib modules.
_run = subprocess.run
_urlopen = urllib.request.urlopen

# (method, path, json_body or None) -> parsed JSON
Transport = Callable[[str, str, Optional[dict]], Any]

_SECRET_RE = re.compile(
    r"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"(?i:authorization)\s*:\s*\S+(\s+\S+)?|(?i:bearer)\s+\S+|(?i:token)\s+[A-Za-z0-9_\-]{20,})"
)


def redact(text: str, *, limit: int = 400) -> str:
    """Strip anything that looks like a credential, then clip."""
    out = _SECRET_RE.sub("[redacted]", str(text or ""))
    for var in TOKEN_ENV_VARS:
        val = os.environ.get(var)
        if val and len(val) >= 8:
            out = out.replace(val, "[redacted]")
    out = out.strip()
    return out if len(out) <= limit else out[:limit] + "…"


def validate_repo(repo: str) -> str:
    r = str(repo or "").strip()
    if not REPO_RE.match(r) or ".." in r:
        raise TrackingError(f"invalid GitHub repo {r!r}; expected owner/name")
    return r


class GhCliTransport:
    """``gh api`` subprocess. Credentials stay inside gh."""

    def __init__(self, gh_path: Optional[str] = None):
        self.gh_path = gh_path or shutil.which("gh") or "gh"

    def argv(self, method: str, path: str, has_body: bool) -> list[str]:
        cmd = [
            self.gh_path,
            "api",
            "-X",
            method.upper(),
            "-H",
            "Accept: application/vnd.github+json",
            path.lstrip("/"),
        ]
        if has_body:
            cmd += ["--input", "-"]
        return cmd

    def __call__(self, method: str, path: str, body: Optional[dict] = None) -> Any:
        cmd = self.argv(method, path, body is not None)
        try:
            proc = _run(  # noqa: S603 — argv list, no shell
                cmd,
                input=json.dumps(body) if body is not None else None,
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_S,
                check=False,
            )
        except FileNotFoundError as e:
            raise TrackingError("gh CLI not found; install gh and run `gh auth login`") from e
        except subprocess.TimeoutExpired as e:
            raise TrackingError(f"gh api {method} timed out") from e
        if proc.returncode != 0:
            raise TrackingError(
                f"gh api {method.upper()} failed (exit {proc.returncode}): "
                f"{redact(proc.stderr or proc.stdout)}"
            )
        out = (proc.stdout or "").strip()
        if not out:
            return {}
        try:
            return json.loads(out)
        except json.JSONDecodeError as e:
            raise TrackingError("gh api returned non-JSON output") from e


class TokenTransport:
    """REST with a token from the environment. Pinned to api.github.com."""

    def __init__(self, token: str):
        if not token:
            raise TrackingError("no GitHub token in VF_GITHUB_TOKEN / GITHUB_TOKEN")
        self._token = token

    def __repr__(self) -> str:  # never show the token
        return "TokenTransport(token=[redacted])"

    def __call__(self, method: str, path: str, body: Optional[dict] = None) -> Any:
        url = API_ROOT + "/" + path.lstrip("/")
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method.upper())
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "vulnforge-tracking")
        req.add_header("Authorization", f"Bearer {self._token}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with _urlopen(req, timeout=_TIMEOUT_S) as resp:  # noqa: S310 — fixed https host
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            msg = ""
            try:
                msg = str(json.loads(e.read().decode("utf-8")).get("message") or "")
            except Exception:  # noqa: BLE001 — error body is best-effort
                msg = ""
            raise TrackingError(
                f"GitHub API {method.upper()} returned {e.code}: {redact(msg)}"
            ) from None
        except urllib.error.URLError as e:
            raise TrackingError(f"GitHub API unreachable: {redact(str(e.reason))}") from None
        return json.loads(raw) if raw.strip() else {}


def resolve_transport(mode: str = "auto") -> Transport:
    m = str(mode or "auto").strip().lower()
    token = next((os.environ.get(v) for v in TOKEN_ENV_VARS if os.environ.get(v)), "")
    if m == "gh":
        return GhCliTransport()
    if m == "token":
        return TokenTransport(token)
    if m != "auto":
        raise TrackingError(f"unknown GitHub transport {mode!r}; use auto|gh|token")
    if shutil.which("gh"):
        return GhCliTransport()
    if token:
        return TokenTransport(token)
    raise TrackingError(
        "no GitHub transport: install gh and run `gh auth login`, or set VF_GITHUB_TOKEN"
    )


def _issue(data: Any) -> ExternalIssue:
    if not isinstance(data, dict) or data.get("number") is None:
        raise TrackingError("GitHub returned an unexpected issue payload")
    return ExternalIssue(
        external_id=str(int(data["number"])),
        url=str(data.get("html_url") or ""),
        body=str(data.get("body") or ""),
        state=str(data.get("state") or ""),
    )


class GitHubIssuesSink:
    name = "github"

    def __init__(self, repo: str, transport: Transport):
        self.destination = validate_repo(repo)
        self._t = transport

    def _issue_path(self, external_id: str) -> str:
        try:
            n = int(str(external_id))
        except ValueError:
            raise TrackingError(f"invalid issue number {external_id!r}") from None
        if n <= 0:
            raise TrackingError(f"invalid issue number {external_id!r}")
        return f"repos/{self.destination}/issues/{n}"

    def get(self, external_id: str) -> ExternalIssue:
        return _issue(self._t("GET", self._issue_path(external_id), None))

    def find_by_marker(self, stable_key: str) -> Optional[ExternalIssue]:
        q = urllib.parse.urlencode(
            {"labels": TRACK_LABEL, "state": "all", "per_page": 100}
        )
        for page in range(1, SCAN_MAX_PAGES + 1):
            rows = self._t("GET", f"repos/{self.destination}/issues?{q}&page={page}", None)
            if not isinstance(rows, list) or not rows:
                return None
            for row in rows:
                if not isinstance(row, dict) or row.get("pull_request"):
                    continue
                if body_has_marker(str(row.get("body") or ""), stable_key):
                    return _issue(row)
            if len(rows) < 100:
                return None
        return None

    def create(self, payload: TrackPayload) -> TrackResult:
        labels = [TRACK_LABEL] + [l for l in payload.labels if l and l != TRACK_LABEL]
        data = self._t(
            "POST",
            f"repos/{self.destination}/issues",
            {"title": payload.title, "body": payload.body_md, "labels": labels},
        )
        iss = _issue(data)
        return TrackResult(
            self.name, self.destination, iss.external_id, iss.url, "created", iss.state
        )

    def update(self, external_id: str, payload: TrackPayload) -> TrackResult:
        current = self.get(external_id)
        if not body_has_marker(current.body, payload.stable_key):
            raise TrackingError(
                f"issue #{current.external_id} does not carry the marker for this "
                "finding; refusing to overwrite it"
            )
        data = self._t(
            "PATCH",
            self._issue_path(external_id),
            {"title": payload.title, "body": payload.body_md},
        )
        iss = _issue(data)
        return TrackResult(
            self.name, self.destination, iss.external_id, iss.url, "updated", iss.state
        )
