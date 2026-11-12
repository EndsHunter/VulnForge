"""Pluggable external tracker interface (#189).

A sink publishes one finding as one external ticket. GitHub Issues is the only
implementation today; Jira and Linear are reserved names in ``SINKS``.

Sinks are outward-facing. Nothing in the Ralph loop or any stage calls them:
the only callers are the dashboard Track route (preview token) and the
operator-chat ``track_findings`` mutator (UI Confirm).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

MARKER_PREFIX = "vulnforge-stable-key:"


class TrackingError(RuntimeError):
    """Sink/transport failure. Messages must never carry credentials."""


@dataclass
class TrackPayload:
    stable_key: str
    title: str
    body_md: str
    labels: list[str] = field(default_factory=list)


@dataclass
class ExternalIssue:
    external_id: str
    url: str
    body: str = ""
    state: str = ""


@dataclass
class TrackResult:
    sink: str
    destination: str
    external_id: str
    url: str
    action: str  # created | updated
    remote_state: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "sink": self.sink,
            "destination": self.destination,
            "external_id": self.external_id,
            "url": self.url,
            "action": self.action,
            "remote_state": self.remote_state,
        }


def marker_line(stable_key: str) -> str:
    return f"{MARKER_PREFIX} {stable_key}"


def body_has_marker(body: str, stable_key: str) -> bool:
    """True only when the LAST non-empty line is the exact marker for this key.

    Interpolated finding text cannot forge it: ``render`` breaks any marker-like
    line inside content, and the real marker is always the final line.
    """
    if not body or not stable_key:
        return False
    lines = [ln.strip() for ln in str(body).splitlines() if ln.strip()]
    return bool(lines) and lines[-1] == marker_line(stable_key)


class TrackingSink(Protocol):
    name: str
    destination: str

    def get(self, external_id: str) -> ExternalIssue: ...

    def find_by_marker(self, stable_key: str) -> Optional[ExternalIssue]: ...

    def create(self, payload: TrackPayload) -> TrackResult: ...

    def update(self, external_id: str, payload: TrackPayload) -> TrackResult: ...


# name -> factory(cfg, repo/destination, transport) ; None = reserved, not implemented
SINKS: dict[str, Any] = {"github": None, "jira": None, "linear": None}


def _github_factory(tracking_cfg: dict, destination: str, transport: Any):
    from vulnforge.tracking.github import GitHubIssuesSink, resolve_transport

    gh_cfg = tracking_cfg.get("github") if isinstance(tracking_cfg.get("github"), dict) else {}
    tr = transport or resolve_transport(str(gh_cfg.get("transport") or "auto"))
    return GitHubIssuesSink(destination, tr)


SINKS["github"] = _github_factory


def sink_names() -> list[str]:
    return sorted(SINKS)


def build_sink(
    sink: str, tracking_cfg: dict, destination: str, *, transport: Any = None
) -> TrackingSink:
    name = str(sink or "").strip().lower()
    if name not in SINKS:
        raise TrackingError(f"unknown tracking sink: {sink!r}; known: {', '.join(sink_names())}")
    factory = SINKS[name]
    if factory is None:
        raise TrackingError(f"tracking sink {name!r} is not implemented yet")
    return factory(tracking_cfg or {}, destination, transport)
