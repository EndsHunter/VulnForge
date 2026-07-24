"""One-shot pending mutation tokens for operator chat."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Optional

TTL_SECONDS = 600


@dataclass
class PendingMutation:
    token: str
    tool_name: str
    arguments: dict[str, Any]
    summary: str
    scope: str  # home | run
    session_id: str
    created_at: float = field(default_factory=time.time)
    run_key: Optional[str] = None  # target/run for run scope

    def expired(self) -> bool:
        return (time.time() - self.created_at) > TTL_SECONDS

    def to_public(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "summary": self.summary,
            "scope": self.scope,
            "session_id": self.session_id,
            "run_key": self.run_key,
            "expires_in_s": max(0, int(TTL_SECONDS - (time.time() - self.created_at))),
        }


# process-local store (dashboard single process)
_PENDING: dict[str, PendingMutation] = {}


def create_pending(
    *,
    tool_name: str,
    arguments: dict[str, Any],
    summary: str,
    scope: str,
    session_id: str,
    run_key: Optional[str] = None,
) -> PendingMutation:
    tok = secrets.token_urlsafe(16)
    p = PendingMutation(
        token=tok,
        tool_name=tool_name,
        arguments=dict(arguments or {}),
        summary=summary,
        scope=scope,
        session_id=session_id,
        run_key=run_key,
    )
    _PENDING[tok] = p
    return p


def take_pending(token: str) -> Optional[PendingMutation]:
    p = _PENDING.pop(token, None)
    if p is None:
        return None
    if p.expired():
        return None
    return p
