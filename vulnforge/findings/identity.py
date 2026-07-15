"""Stable finding identity (PROTOCOL stable_key)."""

from __future__ import annotations

import hashlib

from vulnforge.util import normalize_relpath


def compute_stable_key(profile: str, body: dict) -> str:
    """Hash stable finding identity (PROTOCOL).

    P2.4: prefer explicit sink_path/sink_symbol; normalize path; do not rely
    solely on first citation when a primary sink is declared.
    """
    path = normalize_relpath(str(body.get("sink_path") or ""))
    symbol = str(body.get("sink_symbol") or "")
    citations = body.get("citations") or []
    if isinstance(citations, list):
        chosen = None
        if path:
            for c in citations:
                if isinstance(c, dict) and normalize_relpath(
                    str(c.get("path") or "")
                ) == path:
                    chosen = c
                    break
        if chosen is None:
            for c in citations:
                if isinstance(c, dict) and c.get("path"):
                    chosen = c
                    break
        if chosen is not None:
            if not path:
                path = normalize_relpath(str(chosen.get("path") or ""))
            if not symbol:
                symbol = str(chosen.get("symbol") or "")
    path = normalize_relpath(path)
    tm = body.get("threat_model") or {}
    attacker = str(tm.get("attacker") or body.get("attacker_capability") or "")
    weakness = str(body.get("weakness_class") or "")
    sink = str(body.get("sink_symbol") or symbol)
    parts = [profile, path, symbol, weakness, attacker, sink]
    blob = "|".join(parts).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:32]
