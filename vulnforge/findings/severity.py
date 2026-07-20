"""Normalize and soft-drop optional finding severity_claim values.

severity_claim is optional. Allowed ratings match validate_mech:

  CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL

Free-text or unknown tokens are soft-dropped (field removed, original kept
under severity_claim_dropped) so a solid candidate is not rejected solely
for a mis-filled optional field.
"""

from __future__ import annotations

from typing import Any

ALLOWED_SEVERITY_CLAIMS: frozenset[str] = frozenset(
    {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}
)

# Map uppercased aliases → canonical claim.
_SEVERITY_ALIASES: dict[str, str] = {
    "CRITICAL": "CRITICAL",
    "CRIT": "CRITICAL",
    "P0": "CRITICAL",
    "HIGH": "HIGH",
    "H": "HIGH",
    "P1": "HIGH",
    "MEDIUM": "MEDIUM",
    "MED": "MEDIUM",
    "MODERATE": "MEDIUM",
    "MID": "MEDIUM",
    "P2": "MEDIUM",
    "LOW": "LOW",
    "L": "LOW",
    "P3": "LOW",
    "INFORMATIONAL": "INFORMATIONAL",
    "INFO": "INFORMATIONAL",
    "INFORMATION": "INFORMATIONAL",
    "INFORMATIONAL.": "INFORMATIONAL",
    "NONE": "INFORMATIONAL",
    "P4": "INFORMATIONAL",
    # Numeric style (CVSS-ish buckets, coarse)
    "1": "INFORMATIONAL",
    "2": "LOW",
    "3": "MEDIUM",
    "4": "HIGH",
    "5": "CRITICAL",
}


def normalize_severity_claim(value: Any) -> str | None:
    """
    Return canonical severity string, or None if missing/empty/unmappable.

    Does not invent severity from free-form prose — only exact tokens and
    known aliases after strip/upper.
    """
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    key = s.upper()
    if key in ALLOWED_SEVERITY_CLAIMS:
        return key
    # Collapse internal whitespace for things like "  high  "
    key_compact = " ".join(key.split())
    if key_compact in ALLOWED_SEVERITY_CLAIMS:
        return key_compact
    if key_compact in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[key_compact]
    # Single-token aliases only (reject multi-word free text)
    if " " not in key_compact and key_compact in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[key_compact]
    return None


def apply_severity_claim(body: dict) -> tuple[dict, str | None]:
    """
    Normalize or soft-drop severity_claim on a finding/candidate body.

    Returns (possibly mutated shallow copy, action) where action is one of:
      None — no field / already canonical / empty
      "normalized" — mapped alias → canonical
      "dropped" — unmappable; removed with severity_claim_dropped set
    """
    out = dict(body)
    if "severity_claim" not in out:
        return out, None
    raw = out.get("severity_claim")
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        out.pop("severity_claim", None)
        return out, None

    canon = normalize_severity_claim(raw)
    if canon is not None:
        prev = out.get("severity_claim")
        out["severity_claim"] = canon
        if prev == canon:
            return out, None
        return out, "normalized"

    # Soft-drop: keep audit trail, remove invalid optional field
    out["severity_claim_dropped"] = raw
    out.pop("severity_claim", None)
    return out, "dropped"
