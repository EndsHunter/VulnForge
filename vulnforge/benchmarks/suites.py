"""Named benchmark suites and tiers.

A **suite** groups library cases by *what they measure*, not by type:

- ``realworld``: pinned OSS projects at pre-fix commits (VulnGym GHSA slice,
  plus any case tagged ``suite:realworld``). #171's dataset.
- ``synthetic``: small vendored apps (``toy_sqli``, ``mono_synth``, ``pe-*``,
  ``hx-*``).
- ``fixtures``: recon and finding_report scorer fixtures. L0 only.

A **tier** says what kind of number a run produces. Tiers never mix in one
aggregate:

- ``l0``: mechanical fixture check. No LLM. Says the fixture and scorer still
  line up. It says nothing about model quality.
- ``directed``: live hunt pointed at the oracle file and class. "Recall when
  told where to look."

Suite membership comes from a ``suite:<id>`` tag when present, else from the
case's shape, so libraries seeded before suites existed need no migration.
"""

from __future__ import annotations

from typing import Any

SUITES: dict[str, dict[str, Any]] = {
    "realworld": {
        "label": "Real-world OSS",
        "blurb": "Open-source projects pinned at pre-fix commits (VulnGym GHSA slice).",
        "tiers": ("directed",),
    },
    "synthetic": {
        "label": "Synthetic apps",
        "blurb": "Small vendored apps with planted bugs (toy_sqli, mono_synth, pe-*, hx-*).",
        "tiers": ("directed",),
    },
    "fixtures": {
        "label": "Fixture checks",
        "blurb": "Mechanical L0 over every vendored case: synthetic hunts plus recon and finding-report scorer fixtures.",
        "tiers": ("l0",),
    },
}

TIERS: dict[str, dict[str, str]] = {
    "l0": {
        "label": "L0 fixture check",
        "mode": "mechanical",
        "caveat": "Mechanical. No LLM ran. Fixtures and scorers line up; says nothing about model quality.",
    },
    "directed": {
        "label": "Directed",
        "mode": "live",
        "caveat": "Hunts were pointed at the oracle file and class. Recall when told where to look.",
    },
}

# The ``fixtures`` L0 run covers every case whose target is vendored in the repo.
FIXTURE_CHECK_SUITES = ("synthetic", "fixtures")


def suite_of(defn: dict[str, Any]) -> str:
    """Suite id for one library def (tag wins, else derived from shape)."""
    for tag in defn.get("tags") or []:
        t = str(tag).strip().lower()
        if t.startswith("suite:") and t[6:] in SUITES:
            return t[6:]
    types = [str(t).strip().lower() for t in (defn.get("types") or [])]
    if "hunt" not in types:
        return "fixtures"
    target = str(defn.get("target_ref") or "").replace("\\", "/")
    tags = {str(t).strip().lower() for t in (defn.get("tags") or [])}
    if "/vulngym/trees/" in f"/{target}" or "vulngym" in tags:
        return "realworld"
    return "synthetic"


def suite_members(suite_id: str, tier: str, defs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Library defs a suite run covers, sorted by id."""
    if suite_id == "fixtures" and tier == "l0":
        want = set(FIXTURE_CHECK_SUITES)
    else:
        want = {suite_id}
    rows = [d for d in defs if suite_of(d) in want]
    if tier == "directed":
        rows = [d for d in rows if "hunt" in (d.get("types") or [])]
    return sorted(rows, key=lambda d: str(d.get("id") or ""))


def suite_refusal(suite_id: str, tier: str) -> str | None:
    """None = allowed. Else a human-readable reason."""
    if suite_id not in SUITES:
        return f"unknown suite {suite_id!r}; allow {', '.join(sorted(SUITES))}"
    if tier not in TIERS:
        return f"unknown tier {tier!r}; allow {', '.join(sorted(TIERS))}"
    if tier not in SUITES[suite_id]["tiers"]:
        return f"suite {suite_id} does not support tier {tier}"
    return None


def suite_catalog(defs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Public suite list with case counts (for GET /api/benchmarks/suites)."""
    out = []
    for sid, meta in SUITES.items():
        cases = [d for d in defs if suite_of(d) == sid]
        out.append(
            {
                "id": sid,
                "label": meta["label"],
                "blurb": meta["blurb"],
                "tiers": list(meta["tiers"]),
                "case_count": len(cases),
                "case_ids": sorted(str(d.get("id") or "") for d in cases),
            }
        )
    return out


__all__ = [
    "FIXTURE_CHECK_SUITES",
    "SUITES",
    "TIERS",
    "suite_catalog",
    "suite_of",
    "suite_members",
    "suite_refusal",
]
