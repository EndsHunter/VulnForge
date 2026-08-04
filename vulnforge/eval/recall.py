"""Ground-truth loading and finding↔oracle matching for recall scoring."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnforge.paths import PROJECT_ROOT
from vulnforge.util import normalize_relpath

GROUND_TRUTH_ROOT = PROJECT_ROOT / "fixtures" / "ground_truth"


def load_ground_truth(path: str | Path) -> dict[str, Any]:
    """Load a ground-truth JSON catalog.

    Expected shape::

        {
          "target": "fixtures/toy_sqli",
          "findings": [
            {
              "id": "...",
              "class": "injection",
              "sink_path": "app.py",
              "sink_symbol": "search_users",
              "kinds": ["sql"],
              "match": {"path_suffix": "app.py", "symbol": "search_users"}
            }
          ]
        }
    """
    p = Path(path)
    if not p.is_file():
        # allow bare id like toy_sqli
        alt = GROUND_TRUTH_ROOT / f"{path}.json"
        if alt.is_file():
            p = alt
        else:
            raise FileNotFoundError(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("ground truth must be an object")
    findings = data.get("findings")
    if not isinstance(findings, list):
        data["findings"] = []
    return data


def _path_matches(path: str, oracle: dict[str, Any]) -> bool:
    p = normalize_relpath(path or "")
    if not p:
        return False
    match = oracle.get("match") if isinstance(oracle.get("match"), dict) else {}
    suffix = str(match.get("path_suffix") or oracle.get("sink_path") or "").strip()
    if not suffix:
        return False
    suffix_n = normalize_relpath(suffix)
    return (
        p == suffix_n
        or p.endswith("/" + suffix_n)
        or p.endswith(suffix_n)
        or suffix_n.endswith(p)
        or p.endswith(Path(suffix_n).name)
    )


def _symbol_matches(body: dict, oracle: dict[str, Any]) -> bool:
    match = oracle.get("match") if isinstance(oracle.get("match"), dict) else {}
    want = str(
        match.get("symbol") or oracle.get("sink_symbol") or ""
    ).strip().lower()
    if not want:
        return True  # path-only oracle
    candidates = [
        str(body.get("sink_symbol") or ""),
    ]
    for c in body.get("citations") or []:
        if isinstance(c, dict):
            candidates.append(str(c.get("symbol") or ""))
    return any(want == str(x).strip().lower() for x in candidates if x)


def finding_matches_oracle(finding_body: dict, oracle: dict[str, Any]) -> bool:
    """True if finding body matches one ground-truth oracle entry."""
    if not isinstance(finding_body, dict) or not isinstance(oracle, dict):
        return False
    paths: list[str] = []
    sp = finding_body.get("sink_path")
    if sp:
        paths.append(str(sp))
    for c in finding_body.get("citations") or []:
        if isinstance(c, dict) and c.get("path"):
            paths.append(str(c["path"]))
    if not paths:
        return False
    if not any(_path_matches(p, oracle) for p in paths):
        return False
    return _symbol_matches(finding_body, oracle)


def score_findings(
    findings: list[Any],
    oracles: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute recall against oracles. Extra findings count as extras (not precision fail).

    *findings* may be dict bodies or objects with ``.body``.
    """
    bodies: list[dict] = []
    for f in findings or []:
        if isinstance(f, dict):
            if "body" in f and isinstance(f["body"], dict):
                bodies.append(f["body"])
            else:
                bodies.append(f)
        else:
            b = getattr(f, "body", None)
            if isinstance(b, dict):
                bodies.append(b)

    hits: list[str] = []
    misses: list[str] = []
    hit_bodies: list[dict] = []
    for o in oracles or []:
        oid = str(o.get("id") or o.get("sink_path") or "?")
        matched = False
        for b in bodies:
            if finding_matches_oracle(b, o):
                matched = True
                hit_bodies.append(b)
                break
        if matched:
            hits.append(oid)
        else:
            misses.append(oid)

    total = len(oracles or [])
    recall = (len(hits) / total) if total else 1.0
    # extras = findings not matching any oracle
    extras = 0
    for b in bodies:
        if not any(finding_matches_oracle(b, o) for o in (oracles or [])):
            extras += 1

    return {
        "recall": recall,
        "hits": hits,
        "misses": misses,
        "hit_count": len(hits),
        "oracle_count": total,
        "finding_count": len(bodies),
        "extras": extras,
    }
