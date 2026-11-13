#!/usr/bin/env python3
"""Maintain the frozen VulnGym slice (the ``realworld`` benchmark suite's oracles).

  python scripts/vulngym_slice.py --freeze        # rebuild fixtures/vulngym/slice.json
  python scripts/vulngym_slice.py --prepare       # check out pinned trees under .audit/vulngym/trees
  python scripts/vulngym_slice.py --sensitivity   # ruler check: empty = 0, perfect = 1

Live runs moved to the Benchmarks desk and ``vf bench run --suite realworld``
(Settings LLM, fingerprinted, comparable against a baseline).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulnforge.benchmarks.match import load_ground_truth, score_findings  # noqa: E402
from vulnforge.benchmarks.vulngym import (  # noqa: E402
    SLICE_IDS,
    SLICE_PATH,
    freeze_slice,
    prepare_trees,
)


def load_catalog() -> dict[str, Any]:
    return load_ground_truth(SLICE_PATH)


def synthetic_perfect(oracles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    bodies = []
    for o in oracles:
        path = str(o.get("sink_path") or "")
        line = (o.get("match") or {}).get("start_line")
        bodies.append({"sink_path": path, "citations": [{"path": path, "start_line": line}]})
    return bodies


def sensitivity() -> dict[str, Any]:
    oracles = list(load_catalog().get("findings") or [])
    empty = score_findings([], oracles)
    perfect = score_findings(synthetic_perfect(oracles), oracles)
    return {
        "empty_recall": empty["recall"],
        "perfect_recall": perfect["recall"],
        "oracle_count": len(oracles),
        "ok": empty["recall"] == 0.0 and perfect["recall"] == 1.0 and len(oracles) == len(SLICE_IDS),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Maintain the frozen VulnGym slice")
    ap.add_argument("--freeze", action="store_true", help="Rebuild slice.json from upstream entries")
    ap.add_argument("--prepare", action="store_true", help="Check out the pinned trees")
    ap.add_argument("--sensitivity", action="store_true", help="Ruler check (empty 0, perfect 1)")
    args = ap.parse_args()
    if args.freeze:
        data = freeze_slice()
        print(json.dumps({"ok": True, "n": len(data["findings"]), "path": str(SLICE_PATH)}, indent=2))
        return 0
    if args.prepare:
        if not SLICE_PATH.is_file():
            freeze_slice()
        print(json.dumps({"ok": True, "trees": prepare_trees(list(load_catalog().get("findings") or []))}, indent=2))
        return 0
    if args.sensitivity:
        if not SLICE_PATH.is_file():
            freeze_slice()
        s = sensitivity()
        print(json.dumps(s, indent=2))
        return 0 if s["ok"] else 1
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
