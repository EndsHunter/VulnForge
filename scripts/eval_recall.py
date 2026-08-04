#!/usr/bin/env python3
"""Score L0 mechanical recall (and optionally print live instructions).

Usage:
  python scripts/eval_recall.py
  python scripts/eval_recall.py --target fixtures/toy_sqli
  python scripts/eval_recall.py --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure package import when run as script
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulnforge.eval.recall import load_ground_truth, score_findings
from vulnforge.paths import PROJECT_ROOT
from vulnforge.tools.codemap import build_codemap
from vulnforge.tools.sink_preindex import build_sink_preindex


def mechanical_score(gt_name: str) -> dict:
    gt = load_ground_truth(gt_name)
    target = PROJECT_ROOT / str(gt.get("target") or "")
    sinks = build_sink_preindex(target)
    cm = build_codemap(target)
    oracles = list(gt.get("findings") or [])
    # Synthesize "findings" from sink hits that match oracles for L0 score
    synthetic = []
    for o in oracles:
        for s in sinks:
            sp = str(s.get("path") or "").replace("\\", "/")
            want = str(o.get("sink_path") or "")
            kinds = set(o.get("kinds") or [])
            if want and (sp == want or sp.endswith(want)):
                if not kinds or s.get("kind") in kinds:
                    synthetic.append(
                        {
                            "sink_path": sp,
                            "sink_symbol": o.get("sink_symbol"),
                            "citations": [
                                {
                                    "path": sp,
                                    "start_line": s.get("line"),
                                    "symbol": o.get("sink_symbol"),
                                }
                            ],
                        }
                    )
                    break
    sc = score_findings(synthetic, oracles)
    # symbol coverage
    sym_ok = 0
    for o in oracles:
        want = str(o.get("sink_symbol") or "")
        if not want:
            sym_ok += 1
            continue
        for sym in cm.get("symbols") or []:
            if isinstance(sym, dict) and str(sym.get("name") or "") == want:
                sym_ok += 1
                break
    sc["symbol_hit_count"] = sym_ok
    sc["target"] = str(gt.get("target"))
    sc["gt"] = gt_name
    sc["sink_count"] = len(sinks)
    sc["symbol_count"] = len(cm.get("symbols") or [])
    return sc


def main() -> int:
    ap = argparse.ArgumentParser(description="L0 mechanical fixture recall")
    ap.add_argument(
        "--target",
        action="append",
        dest="targets",
        help="Ground-truth id (toy_sqli, mono_synth). Default: both.",
    )
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args()
    names = args.targets or ["toy_sqli", "mono_synth"]
    rows = [mechanical_score(n) for n in names]
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for sc in rows:
            print(
                f"{sc['gt']}: recall={sc['recall']:.0%} "
                f"hits={sc['hit_count']}/{sc['oracle_count']} "
                f"symbols={sc['symbol_hit_count']}/{sc['oracle_count']} "
                f"sinks_index={sc['sink_count']}"
            )
            if sc["misses"]:
                print(f"  misses: {', '.join(sc['misses'])}")
    bad = [sc for sc in rows if sc["recall"] < 1.0]
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
