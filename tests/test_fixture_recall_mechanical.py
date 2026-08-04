"""L0 mechanical recall: sinks + symbols (+ optional flows) cover ground-truth oracles.

Always runs in CI. Does not require an LLM. Live hunt recall is separate (VF_LIVE).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnforge.eval.recall import (
    finding_matches_oracle,
    load_ground_truth,
    score_findings,
)
from vulnforge.paths import PROJECT_ROOT
from vulnforge.tools.codemap import build_codemap
from vulnforge.tools.flows import call_sites, import_neighborhood
from vulnforge.tools.sink_preindex import build_sink_preindex


FIXTURES = PROJECT_ROOT / "fixtures"
GT_ROOT = FIXTURES / "ground_truth"


def _target_path(gt: dict) -> Path:
    rel = str(gt.get("target") or "")
    p = PROJECT_ROOT / rel
    assert p.is_dir(), f"missing target {p}"
    return p


def _oracle_path_hit(sinks: list[dict], oracle: dict) -> bool:
    kinds = set(oracle.get("kinds") or [])
    want_path = str(oracle.get("sink_path") or "")
    for s in sinks:
        sp = str(s.get("path") or "").replace("\\", "/")
        if want_path and (sp == want_path or sp.endswith(want_path) or want_path.endswith(sp)):
            if not kinds or s.get("kind") in kinds:
                return True
    return False


def _oracle_symbol_hit(codemap: dict, oracle: dict) -> bool:
    want = str(oracle.get("sink_symbol") or "").strip()
    if not want:
        return True
    want_path = str(oracle.get("sink_path") or "").replace("\\", "/")
    for sym in codemap.get("symbols") or []:
        if not isinstance(sym, dict):
            continue
        if str(sym.get("name") or "") != want:
            continue
        sp = str(sym.get("path") or "").replace("\\", "/")
        if not want_path or sp == want_path or sp.endswith(want_path) or want_path in sp:
            return True
    return False


@pytest.mark.parametrize("gt_name", ["toy_sqli", "mono_synth"])
def test_l0_sinks_and_symbols_cover_oracles(gt_name: str):
    gt = load_ground_truth(gt_name)
    target = _target_path(gt)
    sinks = build_sink_preindex(target)
    cm = build_codemap(target)
    misses = []
    for o in gt.get("findings") or []:
        oid = o.get("id")
        if not _oracle_path_hit(sinks, o):
            misses.append(f"{oid}:sink_preindex")
        if not _oracle_symbol_hit(cm, o):
            misses.append(f"{oid}:symbol")
    assert not misses, f"L0 scaffolding misses: {misses}"


def test_l0_toy_sqli_query_flows_calls_ok(toy_sqli: Path):
    """call mode is honest even with zero callers."""
    r = call_sites(toy_sqli, "search_users")
    assert r["ok"] is True


def test_l0_mono_synth_import_neighborhood(project_root: Path):
    mono = project_root / "fixtures" / "mono_synth"
    cm = build_codemap(mono)
    r = import_neighborhood(cm, path="packages/api/routes.py", max_depth=2)
    assert r["ok"] is True
    # module anchor should resolve for multi-package tree
    assert r.get("anchor", {}).get("module") or r.get("nodes") is not None


def test_score_findings_recall_helper():
    gt = load_ground_truth("toy_sqli")
    oracles = gt["findings"]
    # Perfect match body
    bodies = [
        {
            "sink_path": "app.py",
            "sink_symbol": "search_users",
            "citations": [{"path": "app.py", "symbol": "search_users", "start_line": 9}],
        }
    ]
    sc = score_findings(bodies, oracles)
    assert sc["recall"] == 1.0
    assert sc["misses"] == []
    # Miss
    sc2 = score_findings([{"sink_path": "other.py", "sink_symbol": "x"}], oracles)
    assert sc2["recall"] == 0.0
    assert sc2["misses"]
    # Matching helper
    assert finding_matches_oracle(bodies[0], oracles[0]) is True
