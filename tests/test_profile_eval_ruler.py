"""The hunt-profile eval ruler must separate empty vs perfect recall."""

import json
import subprocess
import sys

from vulnforge.eval.recall import load_ground_truth, score_findings
from vulnforge.paths import PROJECT_ROOT

GT = PROJECT_ROOT / "fixtures" / "profile_eval" / "ground_truth.json"
TREE = PROJECT_ROOT / "fixtures" / "profile_eval" / "tree"
EVAL_SCRIPT = PROJECT_ROOT / "scripts" / "eval_hunt_profiles.py"


def _perfect_bodies(oracles):
    bodies = []
    for o in oracles:
        path = str(o.get("sink_path") or "")
        sym = str(o.get("sink_symbol") or "")
        bodies.append(
            {
                "sink_path": path,
                "sink_symbol": sym,
                "citations": [{"path": path, "symbol": sym, "start_line": 1}],
            }
        )
    return bodies


def test_profile_eval_files_exist():
    gt = load_ground_truth(GT)
    for o in gt["findings"]:
        p = TREE / str(o["sink_path"])
        assert p.is_file(), p


def test_profile_eval_empty_is_zero():
    gt = load_ground_truth(GT)
    sc = score_findings([], gt["findings"])
    assert sc["recall"] == 0.0
    assert sc["hit_count"] == 0
    assert len(sc["misses"]) == len(gt["findings"])


def test_profile_eval_perfect_is_one():
    gt = load_ground_truth(GT)
    sc = score_findings(_perfect_bodies(gt["findings"]), gt["findings"])
    assert sc["recall"] == 1.0
    assert sc["misses"] == []


def test_profile_eval_sensitivity_cli():
    r = subprocess.run(
        [sys.executable, str(EVAL_SCRIPT), "--sensitivity"],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr or r.stdout
    data = json.loads(r.stdout)
    assert data["ok"] is True
    assert data["empty_recall"] == 0.0
    assert data["perfect_recall"] == 1.0
