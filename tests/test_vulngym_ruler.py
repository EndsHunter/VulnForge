"""VulnGym slice ruler: empty vs perfect, line slop, class map."""

import json
import subprocess
import sys
from pathlib import Path

from vulnforge.eval.recall import load_ground_truth, parse_line_number, score_findings
from vulnforge.eval.vulngym import SLICE_IDS, SLICE_PATH, map_hunt_class
from vulnforge.paths import PROJECT_ROOT

EVAL_SCRIPT = PROJECT_ROOT / "scripts" / "eval_vulngym.py"


def test_parse_line_ranges():
    assert parse_line_number(348) == 348
    assert parse_line_number("493-494") == 493
    assert parse_line_number("263-266") == 263
    assert parse_line_number(None) is None


def test_class_map_authz_and_cmdi():
    assert map_hunt_class("业务逻辑", "BL-AUTHZ-MISSING(授权缺失)") == "access-control"
    assert map_hunt_class("命令注入", "OS 命令注入") == "injection"
    assert map_hunt_class("业务逻辑", "BL-ORIGIN-INTEGRITY(来源/签名/完整性校验缺失)") == "web-protocol-auth"
    assert map_hunt_class("业务逻辑", "BL-RACE-LOGIC(业务层竞争条件)") == "business-logic"
    assert map_hunt_class("业务逻辑", "BL-MULTI-TENANT(多租户/隔离失效)") == "access-control"


def test_slice_file_frozen():
    gt = load_ground_truth(SLICE_PATH)
    ids = [str(o["id"]) for o in gt["findings"]]
    assert ids == list(SLICE_IDS)
    assert len(gt["findings"]) == 6
    for o in gt["findings"]:
        assert o["sink_path"]
        assert o["match"]["start_line"]
        assert o["class"] in {
            "access-control",
            "injection",
            "web-protocol-auth",
            "business-logic",
        }


def _perfect(oracles):
    bodies = []
    for o in oracles:
        path = str(o["sink_path"])
        line = o["match"]["start_line"]
        bodies.append(
            {
                "sink_path": path,
                "citations": [{"path": path, "start_line": line}],
            }
        )
    return bodies


def test_empty_is_zero():
    gt = load_ground_truth(SLICE_PATH)
    sc = score_findings([], gt["findings"])
    assert sc["recall"] == 0.0


def test_perfect_is_one():
    gt = load_ground_truth(SLICE_PATH)
    sc = score_findings(_perfect(gt["findings"]), gt["findings"])
    assert sc["recall"] == 1.0
    assert sc["misses"] == []


def test_wrong_line_is_miss():
    gt = load_ground_truth(SLICE_PATH)
    o = gt["findings"][0]
    path = o["sink_path"]
    far = int(o["match"]["start_line"]) + 80
    sc = score_findings(
        [{"sink_path": path, "citations": [{"path": path, "start_line": far}]}],
        [o],
    )
    assert sc["recall"] == 0.0


def test_citation_range_covers_oracle_line():
    gt = load_ground_truth(SLICE_PATH)
    o = gt["findings"][0]
    path = o["sink_path"]
    want = int(o["match"]["start_line"])
    sc = score_findings(
        [
            {
                "sink_path": path,
                "citations": [
                    {"path": path, "start_line": want - 9, "end_line": want}
                ],
            }
        ],
        [o],
    )
    assert sc["recall"] == 1.0


def test_line_within_slop_hits():
    gt = load_ground_truth(SLICE_PATH)
    o = gt["findings"][0]
    path = o["sink_path"]
    near = int(o["match"]["start_line"]) + 3
    sc = score_findings(
        [{"sink_path": path, "citations": [{"path": path, "start_line": near}]}],
        [o],
    )
    assert sc["recall"] == 1.0


def test_sensitivity_cli():
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


def test_eval_script_endpoint_flags_and_python():
    import scripts.eval_vulngym as ev

    help_r = subprocess.run(
        [sys.executable, str(EVAL_SCRIPT), "--help"],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert help_r.returncode == 0, help_r.stderr or help_r.stdout
    assert "--host" in help_r.stdout
    assert "--model" in help_r.stdout
    ev.set_endpoint("192.168.80.4", "11434", "ornith-1.5:35b")
    assert ev.MODEL_HOST == "192.168.80.4"
    assert ev.MODEL_PORT == "11434"
    assert ev.MODEL_ID == "ornith-1.5:35b"
    py = ev._python()
    assert py
    assert Path(py).name.lower().startswith("python")
