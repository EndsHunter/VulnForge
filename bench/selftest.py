"""Invariants for the offline scorecard. No network."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from bench.adapters import parse_disprove, survives
from bench.config import load_config
from bench.runner import emit_results, run_bench
from bench.tasks import load_tasks

PACKAGE_DIR = Path(__file__).resolve().parent


def _sharp(payload: dict, difficulty: str) -> dict:
    return payload["models"]["stub-sharp"]["difficulties"][difficulty]


def _mean_recall(payload: dict, model: str, difficulty: str) -> float:
    return payload["models"][model]["difficulties"][difficulty]["mean"]["stages"]["disprove"][
        "recall_at_fpr_le_0.5pct"
    ]


def run_checks() -> list[str]:
    failures: list[str] = []

    def check(cond: bool, message: str) -> None:
        if not cond:
            failures.append(message)

    formed = {"mech": {"formed": True, "reproduced": False}, "verdict": "inconclusive"}
    check(not survives(formed, "disprove"), "inconclusive must not survive disprove")
    formed["verdict"] = "survive"
    check(survives(formed, "disprove"), "explicit survive passes disprove")
    base = {"tokens": 0, "latency_s": 0}
    check(parse_disprove({**base, "verdict_text": "", "error": None, "timed_out": False}) == "inconclusive", "empty verdict")
    check(parse_disprove({**base, "verdict_text": "maybe", "error": None, "timed_out": False}) == "inconclusive", "unparsed verdict")
    check(
        parse_disprove({**base, "verdict_text": '{"verdict":"survive"}', "error": "boom", "timed_out": False})
        == "inconclusive",
        "error overrides survive text",
    )
    check(
        parse_disprove({**base, "verdict_text": '{"verdict":"survive"}', "error": None, "timed_out": True})
        == "inconclusive",
        "timeout overrides survive text",
    )
    check(
        parse_disprove({**base, "verdict_text": '{"verdict":"kill"}', "error": None, "timed_out": False})
        == "kill",
        "kill parses",
    )

    config = load_config(PACKAGE_DIR / "config.yaml")
    tasks = load_tasks()
    with TemporaryDirectory(prefix="vf-bench-cache-") as cache_a, TemporaryDirectory(
        prefix="vf-bench-cache-"
    ) as cache_b:
        first = run_bench(config, tasks, mode="stub", cache_dir=Path(cache_a))
        second = run_bench(config, tasks, mode="stub", cache_dir=Path(cache_b))
    check(first == second, "stub scorecard is not deterministic")
    payload = first
    check(payload["mode"] == "stub", "mode")
    check(payload["scores_are_synthetic"] is True, "synthetic flag")
    check(payload["llm_judge"] is None, "llm judge headline")
    check(payload["headline_metric"] == "recall_at_fpr_le_0.5pct", "headline")
    check(payload["wrote_results"] is False, "stub wrote results flag")
    check(payload["k"] >= 3, "k")
    check(payload["seed"]["pairs"] == 8 and payload["seed"]["benign"] == 4, "seed size")
    check("BigVul" in payload["seed"]["excluded_label_sets"], "label policy")
    check(any(task["split"] == "held_out" for task in payload["seed"]["tasks"]), "held_out")
    check(
        payload["cache_misses"] > payload["cache_hits"] > 0,
        "successes are cached and errors are not",
    )
    check(not (PACKAGE_DIR / "results").exists(), "bench/results was created")

    sharp = _mean_recall(payload, "stub-sharp", "L0")
    noisy = _mean_recall(payload, "stub-noisy", "L0")
    blind = _mean_recall(payload, "stub-blind", "L0")
    check(sharp > noisy > blind, f"recall order {sharp} {noisy} {blind}")

    ci = _sharp(payload, "L0")["ci95"]["recall_at_fpr_le_0.5pct"]
    check(ci["n"] >= 3 and ci["low"] < ci["mean"] < ci["high"], "sharp CI")
    blind_ci = payload["models"]["stub-blind"]["difficulties"]["L0"]["ci95"][
        "recall_at_fpr_le_0.5pct"
    ]
    check(blind_ci["low"] <= blind_ci["mean"] <= blind_ci["high"], "blind CI")

    noisy_rep = payload["models"]["stub-noisy"]["difficulties"]["L0"]["repeats"][0]
    outcomes = noisy_rep["stages"]["disprove"]["pair_outcomes"]
    check(outcomes["both_vulnerable"] >= 1, "both-sides pair outcome")
    check(outcomes["reversed"] >= 1, "reversed pair outcome")
    check(noisy_rep["gates"]["human"] is None, "human gate")
    check(noisy_rep["disprove_health"]["inconclusive"] > 0, "inconclusive count")
    check(noisy_rep["poc_false_signal_rate"] > 0, "poc false signal")
    check(noisy_rep["path_contract_validity_rate"] < 1, "invalid contract")
    check(
        payload["models"]["stub-noisy"]["difficulties"]["L0"]["verdict_flip_rate"] > 0,
        "verdict flip",
    )
    frr = payload["models"]["stub-noisy"]["difficulties"]["L0"]["mean"]["gates"]["disprove"][
        "false_reject_rate"
    ]
    check(frr > payload["disprove_gate"]["false_reject_max"], "false-reject threshold")
    check(any("stub-noisy" in warning for warning in payload["warnings"]), "warn on breach")

    sharp_rep = _sharp(payload, "L0")["repeats"][0]
    check(sharp_rep["dup_rate"] > 0, "dup rate")
    check(sharp_rep["path_contract_validity_rate"] == 1, "sharp contracts")
    check(sharp_rep["poc_false_signal_rate"] == 0, "sharp poc signals")
    check("CWE-89" in sharp_rep["stages"]["disprove"]["recall_per_class"], "recall per class")
    check(set(sharp_rep["stages"]) == {"hunt_raw", "mech_formed", "mech_reproduced", "disprove"}, "stages")
    check(sharp_rep["efficiency"]["findings_per_1k_tokens"] > 0, "findings per 1k")
    check(sharp_rep["cutoff"]["pre"]["recall"] > sharp_rep["cutoff"]["post"]["recall"], "cutoff view")
    check("held_out" in sharp_rep["splits"], "split view")
    union = _sharp(payload, "L0")["union_at_n"]
    check(union["3"] >= union["1"], "union@N")

    blind_rep = payload["models"]["stub-blind"]["difficulties"]["L0"]["repeats"][0]
    check(blind_rep["efficiency"]["errors"] > 0, "blind errors")
    check(blind_rep["efficiency"]["misses"] > 0, "blind misses")
    check("pair-sqli" in blind_rep["error_task_ids"], "error task")
    check("pair-sqli" not in blind_rep["miss_task_ids"], "error is not a miss")
    check("pair-int" in noisy_rep["error_task_ids"], "noisy error task")
    check("pair-int" not in noisy_rep["miss_task_ids"], "noisy error is not a miss")

    check(payload["calibration"]["canary_catch_rate"] == 1, "canary catch")
    check(payload["calibration"]["canary_true_pass"] is True, "canary true pass")
    check("inbox_precision" in payload["not_measured"], "inbox not faked")
    check("Score vs cost" in payload["pareto_markdown"], "pareto markdown")
    frontier = [
        point
        for point in payload["pareto"]["points"]
        if point["model"] == "stub-sharp" and point["difficulty"] == "L0"
    ]
    check(bool(frontier) and frontier[0]["on_frontier"], "sharp on pareto frontier")
    check(payload["leaderboard"]["llm_judge"] is None, "leaderboard judge")

    try:
        emit_results(payload, PACKAGE_DIR / "results")
        check(False, "emit_results should refuse stub payloads")
    except RuntimeError:
        pass
    check(not (PACKAGE_DIR / "results").exists(), "refuse path created results")
    return failures


def main() -> int:
    failures = run_checks()
    if failures:
        for item in failures:
            print(item)
        return 1
    print("bench self-test ok")
    return 0
