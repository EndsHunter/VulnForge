import json

import pytest

from bench.cli import main
from bench.config import BenchConfig, ModelSpec
from bench.score import (
    PAIRED_RECALL_NOTE,
    YOUDEN_FEW_NEGATIVES,
    _sweep,
    average_tree,
    build_scorecard,
)
from bench.selftest import run_checks
from bench.tasks import load_tasks


def test_stub_scorecard_invariants():
    failures = run_checks()
    assert failures == []


def _hit() -> dict:
    return {
        "stable_key": "sink",
        "confidence": 0.9,
        "verdict": "survive",
        "disprove_timeout": False,
        "disprove_error": False,
        "disprove_tokens": 0,
        "disprove_latency_s": 0.0,
        "mech": {
            "oracle_hit": True,
            "formed": True,
            "reproduced": True,
            "path_contract_valid": True,
            "poc_signal": False,
        },
    }


def _attempt(task_id: str, side: str, repeat: int, *, error: str | None) -> dict:
    return {
        "model": "m",
        "knowledge_cutoff": "2024-01-01",
        "repeat": repeat,
        "difficulty": "L0",
        "task_id": task_id,
        "side": side,
        "error": error,
        "timed_out": False,
        "tokens": 1,
        "latency_s": 0.0,
        "t_offset_s": 0.0,
        "findings": [] if error else ([_hit()] if side == "vulnerable" else []),
    }


def test_scorecard_unions_cwe_keys_when_repeats_differ():
    """Repeat 1 has CWE-89 and CWE-287, repeat 2 only CWE-89, repeat 3 CWE-89 and CWE-79."""
    rows = [
        {
            "recall_per_class": {"CWE-89": 1.0, "CWE-287": 0.5},
            "counts": {"CWE-89": 2, "CWE-287": 1},
            "precision": 0.5,
            "zero_rate": 0.0,
        },
        {
            "recall_per_class": {"CWE-89": 0.0},
            "counts": {"CWE-89": 0},
            "precision": None,
            "zero_rate": 0.0,
        },
        {
            "recall_per_class": {"CWE-89": 0.5, "CWE-79": 1.0},
            "counts": {"CWE-89": 1, "CWE-79": 4},
            "precision": 1.0,
            "zero_rate": 1.0,
        },
    ]
    mean = average_tree(rows)
    recall = mean["recall_per_class"]
    counts = mean["counts"]
    assert set(recall) == {"CWE-89", "CWE-287", "CWE-79", "_contributed"}
    assert recall["CWE-89"] == pytest.approx(0.5)
    assert recall["_contributed"]["CWE-89"] == 3
    assert recall["CWE-287"] == pytest.approx(0.5)
    assert recall["_contributed"]["CWE-287"] == 1
    assert recall["CWE-79"] == pytest.approx(1.0)
    assert recall["_contributed"]["CWE-79"] == 1
    assert counts["CWE-89"] == pytest.approx(1.0)
    assert counts["CWE-287"] == pytest.approx(1 / 3)
    assert counts["CWE-79"] == pytest.approx(4 / 3)
    assert counts["_contributed"] == {"CWE-89": 3, "CWE-287": 3, "CWE-79": 3}
    assert mean["precision"] == pytest.approx(0.75)
    assert mean["_contributed"]["precision"] == 2
    assert mean["zero_rate"] == pytest.approx(1 / 3)
    assert mean["_contributed"]["zero_rate"] == 3

    present = {
        0: {"pair-sqli", "pair-auth"},
        1: {"pair-sqli"},
        2: {"pair-sqli", "pair-xss"},
    }
    tasks = [task for task in load_tasks() if task.id in {"pair-sqli", "pair-auth", "pair-xss"}]
    attempts = []
    for repeat, ok in present.items():
        for task in tasks:
            error = None if task.id in ok else "unparsed hunt response"
            for side in ("vulnerable", "fixed"):
                attempts.append(_attempt(task.id, side, repeat, error=error))
    card = build_scorecard(
        attempts,
        tasks,
        mode="live",
        k=3,
        workers=1,
        fpr_cap=0.005,
        false_reject_max=0.10,
        on_breach="warn",
        cache_hits=0,
        cache_misses=0,
    )
    stage = card["models"]["m"]["difficulties"]["L0"]["mean"]["stages"]["disprove"]
    classes = stage["recall_per_class"]
    assert set(classes) == {"CWE-89", "CWE-287", "CWE-79", "_contributed"}
    assert classes["CWE-89"] == pytest.approx(1.0)
    assert classes["_contributed"]["CWE-89"] == 3
    assert classes["CWE-287"] == pytest.approx(1.0)
    assert classes["_contributed"]["CWE-287"] == 1
    assert classes["CWE-79"] == pytest.approx(1.0)
    assert classes["_contributed"]["CWE-79"] == 1
    assert stage["precision"] == pytest.approx(1.0)
    assert stage["vd_s"] == stage["recall_at_fpr_le_0.5pct"]
    assert stage["youden"] is not None
    board = card["leaderboard"]
    assert board["scored_row_count"] == 1
    assert board["infra_error_row_count"] == 0
    assert board["rows"][0]["excluded"] is False
    assert board["rows"][0]["vd_s"] == board["rows"][0]["recall_at_fpr_le_0.5pct"]


def test_vd_s_is_recall_at_fpr_le_half_percent():
    positives = [
        {"score": 0.9, "companion": 0.0},
        {"score": 0.5, "companion": 0.0},
        {"score": 0.05, "companion": 0.0},
    ]
    negatives = [{"score": 0.2} for _ in range(200)]
    row = _sweep(positives, negatives, 0.005)
    assert row["fpr_at_operating_point"] <= 0.005
    assert row["vd_s"] == pytest.approx(2 / 3)
    assert row["vd_s"] == row["recall_at_fpr_le_0.5pct"]
    assert row["fpr_at_operating_point"] == 0
    assert row["youden"] == pytest.approx(2 / 3)


def test_youden_differs_from_vd_s_when_operating_fpr_is_nonzero():
    """Youden is TPR-FPR. VD-S is recall at the FPR cap. They match only when that FPR is 0."""
    positives = [
        {"score": 0.9, "companion": 0.0},
        {"score": 0.7, "companion": 0.0},
    ]
    negatives = [{"score": 0.8}] + [{"score": 0.0} for _ in range(999)]
    row = _sweep(positives, negatives, 0.005)
    assert 0 < row["fpr_at_operating_point"] <= 0.005
    assert row["vd_s"] == pytest.approx(1.0)
    assert row["recall_at_fpr_le_0.5pct"] == row["vd_s"]
    assert row["youden"] == pytest.approx(row["vd_s"] - row["fpr_at_operating_point"])
    assert row["youden"] != pytest.approx(row["vd_s"])


def test_youden_ignores_thresholds_that_break_the_fpr_cap():
    """A high TPR minus a still-too-high FPR is not Youden for this scorecard."""
    positives = [{"score": 0.9, "companion": 0.0} for _ in range(10)]
    negatives = [{"score": 0.9} for _ in range(2)] + [{"score": 0.0} for _ in range(8)]
    row = _sweep(positives, negatives, 0.005)
    assert row["recall_at_fpr_le_0.5pct"] == 0
    assert row["vd_s"] == 0
    assert row["youden"] == 0
    assert row["fpr_at_operating_point"] <= 0.005


def _board_row(attempts: list[dict], tasks: list) -> tuple[dict, dict]:
    card = build_scorecard(
        attempts,
        tasks,
        mode="live",
        k=1,
        workers=1,
        fpr_cap=0.005,
        false_reject_max=0.10,
        on_breach="warn",
        cache_hits=0,
        cache_misses=0,
    )
    row = card["leaderboard"]["rows"][0]
    stage = card["models"]["m"]["difficulties"]["L0"]["repeats"][0]["stages"]["disprove"]
    return row, stage


def _finding(confidence: float, *, oracle_hit: bool) -> dict:
    finding = _hit()
    finding["confidence"] = confidence
    finding["mech"] = dict(finding["mech"])
    finding["mech"]["oracle_hit"] = oracle_hit
    return finding


def test_headline_recall_is_zero_when_every_threshold_breaks_the_cap():
    pair = next(task for task in load_tasks() if task.id == "pair-sqli")
    benign = next(task for task in load_tasks() if task.kind == "benign")
    attempts = [
        _attempt(pair.id, "vulnerable", 0, error=None),
        _attempt(pair.id, "fixed", 0, error=None),
        _attempt(benign.id, "benign", 0, error=None),
    ]
    attempts[0]["findings"] = [_finding(0.9, oracle_hit=True)]
    attempts[1]["findings"] = []
    attempts[2]["findings"] = [_finding(0.95, oracle_hit=False)]
    row, stage = _board_row(attempts, [pair, benign])
    assert stage["fpr"] > 0.005
    assert row["recall_at_fpr_le_0.5pct"] == 0
    assert row["vd_s"] == row["recall_at_fpr_le_0.5pct"]
    assert row["youden"] == YOUDEN_FEW_NEGATIVES
    assert row["youden_in_ranking"] is False
    assert row["fpr"] is not None and row["fpr"] <= 0.005


def test_headline_fpr_is_the_capped_operating_point():
    pair = next(task for task in load_tasks() if task.id == "pair-sqli")
    benign = next(task for task in load_tasks() if task.kind == "benign")
    attempts = [
        _attempt(pair.id, "vulnerable", 0, error=None),
        _attempt(pair.id, "fixed", 0, error=None),
        _attempt(benign.id, "benign", 0, error=None),
    ]
    attempts[0]["findings"] = [_finding(0.9, oracle_hit=True)]
    attempts[1]["findings"] = []
    attempts[2]["findings"] = [_finding(0.2, oracle_hit=False)]
    row, stage = _board_row(attempts, [pair, benign])
    assert stage["fpr"] > 0.005
    assert row["recall_at_fpr_le_0.5pct"] == pytest.approx(1.0)
    assert row["vd_s"] == row["recall_at_fpr_le_0.5pct"]
    assert row["fpr"] <= 0.005
    assert row["youden"] == YOUDEN_FEW_NEGATIVES
    assert row["youden_in_ranking"] is False


def test_operating_point_fpr_cannot_exceed_the_cap():
    """Eligible points are filtered before selection, so a cap breach is not a score."""
    cases = [
        ([{"score": 0.9, "companion": 0.0}], [{"score": 0.9}]),
        (
            [{"score": 0.9, "companion": 0.0}, {"score": 0.7, "companion": 0.0}],
            [{"score": 0.8}] + [{"score": 0.0} for _ in range(999)],
        ),
        ([], [{"score": 0.2} for _ in range(12)]),
        ([{"score": 0.9, "companion": 0.0} for _ in range(8)], [{"score": 0.0} for _ in range(12)]),
        ([], []),
    ]
    for positives, negatives in cases:
        row = _sweep(positives, negatives, 0.005)
        assert row["fpr_at_operating_point"] is None or row["fpr_at_operating_point"] <= 0.005


def test_youden_on_real_seed_size_is_not_ranked():
    tasks = load_tasks()
    n_neg = sum(task.kind == "pair" for task in tasks) + sum(task.kind == "benign" for task in tasks)
    assert n_neg == 12
    assert 1 / n_neg > 0.005
    attempts = []
    for task in tasks:
        sides = ("vulnerable", "fixed") if task.kind == "pair" else ("benign",)
        for side in sides:
            attempt = _attempt(task.id, side, 0, error=None)
            attempt["findings"] = (
                [_finding(0.9, oracle_hit=True)] if side == "vulnerable" else []
            )
            attempts.append(attempt)
    card = build_scorecard(
        attempts,
        tasks,
        mode="live",
        k=1,
        workers=1,
        fpr_cap=0.005,
        false_reject_max=0.10,
        on_breach="warn",
        cache_hits=0,
        cache_misses=0,
    )
    row = card["leaderboard"]["rows"][0]
    assert row["youden"] == YOUDEN_FEW_NEGATIVES
    assert row["youden_in_ranking"] is False
    assert row["vd_s"] == row["recall_at_fpr_le_0.5pct"]
    ranked = sorted(
        card["leaderboard"]["rows"],
        key=lambda item: (item["difficulty"], -item["recall_at_fpr_le_0.5pct"], item["model"]),
    )
    assert [item["rank"] for item in card["leaderboard"]["rows"]] == list(
        range(1, len(ranked) + 1)
    )


def _two_pair_card(attempts: list[dict], tasks: list) -> tuple[dict, dict, dict]:
    card = build_scorecard(
        attempts,
        tasks,
        mode="live",
        k=1,
        workers=1,
        fpr_cap=0.005,
        false_reject_max=0.10,
        on_breach="warn",
        cache_hits=0,
        cache_misses=0,
    )
    stage = card["models"]["m"]["difficulties"]["L0"]["repeats"][0]["stages"]["disprove"]
    mean = card["models"]["m"]["difficulties"]["L0"]["mean"]["stages"]["disprove"]
    return card, stage, mean


def test_errored_pair_lowers_the_full_denominator_only():
    tasks = [task for task in load_tasks() if task.id in {"pair-sqli", "pair-auth"}]
    attempts = []
    for task in tasks:
        for side in ("vulnerable", "fixed"):
            if task.id == "pair-auth" and side == "fixed":
                row = _attempt(task.id, side, 0, error="timeout")
                row["timed_out"] = True
                row["cached_failure"] = True
            elif task.id == "pair-sqli" and side == "vulnerable":
                row = _attempt(task.id, side, 0, error=None)
                row["findings"] = [_finding(0.9, oracle_hit=True)]
            else:
                row = _attempt(task.id, side, 0, error=None)
                row["findings"] = []
            attempts.append(row)
    card, stage, mean = _two_pair_card(attempts, tasks)
    row = card["leaderboard"]["rows"][0]
    assert stage["pairs_lost"] == 1
    assert stage["recall_label"] == "surviving-pairs"
    assert stage["recall"] == pytest.approx(1.0)
    assert stage["recall_at_fpr_le_0.5pct"] == pytest.approx(1.0)
    assert stage["recall_lower_bound"] == pytest.approx(0.5)
    assert stage["recall_at_fpr_lower_bound"] == pytest.approx(0.5)
    assert mean["pairs_lost"] == 1
    assert mean["pair_runs"] == 2
    assert mean["recall_lower_bound"] == pytest.approx(0.5)
    assert row["pairs_lost"] == 1
    assert row["pair_runs"] == 2
    assert row["recall_lower_bound"] == pytest.approx(0.5)
    assert row["recall_at_fpr_lower_bound"] == pytest.approx(0.5)
    assert row["negatives_lost"] == 1
    assert row["recall_label"] == "surviving-pairs"
    assert "completed negatives" in row["fpr_label"]
    assert "not hits" in card["cache_hits_label"]
    assert "including stored failure records" in card["cache_coverage_label"]


def test_paired_recall_is_not_monotonic_and_the_note_is_present():
    pairs = [task for task in load_tasks() if task.id in {"pair-sqli", "pair-auth"}]
    benigns = [task for task in load_tasks() if task.kind == "benign"]
    assert len(benigns) == 4
    tasks = pairs + benigns
    attempts = []
    for task in tasks:
        if task.kind == "benign":
            row = _attempt(task.id, "benign", 0, error=None)
            row["findings"] = []
            attempts.append(row)
            continue
        for side in ("vulnerable", "fixed"):
            row = _attempt(task.id, side, 0, error=None)
            if task.id == "pair-sqli" and side == "vulnerable":
                row["findings"] = [_finding(0.9, oracle_hit=True)]
            elif task.id == "pair-sqli" and side == "fixed":
                row["findings"] = [_finding(0.3, oracle_hit=False)]
            else:
                row["findings"] = []
            attempts.append(row)
    card, stage, _mean = _two_pair_card(attempts, tasks)
    assert stage["recall"] == pytest.approx(0.0)
    assert stage["recall_at_fpr_le_0.5pct"] == pytest.approx(0.5)
    assert card["paired_recall_note"] == PAIRED_RECALL_NOTE


def test_fixed_side_errors_are_counted_with_text():
    pair = next(task for task in load_tasks() if task.id == "pair-auth")
    vulnerable = _attempt(pair.id, "vulnerable", 0, error=None)
    fixed = _attempt(pair.id, "fixed", 0, error="timeout")
    fixed["timed_out"] = True
    fixed["error_kind"] = "timeout"
    card = build_scorecard(
        [vulnerable, fixed],
        [pair],
        mode="live",
        k=1,
        workers=1,
        fpr_cap=0.005,
        false_reject_max=0.10,
        on_breach="warn",
        cache_hits=0,
        cache_misses=0,
    )
    repeat = card["models"]["m"]["difficulties"]["L0"]["repeats"][0]
    assert repeat["error_task_ids"] == ["pair-auth"]
    assert repeat["attempt_errors"] == [
        {
            "task_id": "pair-auth",
            "side": "fixed",
            "error": "timeout",
            "error_kind": "timeout",
        }
    ]


def _one_model_config() -> BenchConfig:
    return BenchConfig(
        models=[ModelSpec(id="glm-id", name="Pretty GLM", knowledge_cutoff="2024-08-01")],
        k=1,
        workers=1,
        difficulties=["L0"],
        timeout_s=0.01,
    )


def test_score_from_cache_rebuilds_without_model_calls(tmp_path, monkeypatch):
    from bench.runner import run_bench

    cache = tmp_path / "cache"
    config = _one_model_config()
    tasks = load_tasks()
    calls = {"n": 0}

    def transport(model, messages):
        del model, messages
        calls["n"] += 1
        return {
            "error": None,
            "timed_out": False,
            "text": '{"findings":[]}',
            "tokens": 4,
            "latency_s": 0.0,
        }

    first = run_bench(config, tasks, mode="live", cache_dir=cache, transport=transport)
    assert calls["n"] > 0

    def explode(*_args, **_kwargs):
        raise AssertionError("model call")

    monkeypatch.setattr("bench.runner.live_hunt", explode)
    monkeypatch.setattr("bench.runner.scripted_hunt", explode)
    monkeypatch.setattr("bench.runner.chat", explode)
    second = run_bench(config, tasks, mode="live", cache_dir=cache, from_cache=True)
    assert first["cache_hits"] == 0
    assert second["cache_misses"] == 0
    assert second["cache_hits"] == calls["n"]
    assert second["models"] == first["models"]
    assert second["leaderboard"]["rows"] == first["leaderboard"]["rows"]
    assert second["leaderboard"]["partial"] is False
    assert second["leaderboard"]["cache_coverage"] == 1
    assert second["wrote_results"] is False


def test_cli_score_from_cache_uses_temp_cache(tmp_path, monkeypatch, capsys):
    from bench.runner import run_bench

    cache = tmp_path / "cache"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "base_url: http://127.0.0.1:9/v1",
                "models:",
                "  - id: glm-id",
                "    name: Pretty GLM",
                '    knowledge_cutoff: "2024-08-01"',
                "k: 1",
                "workers: 1",
                "timeout_s: 0.01",
                "difficulties:",
                "  - L0",
                "prompt_version: bench-1",
                "disprove:",
                "  false_reject_max: 0.10",
                "  on_breach: warn",
                "",
            ]
        ),
        encoding="utf-8",
    )
    run_bench(
        _one_model_config(),
        load_tasks(),
        mode="live",
        cache_dir=cache,
        transport=lambda model, messages: {
            "error": None,
            "timed_out": False,
            "text": '{"findings":[]}',
            "tokens": 4,
            "latency_s": 0.0,
        },
    )

    def explode(*_args, **_kwargs):
        raise AssertionError("model call")

    monkeypatch.setattr("bench.runner.live_hunt", explode)
    monkeypatch.setattr("bench.runner.scripted_hunt", explode)
    monkeypatch.setattr("bench.runner.chat", explode)
    code = main(
        [
            "score",
            "--from-cache",
            "--config",
            str(config_path),
            "--cache-dir",
            str(cache),
            "--mode",
            "live",
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["cache_misses"] == 0
    assert payload["cache_hits"] > 0
    assert payload["wrote_results"] is False
    assert payload["mode"] == "live"
    stage = payload["models"]["glm-id"]["difficulties"]["L0"]["mean"]["stages"]["disprove"]
    assert "precision" in stage
    assert "recall_per_class" in stage
    assert stage["vd_s"] == stage["recall_at_fpr_le_0.5pct"]
    assert "youden" in stage
    board = payload["leaderboard"]
    assert board["scored_row_count"] + board["infra_error_row_count"] == len(board["rows"])
