"""Fake-transport checks for the live client. No network."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from bench.config import BenchConfig, ModelSpec
from bench.runner import run_bench
from bench.tasks import load_tasks

ROOT = Path(__file__).resolve().parents[1]


def _config() -> BenchConfig:
    return BenchConfig(
        models=[ModelSpec(id="glm-id", name="Pretty GLM", knowledge_cutoff="2024-08-01")],
        k=1,
        workers=1,
        difficulties=["L0"],
    )


def _ok(text: str = '{"findings":[]}', tokens: int = 4) -> dict:
    return {
        "error": None,
        "timed_out": False,
        "text": text,
        "tokens": tokens,
        "latency_s": 0.0,
    }


def _http(code: int) -> dict:
    return {
        "error": f"http {code}",
        "timed_out": False,
        "text": "",
        "tokens": 0,
        "latency_s": 0.0,
    }


def _row(payload: dict) -> dict:
    return next(row for row in payload["leaderboard"]["rows"] if row["model"] == "glm-id")


def test_httpx_is_declared():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "httpx>=0.27" in text


def test_live_sends_model_id_not_name():
    seen: list[str] = []

    def transport(model, messages):
        del messages
        seen.append(model)
        return _ok()

    with TemporaryDirectory() as cache:
        run_bench(
            _config(),
            load_tasks(),
            mode="live",
            cache_dir=Path(cache),
            transport=transport,
        )
    assert seen
    assert set(seen) == {"glm-id"}


def test_all_infra_errors_are_excluded():
    def transport(model, messages):
        del model, messages
        return _http(400)

    with TemporaryDirectory() as cache:
        payload = run_bench(
            _config(),
            load_tasks(),
            mode="live",
            cache_dir=Path(cache),
            transport=transport,
        )
    row = _row(payload)
    assert row["recall_at_fpr_le_0.5pct"] is None
    assert row["rank"] is None
    assert row["on_frontier"] is False
    assert row["excluded"] is True
    assert row["exclude_reason"] == "infra_errors"
    assert row["tokens"] == 0
    assert all(point["model"] != "glm-id" for point in payload["pareto"]["points"])
    assert any("excluded" in warning for warning in payload["warnings"])


def test_majority_infra_errors_are_excluded():
    def transport(model, messages):
        del model
        user = messages[-1]["content"]
        if "Task pair-sqli." in user:
            return _ok()
        return _http(503)

    with TemporaryDirectory() as cache:
        payload = run_bench(
            _config(),
            load_tasks(),
            mode="live",
            cache_dir=Path(cache),
            transport=transport,
        )
    row = _row(payload)
    assert row["excluded"] is True
    assert row["recall_at_fpr_le_0.5pct"] is None
    assert row["rank"] is None
    assert row["on_frontier"] is False


def test_a_single_infra_error_still_ranks_as_a_real_zero():
    def transport(model, messages):
        del model
        user = messages[-1]["content"]
        if "Task pair-int." in user and "Side vulnerable." in user:
            return {
                "error": "connection refused",
                "timed_out": False,
                "text": "",
                "tokens": 0,
                "latency_s": 0.0,
            }
        return _ok(tokens=5)

    with TemporaryDirectory() as cache:
        payload = run_bench(
            _config(),
            load_tasks(),
            mode="live",
            cache_dir=Path(cache),
            transport=transport,
        )
    row = _row(payload)
    assert row["excluded"] is False
    assert row["recall_at_fpr_le_0.5pct"] == 0.0
    assert row["rank"] == 1


def test_http_errors_are_not_replayed_from_cache():
    calls = {"n": 0}

    def transport(model, messages):
        del model, messages
        calls["n"] += 1
        return _http(500)

    tasks = load_tasks()
    config = _config()
    with TemporaryDirectory() as cache:
        run_bench(config, tasks, mode="live", cache_dir=Path(cache), transport=transport)
        first = calls["n"]
        run_bench(config, tasks, mode="live", cache_dir=Path(cache), transport=transport)
    assert first == 20
    assert calls["n"] == first * 2


def test_successful_completions_are_cached():
    calls = {"n": 0}

    def transport(model, messages):
        del model, messages
        calls["n"] += 1
        return _ok()

    tasks = load_tasks()
    config = _config()
    with TemporaryDirectory() as cache:
        run_bench(config, tasks, mode="live", cache_dir=Path(cache), transport=transport)
        first = calls["n"]
        run_bench(config, tasks, mode="live", cache_dir=Path(cache), transport=transport)
    assert first == 20
    assert calls["n"] == first


def test_disprove_http_error_is_not_cached():
    calls = {"n": 0}
    finding = {
        "path": "query.py",
        "line": 1,
        "symbol": "lookup_user",
        "cwe": "CWE-89",
        "confidence": 0.2,
        "evidence": "conn.execute(sql)",
        "path_contract": ["lookup_user"],
    }

    def transport(model, messages):
        del model
        calls["n"] += 1
        if messages[0]["content"].startswith("You judge"):
            return _http(502)
        return _ok(text=json.dumps({"findings": [finding]}), tokens=6)

    tasks = load_tasks()
    config = _config()
    with TemporaryDirectory() as cache:
        run_bench(config, tasks, mode="live", cache_dir=Path(cache), transport=transport)
        first = calls["n"]
        run_bench(config, tasks, mode="live", cache_dir=Path(cache), transport=transport)
    assert first == 40
    assert calls["n"] == first * 2
