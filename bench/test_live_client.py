"""Fake-transport checks for the live client. No network."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from bench.config import BenchConfig, ModelSpec
from bench.runner import _cache_key, chat, run_bench
from bench.tasks import Task, load_tasks

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
    assert row["vd_s"] is None
    assert row["tokens"] == 0
    assert payload["leaderboard"]["infra_error_row_count"] == 1
    assert payload["leaderboard"]["scored_row_count"] == 0
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
    assert row["vd_s"] == 0.0
    assert row["rank"] == 1
    assert payload["leaderboard"]["scored_row_count"] == 1
    assert payload["leaderboard"]["infra_error_row_count"] == 0


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


def _cache_key_for(config: BenchConfig, task: Task, side: str) -> str:
    return _cache_key(
        {
            "mode": "live",
            "prompt_version": config.prompt_version,
            "model": config.models[0].id,
            "repeat": 0,
            "difficulty": "L0",
            "task": task.id,
            "side": side,
            "content_hash": task.content_hash,
        }
    )


def test_cache_hits_are_counted_when_they_happen():
    tasks = load_tasks()
    config = _config()
    with TemporaryDirectory() as cache:
        fresh = run_bench(
            config, tasks, mode="live", cache_dir=Path(cache), transport=lambda model, messages: _ok()
        )
        assert fresh["cache_hits"] == 0
        assert fresh["cache_misses"] == 20
        warm = run_bench(
            config, tasks, mode="live", cache_dir=Path(cache), transport=lambda model, messages: _ok()
        )
    assert warm["cache_hits"] == 20
    assert warm["cache_misses"] == 0


def test_failed_jobs_are_stored_and_retried_live():
    calls = {"n": 0}

    def transport(model, messages):
        del model, messages
        calls["n"] += 1
        return _http(500)

    tasks = load_tasks()
    config = _config()
    with TemporaryDirectory() as cache:
        cache_path = Path(cache)
        run_bench(config, tasks, mode="live", cache_dir=cache_path, transport=transport)
        stored = [json.loads(path.read_text(encoding="utf-8")) for path in cache_path.glob("*.json")]
        assert stored
        assert all(item["cached_failure"] is True for item in stored)
        assert all(item["error_kind"] == "hunt_error" for item in stored)
        assert all(item["error"] == "http 500" for item in stored)
        first = calls["n"]
        run_bench(config, tasks, mode="live", cache_dir=cache_path, transport=transport)
    assert first == 20
    assert calls["n"] == first * 2


def test_from_cache_counts_stored_errors_as_infra(monkeypatch):
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
        if messages[0]["content"].startswith("You judge"):
            return _http(502)
        return _ok(text=json.dumps({"findings": [finding]}), tokens=6)

    tasks = load_tasks()
    config = _config()
    with TemporaryDirectory() as cache:
        cache_path = Path(cache)
        run_bench(config, tasks, mode="live", cache_dir=cache_path, transport=transport)
        stored = [json.loads(path.read_text(encoding="utf-8")) for path in cache_path.glob("*.json")]
        assert stored
        assert all(item["error_kind"] == "disprove_error" for item in stored)
        assert all(item["error"] == "http 502" for item in stored)

        def explode(*_args, **_kwargs):
            raise AssertionError("model call")

        monkeypatch.setattr("bench.runner.live_hunt", explode)
        monkeypatch.setattr("bench.runner.chat", explode)
        payload = run_bench(config, tasks, mode="live", cache_dir=cache_path, from_cache=True)
    board = payload["leaderboard"]
    assert payload["cache_misses"] == 0
    assert payload["partial"] is False
    assert board["cache_miss_count"] == 0
    assert board["cache_coverage"] == 1
    assert board["stored_failure_count"] == 20
    assert payload["stored_failure_count"] == 20
    assert board["infra_error_count"] == 20
    assert board["infra_error_row_count"] == 1
    assert board["partial"] is False


def _scored_card(payload: dict) -> dict:
    """Drop lookup counters. A live run and a rescore count hits differently."""
    body = json.loads(json.dumps(payload))
    for key in ("cache_hits", "cache_misses", "cache_coverage"):
        body.pop(key, None)
    board = body["leaderboard"]
    board.pop("cache_coverage", None)
    board.pop("cache_miss_count", None)
    board.pop("cache_misses_by_side", None)
    return body


def test_disprove_failure_scores_identically_live_and_from_cache():
    finding = {
        "path": "query.py",
        "line": 1,
        "symbol": "lookup_user",
        "cwe": "CWE-89",
        "confidence": 0.2,
        "evidence": "conn.execute(sql)",
        "path_contract": ["lookup_user"],
    }
    calls = {"n": 0}

    def transport(model, messages):
        del model
        calls["n"] += 1
        if messages[0]["content"].startswith("You judge"):
            return _http(502)
        return _ok(text=json.dumps({"findings": [finding]}), tokens=6)

    tasks = load_tasks()
    config = _config()
    with TemporaryDirectory() as cache:
        cache_path = Path(cache)
        live = run_bench(config, tasks, mode="live", cache_dir=cache_path, transport=transport)
        first = calls["n"]
        cached = run_bench(config, tasks, mode="live", cache_dir=cache_path, from_cache=True)
    assert calls["n"] == first
    assert live["leaderboard"]["stored_failure_count"] == 20
    assert cached["leaderboard"]["stored_failure_count"] == 20
    assert cached["leaderboard"]["cache_coverage"] == 1
    assert _scored_card(live) == _scored_card(cached)
    repeat = live["models"]["glm-id"]["difficulties"]["L0"]["repeats"][0]
    assert repeat["attempt_errors"]
    assert all(item["error"] == "http 502" for item in repeat["attempt_errors"])


def test_incomplete_cache_is_partial_with_per_side_misses(monkeypatch):
    tasks = load_tasks()
    config = _config()
    pair = next(task for task in tasks if task.kind == "pair")
    benign = next(task for task in tasks if task.kind == "benign")
    with TemporaryDirectory() as cache:
        cache_path = Path(cache)
        run_bench(
            config,
            tasks,
            mode="live",
            cache_dir=cache_path,
            transport=lambda model, messages: _ok(),
        )
        for task, side in (
            (pair, "vulnerable"),
            (pair, "fixed"),
            (benign, "benign"),
        ):
            (cache_path / f"{_cache_key_for(config, task, side)}.json").unlink()

        def explode(*_args, **_kwargs):
            raise AssertionError("model call")

        monkeypatch.setattr("bench.runner.live_hunt", explode)
        monkeypatch.setattr("bench.runner.chat", explode)
        payload = run_bench(config, tasks, mode="live", cache_dir=cache_path, from_cache=True)
    board = payload["leaderboard"]
    assert payload["partial"] is True
    assert board["partial"] is True
    assert board["cache_miss_count"] == 3
    assert board["cache_misses_by_side"] == {"vulnerable": 1, "fixed": 1, "benign": 1}
    assert payload["cache_coverage"] == 17 / 20
    assert board["infra_error_count"] == 0
    assert any(warning.startswith("INCOMPLETE CACHE") for warning in payload["warnings"])


def test_max_inflight_caps_worker_fanout(monkeypatch):
    state = {"inflight": 0, "peak": 0, "calls": 0}
    lock = threading.Lock()

    def transport(model, messages):
        del model, messages
        with lock:
            state["inflight"] += 1
            state["calls"] += 1
            state["peak"] = max(state["peak"], state["inflight"])
        time.sleep(0.05)
        with lock:
            state["inflight"] -= 1
        return _ok()

    def fanout(config, model, task, side, difficulty, transport=None):
        del task, side, difficulty
        errors: list[BaseException] = []

        def one() -> None:
            try:
                chat(
                    config,
                    model,
                    [{"role": "user", "content": "fanout"}],
                    transport=transport,
                )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=one) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        if errors:
            raise errors[0]
        return {
            "error": None,
            "timed_out": False,
            "tokens": 0,
            "latency_s": 0.0,
            "findings": [],
        }

    monkeypatch.setattr("bench.runner.live_hunt", fanout)
    config = _config()
    config.base_url = "http://inflight-test.example/v1"
    config.workers = 6
    config.max_inflight = 3
    config.k = 3
    tasks = [task for task in load_tasks() if task.kind == "benign"][:2]
    with TemporaryDirectory() as cache:
        run_bench(config, tasks, mode="live", cache_dir=Path(cache), transport=transport)
    assert state["calls"] == 6 * 4
    assert state["peak"] == config.max_inflight


def test_cli_partial_cache_exits_2(tmp_path, monkeypatch, capsys):
    from bench.cli import main

    tasks = load_tasks()
    config = _config()
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
                "max_inflight: 4",
                "disprove:",
                "  false_reject_max: 0.10",
                "  on_breach: warn",
                "",
            ]
        ),
        encoding="utf-8",
    )
    run_bench(
        config,
        tasks,
        mode="live",
        cache_dir=cache,
        transport=lambda model, messages: _ok(),
    )
    pair = next(task for task in tasks if task.kind == "pair")
    (cache / f"{_cache_key_for(config, pair, 'fixed')}.json").unlink()

    def explode(*_args, **_kwargs):
        raise AssertionError("model call")

    monkeypatch.setattr("bench.runner.live_hunt", explode)
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
    captured = capsys.readouterr()
    assert code == 2
    assert "INCOMPLETE CACHE" in captured.err
    payload = json.loads(captured.out)
    assert payload["partial"] is True
    assert payload["leaderboard"]["cache_misses_by_side"]["fixed"] == 1
