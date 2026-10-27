"""Cached parallel runner. Stub mode never writes bench/results."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from bench.adapters import annotate, parse_model_findings, read_tree_file
from bench.config import BenchConfig
from bench.score import _oracle_for, build_scorecard, freeze
from bench.stub import STUB_MODELS, scripted_hunt
from bench.tasks import Task

PROMPT_RULES = (
    "Report suspected vulnerabilities as a JSON object "
    '{"findings":[{"path":"","line":1,"symbol":"","cwe":"","confidence":0.0,'
    '"evidence":"quote from that line","path_contract":["symbol"]}]} '
    "with no exploit code. An empty list is allowed."
)


class DiskCache:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, key: str) -> Path:
        return self.root / f"{key}.json"

    def get(self, key: str) -> dict | None:
        with self._lock:
            path = self._path(key)
            if not path.is_file():
                return None
            return json.loads(path.read_text(encoding="utf-8"))

    def put(self, key: str, value: dict) -> None:
        with self._lock:
            self._path(key).write_text(json.dumps(value), encoding="utf-8")


def _cache_key(payload: dict) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def _files(root: Path) -> list[tuple[str, str]]:
    rows = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        rel = path.relative_to(root).as_posix()
        rows.append((rel, path.read_text(encoding="utf-8", errors="replace")))
    return rows


def build_hunt_messages(task: Task, side: str, difficulty: str, root: Path) -> list[dict]:
    listing = "\n\n".join(f"--- {rel}\n{text}" for rel, text in _files(root))
    hint = ""
    if difficulty == "L1":
        cwe = task.cwe or "none"
        hint = f"Component: {task.component}. CWE of interest: {cwe}.\n"
    elif difficulty != "L0":
        raise ValueError(f"unknown difficulty {difficulty}")
    user = (
        f"Difficulty {difficulty}. Side {side}. Task {task.id}.\n"
        f"{hint}{PROMPT_RULES}\n\n{listing}"
    )
    return [
        {"role": "system", "content": "You are a source reviewer. Return JSON only."},
        {"role": "user", "content": user},
    ]


def build_disprove_messages(finding: dict, root: Path) -> list[dict]:
    rel = str(finding.get("path") or "")
    text = read_tree_file(root, rel) or ""
    user = (
        "Judge this finding against the target file. "
        'Reply with JSON only: {"verdict":"survive"} or {"verdict":"kill"}. '
        "survive means the finding names a real bug in the target. "
        "kill means it does not.\n"
        f"Finding: {json.dumps(finding, sort_keys=True)}\n"
        f"File {rel}:\n{text}"
    )
    return [
        {"role": "system", "content": "You judge findings. Return JSON only."},
        {"role": "user", "content": user},
    ]


def cacheable(result: dict) -> bool:
    """Keep only completions that did not fail the transport or the HTTP status."""
    if result.get("error") or result.get("timed_out"):
        return False
    for finding in result.get("findings") or []:
        disprove = finding.get("disprove") or {}
        if disprove.get("error") or disprove.get("timed_out"):
            return False
    return True


def chat(
    config: BenchConfig,
    model: str,
    messages: list[dict],
    *,
    transport=None,
) -> dict:
    if transport is not None:
        result = transport(model, messages)
        if not isinstance(result, dict):
            raise TypeError("transport must return a dict")
        result.setdefault("error", None)
        result.setdefault("timed_out", False)
        result.setdefault("text", "")
        result.setdefault("tokens", 0)
        result.setdefault("latency_s", 0.0)
        return result
    try:
        import httpx
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            "bench --live requires httpx>=0.27 from the project dependencies"
        ) from exc

    url = config.base_url.rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json"}
    key = os.environ.get(config.api_key_env, "")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    body = {"model": model, "temperature": config.temperature, "messages": messages}
    started = time.perf_counter()
    try:
        response = httpx.post(url, json=body, headers=headers, timeout=config.timeout_s)
    except httpx.TimeoutException:
        return {
            "error": "timeout",
            "timed_out": True,
            "text": "",
            "tokens": 0,
            "latency_s": time.perf_counter() - started,
        }
    except httpx.HTTPError as exc:
        return {
            "error": str(exc),
            "timed_out": False,
            "text": "",
            "tokens": 0,
            "latency_s": time.perf_counter() - started,
        }
    latency = time.perf_counter() - started
    if response.status_code >= 400:
        return {
            "error": f"http {response.status_code}",
            "timed_out": False,
            "text": "",
            "tokens": 0,
            "latency_s": latency,
        }
    data = response.json()
    text = data["choices"][0]["message"]["content"]
    usage = data.get("usage") or {}
    tokens = int(
        usage.get("total_tokens")
        or (int(usage.get("prompt_tokens") or 0) + int(usage.get("completion_tokens") or 0))
    )
    return {
        "error": None,
        "timed_out": False,
        "text": text or "",
        "tokens": tokens,
        "latency_s": latency,
    }


def live_hunt(
    config: BenchConfig,
    model: str,
    task: Task,
    side: str,
    difficulty: str,
    *,
    transport=None,
) -> dict:
    root = task.side_root(side)
    hunt = chat(
        config,
        model,
        build_hunt_messages(task, side, difficulty, root),
        transport=transport,
    )
    if hunt["error"]:
        return {
            "error": hunt["error"],
            "timed_out": hunt["timed_out"],
            "tokens": hunt["tokens"],
            "latency_s": hunt["latency_s"],
            "findings": [],
        }
    parsed = parse_model_findings(hunt["text"])
    if parsed is None:
        return {
            "error": "unparsed hunt response",
            "timed_out": False,
            "tokens": hunt["tokens"],
            "latency_s": hunt["latency_s"],
            "findings": [],
        }
    findings = []
    for raw in parsed:
        judged = chat(
            config,
            model,
            build_disprove_messages(raw, root),
            transport=transport,
        )
        raw = dict(raw)
        raw["disprove"] = {
            "verdict_text": "" if judged["error"] else judged["text"],
            "error": judged["error"],
            "timed_out": judged["timed_out"],
            "tokens": judged["tokens"],
            "latency_s": judged["latency_s"],
        }
        findings.append(raw)
    return {
        "error": None,
        "timed_out": False,
        "tokens": hunt["tokens"],
        "latency_s": hunt["latency_s"],
        "findings": findings,
    }


def run_bench(
    config: BenchConfig,
    tasks: list[Task],
    *,
    mode: str,
    cache_dir: Path,
    transport=None,
) -> dict:
    if mode not in {"stub", "live"}:
        raise ValueError(mode)
    if mode == "stub":
        models = [dict(item) for item in STUB_MODELS]
    else:
        if not config.models:
            raise RuntimeError("live run needs at least one model in config")
        models = [
            {
                "id": item.id,
                "name": item.name,
                "knowledge_cutoff": item.knowledge_cutoff,
            }
            for item in config.models
        ]
    jobs = []
    for model in models:
        for repeat in range(config.k):
            for difficulty in config.difficulties:
                for task in tasks:
                    sides = ("vulnerable", "fixed") if task.kind == "pair" else ("benign",)
                    for side in sides:
                        jobs.append(
                            {
                                "model": model,
                                "repeat": repeat,
                                "difficulty": difficulty,
                                "task": task,
                                "side": side,
                            }
                        )
    cache = DiskCache(cache_dir)
    misses = 0
    lock = threading.Lock()

    def execute(job: dict) -> dict:
        nonlocal misses
        task: Task = job["task"]
        key = _cache_key(
            {
                "mode": mode,
                "prompt_version": config.prompt_version,
                "model": job["model"]["id"],
                "repeat": job["repeat"],
                "difficulty": job["difficulty"],
                "task": task.id,
                "side": job["side"],
                "content_hash": task.content_hash,
            }
        )
        cached = cache.get(key)
        if cached is None:
            if mode == "stub":
                result = scripted_hunt(
                    job["model"]["id"], task, job["side"], job["difficulty"], job["repeat"]
                )
            else:
                result = live_hunt(
                    config,
                    job["model"]["id"],
                    task,
                    job["side"],
                    job["difficulty"],
                    transport=transport,
                )
            if cacheable(result):
                cache.put(key, result)
            with lock:
                misses += 1
            cached = result
        return cached

    workers = min(config.workers, max(1, len(jobs)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        raw_results = list(pool.map(execute, jobs))
    hits = 0
    for job in jobs:
        task = job["task"]
        key = _cache_key(
            {
                "mode": mode,
                "prompt_version": config.prompt_version,
                "model": job["model"]["id"],
                "repeat": job["repeat"],
                "difficulty": job["difficulty"],
                "task": task.id,
                "side": job["side"],
                "content_hash": task.content_hash,
            }
        )
        if cache.get(key) is not None:
            hits += 1

    attempts = []
    clock = 0.0
    for job, result in zip(jobs, raw_results):
        task = job["task"]
        oracle = _oracle_for(task) if job["side"] == "vulnerable" else None
        findings = annotate(result["findings"], task.side_root(job["side"]), oracle)
        extra = sum(item["disprove_latency_s"] for item in findings)
        clock += float(result["latency_s"]) + extra
        attempts.append(
            {
                "model": job["model"]["id"],
                "knowledge_cutoff": job["model"]["knowledge_cutoff"],
                "repeat": job["repeat"],
                "difficulty": job["difficulty"],
                "task_id": task.id,
                "side": job["side"],
                "error": result["error"],
                "timed_out": result["timed_out"],
                "tokens": result["tokens"],
                "latency_s": result["latency_s"],
                "t_offset_s": clock,
                "findings": findings,
            }
        )
    card = build_scorecard(
        attempts,
        tasks,
        mode=mode,
        k=config.k,
        workers=config.workers,
        fpr_cap=config.fpr_cap,
        false_reject_max=config.false_reject_max,
        on_breach=config.on_breach,
        cache_hits=hits,
        cache_misses=misses,
    )
    return freeze(card)  # type: ignore[return-value]


def emit_results(payload: dict, results_root: Path) -> Path:
    if payload.get("mode") == "stub" or payload.get("scores_are_synthetic"):
        raise RuntimeError("refusing to write stub output under bench/results")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out = results_root / stamp
    out.mkdir(parents=True, exist_ok=False)
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    (out / "scorecard.json").write_text(encoded, encoding="utf-8")
    (out / "leaderboard.json").write_text(
        json.dumps(payload["leaderboard"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out / "pareto.json").write_text(
        json.dumps(payload["pareto"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out / "pareto.md").write_text(payload["pareto_markdown"], encoding="utf-8")
    return out
