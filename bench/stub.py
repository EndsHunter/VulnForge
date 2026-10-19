"""Deterministic personas for offline runs. Not measurements of a live model."""

from __future__ import annotations

import json

from bench.tasks import Task

STUB_MODELS = (
    {"id": "stub-sharp", "name": "stub-sharp", "knowledge_cutoff": "2024-08-01"},
    {"id": "stub-noisy", "name": "stub-noisy", "knowledge_cutoff": "2024-08-01"},
    {"id": "stub-blind", "name": "stub-blind", "knowledge_cutoff": "2024-08-01"},
)

_EMPTY_TOKENS = 500
_HIT_TOKENS = 800
_NOISY_TOKENS = 1100
_BLIND_TOKENS = 220
_ERROR_TOKENS = 100


def _verdict(name: str, *, tokens: int = 40, latency_s: float = 0.02) -> dict:
    return {
        "verdict_text": json.dumps({"verdict": name}),
        "error": None,
        "timed_out": False,
        "tokens": tokens,
        "latency_s": latency_s,
    }


def _oracle_finding(task: Task, verdict: dict, confidence: float = 0.9) -> dict:
    oracle = task.oracle
    assert oracle is not None
    return {
        "path": oracle.path,
        "line": oracle.line,
        "symbol": oracle.symbol,
        "cwe": task.cwe,
        "confidence": confidence,
        "evidence": oracle.quote,
        "path_contract": [oracle.symbol],
        "severity": "high",
        "disprove": verdict,
    }


def _done(findings: list[dict], tokens: int, latency_s: float) -> dict:
    return {
        "error": None,
        "timed_out": False,
        "tokens": tokens,
        "latency_s": latency_s,
        "findings": findings,
    }


def _error(message: str, *, timed_out: bool) -> dict:
    return {
        "error": message,
        "timed_out": timed_out,
        "tokens": _ERROR_TOKENS,
        "latency_s": 0.01,
        "findings": [],
    }


def _sharp(task: Task, side: str, difficulty: str, repeat: int) -> dict:
    if side != "vulnerable":
        return _done([], _EMPTY_TOKENS, 0.04)
    missed = set()
    if difficulty == "L0":
        missed.add("pair-ssrf")
    missed.add("pair-int")
    if repeat == 2:
        missed.add("pair-auth")
    if task.id in missed:
        return _done([], _EMPTY_TOKENS, 0.04)
    findings = [_oracle_finding(task, _verdict("survive"))]
    if task.id == "pair-sqli" and repeat == 0:
        findings.append(_oracle_finding(task, _verdict("survive")))
    return _done(findings, _HIT_TOKENS, 0.05)


def _noisy(task: Task, side: str, difficulty: str, repeat: int) -> dict:
    if task.id == "pair-int" and side == "vulnerable":
        return _error("timeout", timed_out=True)
    if task.id == "pair-int":
        return _done([], _NOISY_TOKENS, 0.05)
    if task.id == "pair-sqli":
        if side == "vulnerable":
            return _done(
                [_oracle_finding(task, _verdict("survive"), 0.9)],
                _NOISY_TOKENS,
                0.05,
            )
        return _done(
            [
                {
                    "path": "query.py",
                    "line": 2,
                    "symbol": "lookup_user",
                    "cwe": "CWE-89",
                    "confidence": 0.4,
                    "evidence": "name = ?",
                    "path_contract": ["lookup_user"],
                    "severity": "high",
                    "disprove": _verdict("survive"),
                }
            ],
            _NOISY_TOKENS,
            0.05,
        )
    if task.id == "pair-cmd" and side == "vulnerable":
        return _done([_oracle_finding(task, _verdict("kill"), 0.9)], _NOISY_TOKENS, 0.05)
    if task.id == "pair-path" and side == "vulnerable":
        path_verdict = ("survive", "kill", "survive")[repeat]
        findings = [
            _oracle_finding(task, _verdict(path_verdict), 0.9),
            {
                "path": "poc/note.py",
                "line": 2,
                "symbol": "MARKER",
                "cwe": "CWE-22",
                "confidence": 0.4,
                "evidence": "os.path.join(ROOT, name)",
                "path_contract": ["MARKER"],
                "severity": "critical",
                "disprove": _verdict("kill"),
            },
        ]
        return _done(findings, _NOISY_TOKENS, 0.05)
    if task.id == "pair-buf" and side == "vulnerable":
        return _done(
            [
                _oracle_finding(
                    task,
                    {
                        "verdict_text": "",
                        "error": None,
                        "timed_out": False,
                        "tokens": 15,
                        "latency_s": 0.02,
                    },
                    0.9,
                )
            ],
            _NOISY_TOKENS,
            0.05,
        )
    if task.id == "pair-auth" and side == "fixed":
        return _done(
            [
                {
                    "path": "auth.py",
                    "line": 2,
                    "symbol": "allow",
                    "cwe": "CWE-287",
                    "confidence": 0.4,
                    "evidence": "if not supplied or not stored:",
                    "path_contract": ["not_a_symbol"],
                    "severity": "high",
                    "disprove": _verdict("survive"),
                }
            ],
            _NOISY_TOKENS,
            0.05,
        )
    if task.id == "pair-ssrf" and side == "vulnerable" and difficulty == "L1":
        return _done([_oracle_finding(task, _verdict("survive"), 0.9)], _NOISY_TOKENS, 0.05)
    if task.id == "benign-param" and side == "benign":
        return _done(
            [
                {
                    "path": "query.py",
                    "line": 2,
                    "symbol": "lookup_user",
                    "cwe": "CWE-89",
                    "confidence": 0.4,
                    "evidence": "name = ?",
                    "path_contract": ["lookup_user"],
                    "severity": "high",
                    "disprove": _verdict("kill"),
                }
            ],
            _NOISY_TOKENS,
            0.05,
        )
    if task.id == "benign-copy" and side == "benign":
        return _done(
            [
                {
                    "path": "copy.c",
                    "line": 7,
                    "symbol": "copy_name",
                    "cwe": "CWE-120",
                    "confidence": 0.4,
                    "evidence": "strncpy(dst, src, cap - 1);",
                    "path_contract": ["copy_name"],
                    "severity": "high",
                    "disprove": {
                        "verdict_text": "maybe",
                        "error": None,
                        "timed_out": False,
                        "tokens": 12,
                        "latency_s": 0.02,
                    },
                }
            ],
            _NOISY_TOKENS,
            0.05,
        )
    return _done([], _NOISY_TOKENS, 0.05)


def _blind(task: Task, side: str, difficulty: str, repeat: int) -> dict:
    del difficulty, repeat
    if task.id == "pair-sqli" and side == "vulnerable":
        return _error("connection refused", timed_out=False)
    return _done([], _BLIND_TOKENS, 0.03)


_PERSONAS = {
    "stub-sharp": _sharp,
    "stub-noisy": _noisy,
    "stub-blind": _blind,
}


def scripted_hunt(model_id: str, task: Task, side: str, difficulty: str, repeat: int) -> dict:
    return _PERSONAS[model_id](task, side, difficulty, repeat)
