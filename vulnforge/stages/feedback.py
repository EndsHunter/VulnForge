"""
Stage: feedback — DEFERRED (default off)

MUST NOT rewrite live system prompts.
Only next-run parameter pins / prompt patch proposals under version control.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def run(task, db, run_dir: Path, cfg: dict) -> dict[str, Any]:
    """
    TODO (later):
      - read rejected_mech / rejected_llm reasons
      - propose parameter tweaks (class weights, path focus)
      - write PromptPatch proposal file — human applies to prompts/v2
      - never mutate prompts/v1 in place during a run
    """
    raise NotImplementedError("TODO: feedback.run — deferred")


def collect_failure_signals(db) -> list[dict]:
    """TODO: aggregate validation failure reasons."""
    raise NotImplementedError("TODO: collect_failure_signals")


def propose_parameter_patch(signals: list[dict]) -> dict:
    """TODO: emit structured patch proposal JSON."""
    raise NotImplementedError("TODO: propose_parameter_patch")
