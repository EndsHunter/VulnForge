"""
Stage: gapfill — DEFERRED (default off)

Enqueue hunts for under-visited coverage cells. Do not enable until
mechanical validate is solid and coverage_facts reflect real file hits.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def run(task, db, run_dir: Path, cfg: dict) -> dict[str, Any]:
    """
    TODO (later):
      - if not cfg.stages.gapfill: return skipped
      - read coverage_facts
      - find cells with visit_count==0 or shallow
      - enqueue hunt tasks up to remaining budget
      - never infinite loop: max visits per cell
    """
    # PSEUDO:
    #   if not cfg["stages"].get("gapfill"):
    #       return {"status": "succeeded", "skipped": True}
    #   cells = db.under_covered_cells()
    #   for cell in cells[:budget]:
    #       db.enqueue_task("hunt", cell)
    #   return {"status": "succeeded", "enqueued": n}
    raise NotImplementedError("TODO: gapfill.run — deferred")


def select_under_covered(db, max_new: int) -> list[dict]:
    """TODO: query coverage_facts for gapfill candidates."""
    raise NotImplementedError("TODO: select_under_covered")
