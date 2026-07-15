"""Stage: tool_gaps — mechanical and/or LLM analysis of missing tools.

Mines transcripts / notes / task results for missing-tool signals.
Optional AI synthesis when run.tool_gaps_mode is llm|hybrid or payload.mode set.
Enqueue after a campaign (or any time) so Ralph picks it up.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnforge.tool_gaps import analyze_run_mode, write_reports


def run(task, db, run_dir: Path, cfg: dict) -> dict[str, Any]:
    """Analyze tool gaps; always safe to re-run (projection write)."""
    payload = getattr(task, "payload", None) or {}
    if not isinstance(payload, dict):
        payload = {}
    mode = (
        payload.get("mode")
        or (cfg.get("run") or {}).get("tool_gaps_mode")
        or "mechanical"
    )
    analysis = analyze_run_mode(run_dir, str(mode), cfg)
    paths = write_reports(run_dir, analysis)
    return {
        "status": "succeeded",
        "gap_count": int(analysis.get("gap_count") or 0),
        "mode": analysis.get("mode") or mode,
        "written": paths,
        "stats": analysis.get("stats") or {},
        "llm_error": analysis.get("llm_error"),
    }
