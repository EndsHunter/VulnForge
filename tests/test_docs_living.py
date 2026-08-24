"""Living docs stay aligned with seeds, CLI, and agent tools."""

from __future__ import annotations

import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_living_docs_match_repo():
    ns = runpy.run_path(str(ROOT / "scripts" / "check_docs.py"))
    errors: list[str] = []
    for fn in (
        ns["check_seed_catalog"],
        ns["check_cli_in_protocol"],
        ns["check_tools_in_protocol"],
        ns["check_dashboard_hunts_name"],
        ns["check_agents_posix_quickstart"],
        ns["check_phantom_paths"],
        ns["check_hunt_preamble_claim"],
    ):
        errors.extend(fn())
    assert errors == [], "\n".join(errors)
