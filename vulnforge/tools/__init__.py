"""Allowlisted tools for agent tool-calls.

Model-facing tools live under ``vulnforge.tools.agent`` (one file = SPEC + run).
Shared backends (fs_read, grep_index, …) remain importable for tests and stages.
"""

from __future__ import annotations

from vulnforge.tools.dispatch import build_tool_handler, run_tool

__all__ = ["build_tool_handler", "run_tool"]
