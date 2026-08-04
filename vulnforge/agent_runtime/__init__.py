"""Agent tool-loop runtime — **Strands Agents only** (production).

Hunt, recon, develop_poc, and operator chat use Strands.
``FakeLLMClient`` retains a scripted tool loop for offline tests.

Multi-agent recon: ``cfg['llm']['recon_orchestrator']`` =
``ralph`` | ``inprocess`` | ``graph``.
"""

from __future__ import annotations

from vulnforge.llm import LLMResult

from vulnforge.agent_runtime.dispatch import run_tool_loop

__all__ = [
    "run_tool_loop",
    "LLMResult",
]
