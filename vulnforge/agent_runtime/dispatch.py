"""Strands Agents tool-loop entrypoint for production stages.

Offline ``FakeLLMClient`` keeps a small scripted tool loop for unit tests only.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from vulnforge.llm import LLMResult


def run_tool_loop(
    client: Any,
    packet: Any,
    tool_handler: Callable[[str, dict], dict],
    max_rounds: int,
    temperature: float,
    *,
    cfg: Optional[dict[str, Any]] = None,
) -> LLMResult:
    """Run the agent tool loop via Strands (or FakeLLM scripted loop in tests).

    ``cfg`` is accepted for call-site compatibility (stages pass harness config)
    but does not select an alternate backend.
    """
    del cfg  # always Strands for live clients

    from vulnforge.llm import FakeLLMClient

    if isinstance(client, FakeLLMClient):
        return client.run_tool_loop(
            packet, tool_handler, max_rounds=max_rounds, temperature=temperature
        )

    from vulnforge.agent_runtime.strands_loop import run_strands_tool_loop

    return run_strands_tool_loop(
        client, packet, tool_handler, max_rounds, temperature
    )
