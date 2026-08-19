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

    Applies ``force_submit_on_round_limit`` fallback when the model thrashs
    without a successful submit_* (default on).
    """
    from vulnforge.agent_runtime.round_limit import apply_round_limit_fallback
    from vulnforge.llm import FakeLLMClient

    if isinstance(client, FakeLLMClient):
        result = client.run_tool_loop(
            packet,
            tool_handler,
            max_rounds=max_rounds,
            temperature=temperature,
            cfg=cfg,
        )
        return apply_round_limit_fallback(
            result,
            tool_handler,
            packet,
            max_rounds=max_rounds,
            cfg=cfg,
        )

    from vulnforge.agent_runtime.strands_loop import run_strands_tool_loop

    result = run_strands_tool_loop(
        client, packet, tool_handler, max_rounds, temperature, cfg=cfg
    )
    return apply_round_limit_fallback(
        result,
        tool_handler,
        packet,
        max_rounds=max_rounds,
        cfg=cfg,
    )
