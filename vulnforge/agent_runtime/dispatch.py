"""Strands Agents tool-loop entrypoint for production stages.

Offline ``FakeLLMClient`` keeps a small scripted tool loop for unit tests only.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from vulnforge.llm import LLMResult


def _recording_handler(
    tool_handler: Callable[[str, dict], dict],
) -> Callable[[str, dict], dict]:
    """Record each tool call on the live task pane when a task is bound."""
    from vulnforge.live_task import record_tool_call

    def wrapped(name: str, args: dict) -> dict:
        payload = args if isinstance(args, dict) else {}
        try:
            out = tool_handler(name, payload)
        except Exception as e:
            record_tool_call(name, payload, {"ok": False, "error": str(e)})
            raise
        record_tool_call(
            name,
            payload,
            out if isinstance(out, dict) else {"ok": True, "result": out},
        )
        return out

    return wrapped


def _cfg_with_client_budgets(cfg: Optional[dict[str, Any]], client: Any) -> Optional[dict[str, Any]]:
    """Overlay the client's resolved pair budgets onto the loop cfg.

    Hand-built fakes leave these unset and keep the caller's cfg.
    """
    ctx = getattr(client, "context_tokens", None)
    mt = getattr(client, "max_tokens", None)
    if ctx is None and mt is None:
        return cfg
    out = dict(cfg or {})
    llm = dict(out.get("llm") or {})
    if ctx is not None:
        llm["context_tokens"] = int(ctx)
    if mt is not None:
        llm["max_tokens"] = int(mt)
    out["llm"] = llm
    return out


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

    tool_handler = _recording_handler(tool_handler)
    cfg = _cfg_with_client_budgets(cfg, client)

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
