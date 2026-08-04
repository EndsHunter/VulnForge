"""Strands Agents backend for VulnForge tool loops (Phase 1)."""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Optional

from vulnforge.llm import LLMResult, ResponseClass, TokenUsage, messages_from_packet
from vulnforge.agent_runtime.transcript import (
    strands_messages_to_openaiish,
    strip_reasoning_from_strands_messages,
)

logger = logging.getLogger(__name__)

TERMINAL_TOOLS = frozenset(
    {"submit_candidate", "submit_none", "submit_architecture"}
)


def _require_strands() -> None:
    try:
        import strands  # noqa: F401
        from strands.models.openai import OpenAIModel  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "Strands Agents is required (default VulnForge agent runtime). "
            "Install: pip install -e .   # or pip install 'strands-agents[openai]'"
        ) from e


def _openai_tools_to_strands(
    tools_schema: list[dict],
    tool_handler: Callable[[str, dict], dict],
    session: dict[str, Any],
) -> list[Any]:
    """Build Strands PythonAgentTool list from VulnForge OpenAI-style schemas."""
    from strands.tools.tools import PythonAgentTool

    tools: list[Any] = []
    for t in tools_schema or []:
        if not isinstance(t, dict):
            continue
        fn = t.get("function") if isinstance(t.get("function"), dict) else t
        if not isinstance(fn, dict) or not fn.get("name"):
            continue
        name = str(fn["name"])
        description = str(fn.get("description") or name)
        parameters = fn.get("parameters") or {
            "type": "object",
            "properties": {},
        }
        if not isinstance(parameters, dict):
            parameters = {"type": "object", "properties": {}}

        # Closure over name
        def _make_func(tool_name: str) -> Callable[..., dict]:
            def tool_func(tool_use: dict, **_kwargs: Any) -> dict[str, Any]:
                tu = tool_use if isinstance(tool_use, dict) else {}
                raw_input = tu.get("input") or {}
                if isinstance(raw_input, str):
                    try:
                        args = json.loads(raw_input)
                    except json.JSONDecodeError:
                        args = {}
                elif isinstance(raw_input, dict):
                    args = raw_input
                else:
                    args = {}
                try:
                    out = tool_handler(tool_name, args)
                except Exception as e:
                    out = {"ok": False, "error": str(e)}
                if not isinstance(out, dict):
                    out = {"ok": True, "result": out}

                # Domain terminal success → flag for cancel hook
                if (
                    tool_name in TERMINAL_TOOLS
                    and out.get("ok") is True
                ):
                    session["terminal_ok"] = True
                    session["terminal_tool"] = tool_name
                    session["terminal_result"] = out

                return {
                    "toolUseId": tu.get("toolUseId") or "call",
                    "status": "success",
                    "content": [{"text": json.dumps(out)}],
                }

            return tool_func

        tool_spec = {
            "name": name,
            "description": description,
            "inputSchema": {"json": parameters},
        }
        tools.append(PythonAgentTool(name, tool_spec, _make_func(name)))
    return tools


def _attach_submit_stop_hook(agent: Any, session: dict[str, Any]) -> None:
    from strands.hooks import AfterToolCallEvent

    def after_tool(event: Any) -> None:
        if not session.get("terminal_ok"):
            return
        # Cancel after successful domain terminal tool
        try:
            agent.cancel()
        except Exception as e:
            logger.warning("strands cancel after submit failed: %s", e)

    agent.hooks.add_callback(AfterToolCallEvent, after_tool)


def _attach_reasoning_strip_hook(agent: Any) -> None:
    """Strip reasoning blocks after each message add to protect multi-turn."""
    try:
        from strands.hooks import MessageAddedEvent
    except ImportError:
        return

    def on_message(event: Any) -> None:
        try:
            strip_reasoning_from_strands_messages(list(agent.messages))
        except Exception:
            pass

    try:
        agent.hooks.add_callback(MessageAddedEvent, on_message)
    except Exception:
        pass


def _model_from_client(client: Any, temperature: float) -> Any:
    from strands.models.openai import OpenAIModel

    base_url = getattr(client, "base_url", None) or "http://127.0.0.1:1234/v1"
    model_id = (
        getattr(client, "_resolved_model", None)
        or getattr(client, "model", None)
        or getattr(client, "model_id", None)
        or ""
    )
    api_key = getattr(client, "api_key", None)
    if api_key is None:
        api_key = "lm-studio"
    timeout = float(getattr(client, "timeout", 600) or 600)
    max_tokens = int(getattr(client, "max_tokens", 4096) or 4096)

    client_args: dict[str, Any] = {
        "base_url": str(base_url).rstrip("/"),
        "timeout": timeout,
    }
    # Empty api_key → omit Authorization for local servers that reject dummy keys
    if api_key:
        client_args["api_key"] = str(api_key)
    else:
        client_args["api_key"] = "no-key"

    return OpenAIModel(
        client_args=client_args,
        model_id=str(model_id),
        params={
            "temperature": float(temperature),
            "max_tokens": max_tokens,
        },
    )


def _usage_from_result(result: Any) -> Optional[TokenUsage]:
    try:
        metrics = getattr(result, "metrics", None)
        if metrics is None:
            return None
        summary = metrics.get_summary() if hasattr(metrics, "get_summary") else None
        if not isinstance(summary, dict):
            return None
        acc = summary.get("accumulated_usage") or summary.get("usage") or {}
        if not isinstance(acc, dict):
            return None
        prompt = int(acc.get("inputTokens") or acc.get("prompt_tokens") or 0)
        completion = int(acc.get("outputTokens") or acc.get("completion_tokens") or 0)
        total = int(acc.get("totalTokens") or acc.get("total_tokens") or 0)
        if total <= 0:
            total = prompt + completion
        cycles = int(summary.get("total_cycles") or 0)
        if prompt or completion or total:
            return TokenUsage(
                prompt_tokens=prompt,
                completion_tokens=completion,
                total_tokens=total,
                source="provider",
                llm_calls=max(1, cycles),
            )
    except Exception:
        return None
    return None


def _last_assistant_content(openaiish: list[dict[str, Any]]) -> Optional[str]:
    for m in reversed(openaiish):
        if m.get("role") == "assistant":
            c = m.get("content")
            if isinstance(c, str) and c.strip():
                return c
    return None


def _tool_calls_from_transcript(openaiish: list[dict[str, Any]]) -> list[dict]:
    """Flatten last-round style tool_calls list for LLMResult.tool_calls."""
    out: list[dict] = []
    for m in openaiish:
        if m.get("role") != "assistant":
            continue
        for tc in m.get("tool_calls") or []:
            fn = tc.get("function") or {}
            args_raw = fn.get("arguments") or "{}"
            if isinstance(args_raw, str):
                try:
                    args = json.loads(args_raw)
                except json.JSONDecodeError:
                    args = {}
            else:
                args = args_raw if isinstance(args_raw, dict) else {}
            out.append(
                {
                    "id": tc.get("id"),
                    "name": fn.get("name"),
                    "arguments": args,
                }
            )
    return out


def run_strands_tool_loop(
    client: Any,
    packet: Any,
    tool_handler: Callable[[str, dict], dict],
    max_rounds: int,
    temperature: float,
    cfg: Optional[dict[str, Any]] = None,
) -> LLMResult:
    """Run one VulnForge packet through a Strands Agent; return LLMResult."""
    _require_strands()
    from strands import Agent

    session: dict[str, Any] = {
        "terminal_ok": False,
        "terminal_tool": None,
        "terminal_result": None,
    }
    tools_schema = getattr(packet, "tools_schema", None) or []
    strands_tools = _openai_tools_to_strands(tools_schema, tool_handler, session)
    model = _model_from_client(client, temperature)
    system = str(getattr(packet, "system", "") or "")
    user = str(getattr(packet, "user", "") or "")
    # Round-budget nudge so models finish with submit_* before the hard limit.
    turns = max(1, int(max_rounds))
    if turns >= 2 and "max_tool_rounds" not in user.lower():
        user = (
            user
            + f"\n\n## Tool budget\nYou have at most **{turns}** tool rounds. "
            "If you are near the limit, call the terminal tool now "
            "(submit_candidate / submit_none / submit_architecture). "
            "Do not thrash on failed tools — fix args or submit_none.\n"
        )

    agent = Agent(
        model=model,
        tools=strands_tools,
        system_prompt=system or None,
        callback_handler=None,
    )
    _attach_submit_stop_hook(agent, session)
    _attach_reasoning_strip_hook(agent)

    # Also strip before invoke in case of prior state (fresh agent, no-op)
    strip_reasoning_from_strands_messages(list(agent.messages))

    try:
        result = agent(
            user,
            limits={"turns": turns},
        )
    except Exception as e:
        err = str(e)
        low = err.lower()
        # Map transport-ish failures to infra-style classification
        classification = ResponseClass.TRANSPORT
        if "context" in low or "token" in low:
            classification = ResponseClass.CONTEXT_LENGTH
        return LLMResult(
            ok=False,
            classification=classification,
            content=None,
            tool_calls=[],
            raw=None,
            model_id=getattr(client, "model", None)
            or getattr(client, "model_id", None),
            error=err,
            transcript=messages_from_packet(packet),
        )

    openaiish = strands_messages_to_openaiish(list(agent.messages))
    # Prepend system for dashboard / tool-gaps transcript consumers
    transcript: list[dict[str, Any]] = []
    if system:
        transcript.append({"role": "system", "content": system})
    transcript.extend(openaiish)

    stop = getattr(result, "stop_reason", None)
    usage = _usage_from_result(result)
    content = _last_assistant_content(openaiish)
    tool_calls = _tool_calls_from_transcript(openaiish)
    model_id = (
        getattr(client, "_resolved_model", None)
        or getattr(client, "model", None)
        or getattr(client, "model_id", None)
    )

    terminal_ok = bool(session.get("terminal_ok"))
    # Domain success: cancelled after submit_* or any successful terminal
    if terminal_ok:
        return LLMResult(
            ok=True,
            classification=ResponseClass.OK,
            content=content,
            tool_calls=tool_calls,
            raw={"stop_reason": stop, "strands": True},
            model_id=model_id,
            error=None,
            transcript=transcript,
            usage=usage,
        )

    # Free-text end without submit — soft failure (no_submit)
    if stop in ("end_turn", "stop", None) and not any(
        tc.get("name") in TERMINAL_TOOLS for tc in tool_calls
    ):
        return LLMResult(
            ok=False,
            classification=ResponseClass.TRUNCATED,
            content=content,
            tool_calls=tool_calls,
            raw={"stop_reason": stop, "strands": True},
            model_id=model_id,
            error="no_submit",
            transcript=transcript,
            usage=usage,
        )

    if stop in ("limit_turns", "limitTurns", "max_tokens"):
        return LLMResult(
            ok=False,
            classification=ResponseClass.TRUNCATED,
            content=content,
            tool_calls=tool_calls,
            raw={"stop_reason": stop, "strands": True},
            model_id=model_id,
            error="max_tool_rounds" if "limit" in str(stop).lower() or "turn" in str(stop).lower() else "truncated",
            transcript=transcript,
            usage=usage,
        )

    if stop == "cancelled" and not terminal_ok:
        return LLMResult(
            ok=False,
            classification=ResponseClass.TRUNCATED,
            content=content,
            tool_calls=tool_calls,
            raw={"stop_reason": stop, "strands": True},
            model_id=model_id,
            error="cancelled",
            transcript=transcript,
            usage=usage,
        )

    # Tool-use stop without terminal — exhausted mid-loop
    return LLMResult(
        ok=False,
        classification=ResponseClass.TRUNCATED,
        content=content,
        tool_calls=tool_calls,
        raw={"stop_reason": stop, "strands": True},
        model_id=model_id,
        error="no_submit" if not terminal_ok else None,
        transcript=transcript,
        usage=usage,
    )
