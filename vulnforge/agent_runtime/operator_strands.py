"""Operator chat tool loop via Strands Agents.

Mutation tools never execute: they create a pending confirm and stop the agent
(same UX contract as the FakeLLM operator path used in unit tests).
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Optional

from vulnforge.llm import FakeLLMClient
from vulnforge.operator_chat.confirm import PendingMutation, create_pending
from vulnforge.operator_chat.summarize import tool_result_content
from vulnforge.operator_chat.tools_common import MUTATE_TOOLS, mutation_summary
from vulnforge.agent_runtime.strands_loop import (
    _model_from_client,
    _openai_tools_to_strands,
    _require_strands,
)
from vulnforge.agent_runtime.transcript import (
    openaiish_to_strands_messages,
    strands_messages_to_openaiish,
    strip_reasoning_from_strands_messages,
)

logger = logging.getLogger(__name__)

SAFETY_MAX_TOOL_ROUNDS = 500


def run_operator_loop_strands(
    *,
    client: Any,
    system: str,
    history: list[dict[str, Any]],
    user_message: str,
    tools: list[dict],
    dispatch: Callable[[str, dict], dict[str, Any]],
    max_rounds: Optional[int] = None,
    session_id: str,
    scope: str,
    run_key: Optional[str] = None,
    temperature: float = 0.3,
) -> dict[str, Any]:
    """Strands-backed operator chat; returns same shape as ``run_operator_loop``."""
    if isinstance(client, FakeLLMClient):
        raise TypeError(
            "operator_strands does not support FakeLLMClient; "
            "run_operator_loop routes fakes to the scripted chat path"
        )

    _require_strands()
    from strands import Agent

    limit = SAFETY_MAX_TOOL_ROUNDS if max_rounds is None else int(max_rounds)
    if limit < 1:
        limit = 1

    state: dict[str, Any] = {
        "pending": None,
        "ui_hints": {"navigate": None, "refresh_run": False},
        "terminal_ok": False,  # unused; silence submit flag noise
    }
    new_ui: list[dict[str, Any]] = [{"role": "user", "content": user_message}]
    model_id = getattr(client, "model_id", None) or getattr(client, "model", None)

    def tool_handler(name: str, args: dict) -> dict[str, Any]:
        if name in MUTATE_TOOLS:
            summary = mutation_summary(name, args)
            pending = create_pending(
                tool_name=name,
                arguments=args,
                summary=summary,
                scope=scope,
                session_id=session_id,
                run_key=run_key,
            )
            state["pending"] = pending
            return {
                "ok": False,
                "pending_confirm": True,
                "summary": summary,
                "token": pending.token,
                "tool_name": name,
                "arguments": args,
            }
        out = dispatch(name, args or {})
        if isinstance(out, dict):
            _merge_hints(state["ui_hints"], out)
        return out if isinstance(out, dict) else {"ok": True, "result": out}

    # Build tools; mutation tools still registered so the model can call them
    session_flags: dict[str, Any] = {"terminal_ok": False}
    strands_tools = _openai_tools_to_strands(tools or [], tool_handler, session_flags)

    # History without system
    hist_for_model: list[dict[str, Any]] = []
    for m in history or []:
        if not isinstance(m, dict):
            continue
        if m.get("role") in ("user", "assistant", "tool"):
            hist_for_model.append(m)
    strands_hist = openaiish_to_strands_messages(hist_for_model)

    model = _model_from_client(client, temperature)
    agent = Agent(
        model=model,
        tools=strands_tools,
        system_prompt=system or None,
        messages=strands_hist or None,
        callback_handler=None,
    )

    def after_tool(event: Any) -> None:
        if state.get("pending") is not None:
            try:
                agent.cancel()
            except Exception as e:
                logger.warning("operator strands cancel after mutate: %s", e)

    from strands.hooks import AfterToolCallEvent

    agent.hooks.add_callback(AfterToolCallEvent, after_tool)
    try:
        from strands.hooks import MessageAddedEvent

        def on_msg(_event: Any) -> None:
            try:
                strip_reasoning_from_strands_messages(list(agent.messages))
            except Exception:
                pass

        agent.hooks.add_callback(MessageAddedEvent, on_msg)
    except Exception:
        pass

    try:
        result = agent(user_message, limits={"turns": limit})
    except Exception as e:
        err = str(e)
        new_ui.append({"role": "assistant", "content": f"LLM error: {err}", "error": True})
        return {
            "ok": False,
            "messages": new_ui,
            "pending_confirm": None,
            "ui_hints": state["ui_hints"],
            "error": err,
            "model_id": model_id,
            "model_messages": [{"role": "system", "content": system}],
        }

    stop = getattr(result, "stop_reason", None)
    model_id = getattr(result, "model_id", None) or model_id

    # Build UI deltas from full agent transcript relative to history length
    openaiish = strands_messages_to_openaiish(list(agent.messages))
    # Prefixed history was converted without system; new turns after history
    # Approximate: emit assistant/tool turns from openaiish that are "new"
    # Simpler: walk openaiish and rebuild new_ui from last user message onward
    new_ui = _ui_from_strands_turn(
        openaiish,
        user_message=user_message,
        pending=state.get("pending"),
        tool_result_content=tool_result_content,
    )

    pending: Optional[PendingMutation] = state.get("pending")
    if pending is not None:
        new_ui.append(
            {
                "role": "assistant",
                "content": (
                    f"This action needs your confirmation: **{pending.summary}**.\n"
                    "Click Confirm to run it, or Cancel."
                ),
            }
        )
        return {
            "ok": True,
            "messages": new_ui,
            "pending_confirm": pending.to_public(),
            "ui_hints": state["ui_hints"],
            "error": None,
            "model_id": model_id,
            "model_messages": [{"role": "system", "content": system}] + openaiish,
        }

    # Final assistant text already in new_ui; if missing, add stop note
    if stop in ("limit_turns", "limitTurns") and not any(
        m.get("role") == "assistant" and isinstance(m.get("content"), str) and m.get("content")
        for m in new_ui
    ):
        new_ui.append(
            {
                "role": "assistant",
                "content": "Stopped after max tool rounds. Try a more specific question.",
            }
        )

    return {
        "ok": True,
        "messages": new_ui,
        "pending_confirm": None,
        "ui_hints": state["ui_hints"],
        "error": None,
        "model_id": model_id,
        "model_messages": [{"role": "system", "content": system}] + openaiish,
    }


def _merge_hints(ui_hints: dict[str, Any], out: dict[str, Any]) -> None:
    hints = out.get("ui_hints") if isinstance(out.get("ui_hints"), dict) else None
    if not hints:
        # also accept top-level navigate/refresh
        if out.get("navigate"):
            ui_hints["navigate"] = out.get("navigate")
        if out.get("refresh_run"):
            ui_hints["refresh_run"] = True
        return
    if hints.get("navigate"):
        ui_hints["navigate"] = hints["navigate"]
    if hints.get("refresh_run"):
        ui_hints["refresh_run"] = True


def _ui_from_strands_turn(
    openaiish: list[dict[str, Any]],
    *,
    user_message: str,
    pending: Optional[PendingMutation],
    tool_result_content: Callable[[Any], str],
) -> list[dict[str, Any]]:
    """UI-facing messages for this user turn (user + following assistant/tool)."""
    new_ui: list[dict[str, Any]] = [{"role": "user", "content": user_message}]
    # Find last user text matching this turn (prefer last plain user)
    start = 0
    for i, m in enumerate(openaiish):
        if m.get("role") == "user" and m.get("content") == user_message:
            start = i + 1
    for m in openaiish[start:]:
        role = m.get("role")
        if role == "assistant":
            content = m.get("content") or ""
            entry: dict[str, Any] = {"role": "assistant", "content": content}
            if m.get("tool_calls"):
                entry["tool_calls"] = m["tool_calls"]
            # Keep tool-call-only assistants in history; UI skips empty bubbles.
            if content.strip() or m.get("tool_calls"):
                new_ui.append(entry)
        elif role == "tool":
            raw = m.get("content")
            payload: Any = raw
            if isinstance(raw, str):
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    payload = {"text": raw}
            entry = {
                "role": "tool",
                "name": m.get("name"),
                "tool_call_id": m.get("tool_call_id") or "call",
                "content": payload if isinstance(payload, dict) else {"text": str(payload)},
            }
            if isinstance(payload, dict) and payload.get("pending_confirm") and pending:
                entry["pending_confirm"] = pending.to_public()
            new_ui.append(entry)
    return new_ui
