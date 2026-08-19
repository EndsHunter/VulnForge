"""Operator chat multi-turn tool loop."""

from __future__ import annotations

import json
from typing import Any, Callable, Optional

from vulnforge.llm import LLMClient, LLMResult, ResponseClass
from vulnforge.operator_chat.confirm import PendingMutation, create_pending
from vulnforge.operator_chat.summarize import tool_result_content
from vulnforge.operator_chat.tools_common import MUTATE_TOOLS, mutation_summary

# Legacy named default for tests that pass an explicit cap. Production operator
# chat uses max_rounds=None (unlimited with SAFETY_MAX_TOOL_ROUNDS ceiling).
MAX_TOOL_ROUNDS = 10
# Anti-runaway ceiling when max_rounds is None (model keeps tool-calling forever).
SAFETY_MAX_TOOL_ROUNDS = 500


def run_operator_loop(
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
    """
    Run LLM + tools until final assistant text or pending mutation confirm.

    Production clients use Strands. FakeLLM uses the scripted chat loop below.

    max_rounds:
      None  — no operator-facing tool limit (safety ceiling SAFETY_MAX_TOOL_ROUNDS)
      int   — stop after that many LLM rounds (tests / explicit overrides)

    Returns dict with keys: messages (new UI-facing turns), pending_confirm,
    ui_hints, error, model_id.
    """
    from vulnforge.llm import FakeLLMClient

    if not isinstance(client, FakeLLMClient):
        from vulnforge.agent_runtime.operator_strands import (
            run_operator_loop_strands,
        )

        return run_operator_loop_strands(
            client=client,
            system=system,
            history=history,
            user_message=user_message,
            tools=tools,
            dispatch=dispatch,
            max_rounds=max_rounds,
            session_id=session_id,
            scope=scope,
            run_key=run_key,
            temperature=temperature,
        )

    messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
    # history: only user/assistant/tool for model (skip pure UI meta)
    for m in history:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        if role in ("user", "assistant", "tool", "system"):
            # drop oversized
            messages.append(_slim_message(m))

    messages.append({"role": "user", "content": user_message})

    new_ui: list[dict[str, Any]] = [{"role": "user", "content": user_message}]
    pending: Optional[PendingMutation] = None
    ui_hints: dict[str, Any] = {"navigate": None, "refresh_run": False}
    last: Optional[LLMResult] = None
    model_id = getattr(client, "model_id", None) or getattr(client, "model", None)

    # None = unlimited for the operator; still apply safety ceiling.
    limit = SAFETY_MAX_TOOL_ROUNDS if max_rounds is None else int(max_rounds)
    if limit < 1:
        limit = 1

    for _round in range(limit):
        last = client.chat(messages, tools=tools or None, temperature=temperature)
        model_id = last.model_id or model_id
        if not last.ok:
            err = last.error or last.classification.value
            msg = {
                "role": "assistant",
                "content": f"LLM error: {err}",
                "error": True,
            }
            new_ui.append(msg)
            messages.append({"role": "assistant", "content": msg["content"]})
            return {
                "ok": False,
                "messages": new_ui,
                "pending_confirm": None,
                "ui_hints": ui_hints,
                "error": err,
                "model_id": model_id,
                "model_messages": messages,
            }

        if last.tool_calls:
            asst_content = last.content or ""
            tool_meta = []
            asst_msg: dict[str, Any] = {
                "role": "assistant",
                "content": asst_content,
                "tool_calls": [],
            }
            for i, tc in enumerate(last.tool_calls):
                asst_msg["tool_calls"].append(
                    {
                        "id": tc.get("id") or f"call_{i}",
                        "type": "function",
                        "function": {
                            "name": tc.get("name"),
                            "arguments": json.dumps(tc.get("arguments") or {}),
                        },
                    }
                )
            messages.append(asst_msg)
            # Persist tool_calls even when content is empty so follow-up
            # Strands turns can pair toolResult with the original toolUse id.
            ui_asst: dict[str, Any] = {
                "role": "assistant",
                "content": asst_content,
                "tool_calls": asst_msg["tool_calls"],
            }
            new_ui.append(ui_asst)

            stop_for_confirm = False
            for i, tc in enumerate(last.tool_calls):
                name = str(tc.get("name") or "")
                args = tc.get("arguments") or {}
                if not isinstance(args, dict):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {}
                tc_id = tc.get("id") or f"call_{i}"

                if name in MUTATE_TOOLS:
                    # Request confirm — do not execute
                    summary = mutation_summary(name, args)
                    pending = create_pending(
                        tool_name=name,
                        arguments=args,
                        summary=summary,
                        scope=scope,
                        session_id=session_id,
                        run_key=run_key,
                    )
                    tool_payload = {
                        "ok": False,
                        "pending_confirm": True,
                        "summary": summary,
                        "token": pending.token,
                        "tool_name": name,
                        "arguments": args,
                    }
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc_id,
                            "name": name,
                            "content": tool_result_content(tool_payload),
                        }
                    )
                    new_ui.append(
                        {
                            "role": "tool",
                            "name": name,
                            "tool_call_id": tc_id,
                            "content": tool_payload,
                            "pending_confirm": pending.to_public(),
                        }
                    )
                    stop_for_confirm = True
                    break

                out = dispatch(name, args)
                _merge_hints(ui_hints, out)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc_id,
                        "name": name,
                        "content": tool_result_content(out),
                    }
                )
                new_ui.append(
                    {
                        "role": "tool",
                        "name": name,
                        "tool_call_id": tc_id,
                        "content": out,
                    }
                )
                tool_meta.append(name)

            if stop_for_confirm:
                # One short assistant line about confirm
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
                    "pending_confirm": pending.to_public() if pending else None,
                    "ui_hints": ui_hints,
                    "error": None,
                    "model_id": model_id,
                    "model_messages": messages,
                }
            continue

        # final text
        text = last.content or ""
        messages.append({"role": "assistant", "content": text})
        new_ui.append({"role": "assistant", "content": text})
        return {
            "ok": True,
            "messages": new_ui,
            "pending_confirm": None,
            "ui_hints": ui_hints,
            "error": None,
            "model_id": model_id,
            "model_messages": messages,
        }

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
        "ui_hints": ui_hints,
        "error": None,
        "model_id": model_id,
        "model_messages": messages,
    }


def _slim_message(m: dict[str, Any]) -> dict[str, Any]:
    role = m.get("role")
    out: dict[str, Any] = {"role": role}
    if role == "tool":
        out["name"] = m.get("name")
        out["tool_call_id"] = m.get("tool_call_id") or "call"
        c = m.get("content")
        if isinstance(c, dict):
            out["content"] = tool_result_content(c)
        else:
            out["content"] = str(c or "")[:8000]
        return out
    if role == "assistant" and m.get("tool_calls"):
        out["content"] = m.get("content") or ""
        out["tool_calls"] = m["tool_calls"]
        return out
    out["content"] = str(m.get("content") or "")[:12000]
    return out


def _merge_hints(hints: dict[str, Any], out: Any) -> None:
    if not isinstance(out, dict):
        return
    if out.get("navigate") or out.get("url"):
        hints["navigate"] = out.get("navigate") or out.get("url")
    if out.get("task_id") or out.get("ok") and out.get("action"):
        hints["refresh_run"] = True
    if out.get("task_id"):
        hints["refresh_run"] = True
