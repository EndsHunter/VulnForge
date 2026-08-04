"""Normalize Strands agent messages → VulnForge OpenAI-ish transcript shape."""

from __future__ import annotations

import json
from typing import Any


def strands_messages_to_openaiish(messages: list[Any]) -> list[dict[str, Any]]:
    """Map Strands ``agent.messages`` into roles user|assistant|tool.

    Tool results in Strands arrive as ``user`` messages with ``toolResult``
    content blocks. VulnForge tool-gaps / dashboard expect ``role: tool`` and
    assistant ``tool_calls`` with ``function.name`` / ``function.arguments``.
    """
    out: list[dict[str, Any]] = []
    for m in messages or []:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        content = m.get("content")
        if role == "user" and isinstance(content, list):
            tool_results = [
                b.get("toolResult")
                for b in content
                if isinstance(b, dict) and "toolResult" in b
            ]
            texts = [
                str(b.get("text", ""))
                for b in content
                if isinstance(b, dict) and "text" in b
            ]
            if tool_results:
                for tr in tool_results:
                    if not isinstance(tr, dict):
                        continue
                    body = tr.get("content") or []
                    text_parts: list[str] = []
                    for part in body:
                        if isinstance(part, dict) and "text" in part:
                            text_parts.append(str(part["text"]))
                    out.append(
                        {
                            "role": "tool",
                            "tool_call_id": tr.get("toolUseId") or "call",
                            "name": None,
                            "content": "\n".join(text_parts)
                            if text_parts
                            else json.dumps(tr),
                            "status": tr.get("status"),
                        }
                    )
            elif texts:
                out.append({"role": "user", "content": "\n".join(texts)})
            else:
                out.append({"role": "user", "content": json.dumps(content)})
        elif role == "assistant" and isinstance(content, list):
            texts: list[str] = []
            tool_calls: list[dict[str, Any]] = []
            for b in content:
                if not isinstance(b, dict):
                    continue
                if "text" in b and b["text"] is not None:
                    texts.append(str(b["text"]))
                if "toolUse" in b and isinstance(b["toolUse"], dict):
                    tu = b["toolUse"]
                    args = tu.get("input") or {}
                    tool_calls.append(
                        {
                            "id": tu.get("toolUseId") or "call",
                            "type": "function",
                            "function": {
                                "name": tu.get("name"),
                                "arguments": json.dumps(args)
                                if not isinstance(args, str)
                                else args,
                            },
                        }
                    )
            msg: dict[str, Any] = {
                "role": "assistant",
                "content": "\n".join(texts) if texts else "",
            }
            if tool_calls:
                msg["tool_calls"] = tool_calls
            out.append(msg)
        elif role in ("user", "assistant", "system", "tool"):
            out.append(
                {
                    "role": role,
                    "content": content
                    if isinstance(content, str)
                    else json.dumps(content),
                }
            )

    pending: dict[str, str] = {}
    for msg in out:
        if msg.get("role") == "assistant":
            for tc in msg.get("tool_calls") or []:
                fn = tc.get("function") or {}
                tid = tc.get("id")
                name = fn.get("name")
                if tid and name:
                    pending[str(tid)] = str(name)
        if msg.get("role") == "tool" and not msg.get("name"):
            tid = str(msg.get("tool_call_id") or "")
            if tid in pending:
                msg["name"] = pending[tid]
    return out


def openaiish_to_strands_messages(messages: list[Any]) -> list[dict[str, Any]]:
    """Convert VulnForge OpenAI-ish history into Strands content-block messages.

    Skips system messages (pass those as ``system_prompt``). Tool results become
    user messages with ``toolResult`` blocks (Strands convention).
    """
    out: list[dict[str, Any]] = []
    for m in messages or []:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        if role == "system":
            continue
        if role == "user":
            text = m.get("content")
            if isinstance(text, list):
                # already block-shaped
                out.append({"role": "user", "content": text})
            else:
                out.append(
                    {"role": "user", "content": [{"text": str(text or "")}]}
                )
        elif role == "assistant":
            content: list[dict[str, Any]] = []
            text = m.get("content")
            if isinstance(text, str) and text:
                content.append({"text": text})
            for tc in m.get("tool_calls") or []:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get("function") or {}
                args_raw = fn.get("arguments") or "{}"
                if isinstance(args_raw, str):
                    try:
                        args = json.loads(args_raw)
                    except json.JSONDecodeError:
                        args = {}
                else:
                    args = args_raw if isinstance(args_raw, dict) else {}
                content.append(
                    {
                        "toolUse": {
                            "toolUseId": tc.get("id") or "call",
                            "name": fn.get("name") or "tool",
                            "input": args,
                        }
                    }
                )
            if content:
                out.append({"role": "assistant", "content": content})
        elif role == "tool":
            body = m.get("content")
            if isinstance(body, dict):
                text = json.dumps(body)
            else:
                text = str(body or "")
            out.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "toolResult": {
                                "toolUseId": m.get("tool_call_id") or "call",
                                "status": "success",
                                "content": [{"text": text}],
                            }
                        }
                    ],
                }
            )
    return out


def strip_reasoning_from_strands_messages(messages: list[Any]) -> None:
    """In-place: drop reasoningContent blocks that break multi-turn Chat Completions.

    Ornith-class models may emit reasoning; the OpenAI Chat Completions path in
    Strands warns and can fail on subsequent turns if those blocks remain.
    """
    for m in messages or []:
        if not isinstance(m, dict):
            continue
        content = m.get("content")
        if not isinstance(content, list):
            continue
        cleaned = []
        for b in content:
            if not isinstance(b, dict):
                cleaned.append(b)
                continue
            if "reasoningContent" in b or "reasoning_content" in b:
                continue
            cleaned.append(b)
        m["content"] = cleaned
