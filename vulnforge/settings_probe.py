"""Probe a live LLM endpoint and recommend UI settings.

Used by dashboard **Optimize AI settings**. Tests are cheap, sequential, and
read-only against the model server (no target tree access).

Heuristics are conservative for local / LM Studio style servers.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Optional

import httpx

from vulnforge.settings import DEFAULT_UI_SETTINGS, load_ui_settings, normalize_api_mode

# Tiny tool schema for compliance probe (OpenAI-style).
_PROBE_TOOL = {
    "type": "function",
    "function": {
        "name": "ping",
        "description": "Acknowledge the probe. Call this tool once with message=pong.",
        "parameters": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Must be the string pong"},
            },
            "required": ["message"],
        },
    },
}


def _base_url(host: str, port: int) -> str:
    return f"http://{host.strip()}:{int(port)}/v1"


def model_candidates(requested: str, listed: list[str]) -> list[str]:
    """Ordered unique candidates for model id matching (LM Studio / Ornith quirks)."""
    req = (requested or "").strip()
    out: list[str] = []
    seen: set[str] = set()

    def add(x: str) -> None:
        x = (x or "").strip()
        if not x or x in seen:
            return
        seen.add(x)
        out.append(x)

    add(req)
    if req.startswith("models/"):
        add(req[len("models/") :])
    else:
        add("models/" + req)
    # Case-insensitive exact from server list
    low = {m.lower(): m for m in listed if m}
    for cand in list(out):
        hit = low.get(cand.lower())
        if hit:
            add(hit)
    # Fuzzy: requested stem appears in listed id
    stem = re.sub(r"[^a-z0-9]+", "", req.lower().replace("models/", ""))
    if stem:
        for m in listed:
            m_stem = re.sub(r"[^a-z0-9]+", "", m.lower())
            if stem in m_stem or m_stem in stem:
                add(m)
    return out


# Back-compat private alias
_model_candidates = model_candidates


def resolve_listed_model(requested: str, listed: list[str]) -> Optional[str]:
    """Pick the best listed model id for a configured request string.

    Prefers an id that appears in ``listed`` (case/prefix-normalized). Falls
    back to the configured string when the server list is empty or unmatched
    (some proxies accept unlisted names).
    """
    listed = [str(x) for x in (listed or []) if x]
    if not listed:
        return (requested or "").strip() or None
    for cand in model_candidates(requested, listed):
        if cand in listed:
            return cand
    # Case-insensitive membership
    low = {m.lower(): m for m in listed}
    for cand in model_candidates(requested, listed):
        hit = low.get(cand.lower())
        if hit:
            return hit
    return listed[0]


def _extract_context_tokens(model_obj: dict[str, Any]) -> Optional[int]:
    """Best-effort context window from /v1/models payload variants."""
    if not isinstance(model_obj, dict):
        return None
    for key in (
        "context_length",
        "max_context_length",
        "context_window",
        "max_model_len",
        "n_ctx",
    ):
        v = model_obj.get(key)
        if v is not None:
            try:
                n = int(v)
                if n >= 1024:
                    return n
            except (TypeError, ValueError):
                pass
    meta = model_obj.get("meta") or model_obj.get("metadata") or {}
    if isinstance(meta, dict):
        for key in ("context_length", "max_context_length", "n_ctx"):
            v = meta.get(key)
            if v is not None:
                try:
                    n = int(v)
                    if n >= 1024:
                        return n
                except (TypeError, ValueError):
                    pass
    return None


def _chat_payload(
    model: str,
    *,
    messages: list[dict],
    max_tokens: int = 64,
    tools: Optional[list] = None,
    tool_choice: Any = None,
    temperature: float = 0.0,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if tools is not None:
        body["tools"] = tools
    if tool_choice is not None:
        body["tool_choice"] = tool_choice
    return body


def _post_json(
    client: httpx.Client, url: str, body: dict[str, Any]
) -> tuple[int, dict[str, Any] | str, float]:
    t0 = time.perf_counter()
    try:
        r = client.post(url, json=body)
        elapsed = time.perf_counter() - t0
        try:
            data = r.json()
        except Exception:
            data = (r.text or "")[:500]
        return r.status_code, data, elapsed
    except Exception as e:
        elapsed = time.perf_counter() - t0
        return 0, f"{type(e).__name__}: {e}", elapsed


def _message_has_tool_call(data: dict[str, Any]) -> bool:
    if not isinstance(data, dict):
        return False
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        return False
    msg = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(msg, dict):
        return False
    tcs = msg.get("tool_calls") or msg.get("function_call")
    return bool(tcs)


def _message_content_nonempty(data: dict[str, Any]) -> bool:
    if not isinstance(data, dict):
        return False
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        return False
    msg = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(msg, dict):
        return False
    content = msg.get("content")
    if isinstance(content, str) and content.strip():
        return True
    # Reasoning-only models sometimes only fill reasoning_content
    rc = msg.get("reasoning_content")
    if isinstance(rc, str) and rc.strip():
        return True
    return False


def optimize_ui_settings(
    *,
    host: Optional[str] = None,
    port: Optional[int] = None,
    model: Optional[str] = None,
    apply: bool = False,
    timeout_seconds: float = 90.0,
) -> dict[str, Any]:
    """Probe endpoint and return recommendations.

    Parameters
    ----------
    host, port, model
        Form overrides; defaults from current ui_settings.
    apply
        If True, save recommended settings (still returns full report).
    """
    current = load_ui_settings()
    host = (host if host is not None else current.get("host") or "127.0.0.1").strip()
    try:
        port = int(port if port is not None else current.get("port") or 1234)
    except (TypeError, ValueError):
        port = 1234
    model_req = (model if model is not None else current.get("model") or "").strip()

    tests: list[dict[str, Any]] = []
    warnings: list[str] = []
    recommended = dict(DEFAULT_UI_SETTINGS)
    # Preserve operator caps that are not model-derived
    recommended["host"] = host
    recommended["port"] = port
    recommended["model"] = model_req or recommended["model"]
    recommended["max_tasks"] = int(current.get("max_tasks") or 50)
    recommended["max_concurrent_agents"] = 1  # safe default for local GPUs

    base = _base_url(host, port)
    listed: list[str] = []
    model_objs: list[dict[str, Any]] = []
    resolved_model = model_req
    context_from_card: Optional[int] = None
    best_api_mode = "chat_completions"
    tool_ok = False
    latencies: list[float] = []
    reasoning_heavy = False

    with httpx.Client(timeout=timeout_seconds) as client:
        # ---- 1. /v1/models ----
        t0 = time.perf_counter()
        try:
            r = client.get(f"{base}/models")
            elapsed = time.perf_counter() - t0
            latencies.append(elapsed)
            if r.status_code != 200:
                tests.append(
                    {
                        "id": "models",
                        "ok": False,
                        "detail": f"HTTP {r.status_code}",
                        "seconds": round(elapsed, 3),
                    }
                )
                return {
                    "ok": False,
                    "error": f"Cannot list models at {base}/models (HTTP {r.status_code})",
                    "tests": tests,
                    "recommended": recommended,
                    "current": current,
                    "applied": False,
                }
            body = r.json()
            data = body.get("data") if isinstance(body, dict) else None
            if isinstance(data, list):
                for m in data:
                    if isinstance(m, dict) and m.get("id"):
                        listed.append(str(m["id"]))
                        model_objs.append(m)
            tests.append(
                {
                    "id": "models",
                    "ok": True,
                    "detail": f"{len(listed)} model(s): {', '.join(listed[:6])}"
                    + ("…" if len(listed) > 6 else ""),
                    "seconds": round(elapsed, 3),
                    "models": listed,
                }
            )
        except Exception as e:
            elapsed = time.perf_counter() - t0
            tests.append(
                {
                    "id": "models",
                    "ok": False,
                    "detail": f"{type(e).__name__}: {e}",
                    "seconds": round(elapsed, 3),
                }
            )
            return {
                "ok": False,
                "error": f"Endpoint unreachable at {base}: {e}",
                "tests": tests,
                "recommended": recommended,
                "current": current,
                "applied": False,
            }

        candidates = _model_candidates(model_req, listed)
        if not candidates and listed:
            candidates = [listed[0]]
            warnings.append(
                f"No model id provided; using first listed model {listed[0]!r}."
            )

        # ---- 2. Resolve model id with a tiny completion ----
        chat_url = f"{base}/chat/completions"
        picked = None
        for cand in candidates:
            status, data, elapsed = _post_json(
                client,
                chat_url,
                _chat_payload(
                    cand,
                    messages=[
                        {
                            "role": "user",
                            "content": "Reply with exactly the single word: ok",
                        }
                    ],
                    max_tokens=32,
                ),
            )
            latencies.append(elapsed)
            ok = status == 200 and isinstance(data, dict) and "choices" in data
            detail = f"model={cand!r} HTTP {status}"
            if ok:
                picked = cand
                if isinstance(data, dict):
                    # Detect reasoning-only empty content
                    choices = data.get("choices") or []
                    if choices and isinstance(choices[0], dict):
                        msg = choices[0].get("message") or {}
                        if isinstance(msg, dict):
                            c = msg.get("content")
                            rc = msg.get("reasoning_content")
                            if (not c or not str(c).strip()) and isinstance(rc, str) and rc.strip():
                                reasoning_heavy = True
                tests.append(
                    {
                        "id": "model_resolve",
                        "ok": True,
                        "detail": detail + " (accepted)",
                        "seconds": round(elapsed, 3),
                        "model": cand,
                    }
                )
                break
            else:
                err_snip = ""
                if isinstance(data, dict):
                    err = data.get("error")
                    if isinstance(err, dict):
                        err_snip = str(err.get("message") or err)[:160]
                    elif err:
                        err_snip = str(err)[:160]
                elif isinstance(data, str):
                    err_snip = data[:160]
                tests.append(
                    {
                        "id": "model_resolve_try",
                        "ok": False,
                        "detail": f"{detail} {err_snip}".strip(),
                        "seconds": round(elapsed, 3),
                        "model": cand,
                    }
                )

        if not picked:
            return {
                "ok": False,
                "error": (
                    f"No working model id among candidates {candidates[:5]!r}. "
                    "Check Model id matches /v1/models."
                ),
                "tests": tests,
                "recommended": recommended,
                "current": current,
                "applied": False,
                "warnings": warnings,
            }

        resolved_model = picked
        recommended["model"] = resolved_model

        for m in model_objs:
            if str(m.get("id") or "") == resolved_model:
                context_from_card = _extract_context_tokens(m)
                break

        # ---- 3. API mode probe (chat first already works; try others lightly) ----
        mode_scores: dict[str, bool] = {"chat_completions": True}
        # responses
        status, data, elapsed = _post_json(
            client,
            f"{base}/responses",
            {
                "model": resolved_model,
                "input": "Say ok",
                "max_output_tokens": 16,
            },
        )
        latencies.append(elapsed)
        mode_scores["responses"] = status == 200 and isinstance(data, dict)
        tests.append(
            {
                "id": "api_mode_responses",
                "ok": mode_scores["responses"],
                "detail": f"HTTP {status}",
                "seconds": round(elapsed, 3),
            }
        )
        # messages (Anthropic-style)
        status, data, elapsed = _post_json(
            client,
            f"{base}/messages",
            {
                "model": resolved_model,
                "max_tokens": 16,
                "messages": [{"role": "user", "content": "Say ok"}],
            },
        )
        latencies.append(elapsed)
        mode_scores["messages"] = status == 200 and isinstance(data, dict)
        tests.append(
            {
                "id": "api_mode_messages",
                "ok": mode_scores["messages"],
                "detail": f"HTTP {status}",
                "seconds": round(elapsed, 3),
            }
        )
        # Prefer chat_completions for LM Studio / tool loop; only switch if chat fails
        # (we already proved chat works). Keep chat as best for VulnForge harness.
        best_api_mode = "chat_completions"
        recommended["api_mode"] = best_api_mode

        # ---- 4. Tool-call compliance (critical for recon/hunt) ----
        status, data, elapsed = _post_json(
            client,
            chat_url,
            _chat_payload(
                resolved_model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a tool-using agent. You MUST call the tool "
                            "`ping` with message=pong. Do not only reply in text."
                        ),
                    },
                    {
                        "role": "user",
                        "content": "Call the ping tool now with message pong.",
                    },
                ],
                max_tokens=256,
                tools=[_PROBE_TOOL],
                tool_choice="auto",
            ),
        )
        latencies.append(elapsed)
        tool_ok = status == 200 and isinstance(data, dict) and _message_has_tool_call(data)
        content_ok = status == 200 and isinstance(data, dict) and _message_content_nonempty(data)
        if status == 200 and isinstance(data, dict) and not tool_ok:
            # One retry with forced tool_choice if server supports it
            status2, data2, elapsed2 = _post_json(
                client,
                chat_url,
                _chat_payload(
                    resolved_model,
                    messages=[
                        {
                            "role": "user",
                            "content": "Call the ping tool with message pong.",
                        }
                    ],
                    max_tokens=256,
                    tools=[_PROBE_TOOL],
                    tool_choice={"type": "function", "function": {"name": "ping"}},
                ),
            )
            latencies.append(elapsed2)
            tool_ok = status2 == 200 and isinstance(data2, dict) and _message_has_tool_call(
                data2
            )
            tests.append(
                {
                    "id": "tool_call_forced",
                    "ok": tool_ok,
                    "detail": f"HTTP {status2}",
                    "seconds": round(elapsed2, 3),
                }
            )
        tests.append(
            {
                "id": "tool_call",
                "ok": tool_ok,
                "detail": (
                    "model returned tool_calls"
                    if tool_ok
                    else "no tool_calls — recon may fail with no_submit"
                ),
                "seconds": round(elapsed, 3),
                "content_or_reasoning": content_ok,
            }
        )
        if not tool_ok:
            warnings.append(
                "Model did not emit tool_calls in the probe. Expect recon "
                "`no_submit` / weak tool use. Prefer a tool-capable model or "
                "raise max_tool_rounds and rely on free-text salvage."
            )

        # ---- 5. Latency → timeout + tool rounds heuristics ----
        p95 = sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)] if latencies else 5.0
        avg = sum(latencies) / len(latencies) if latencies else 5.0
        # HTTP timeout: probe latency is optimistic (tiny prompts). Reasoning /
        # tool loops need large headroom over p95 of micro-probes.
        if reasoning_heavy:
            timeout_rec = int(max(600, min(1800, p95 * 200 + 300)))
        else:
            timeout_rec = int(max(180, min(1800, p95 * 80 + 120)))
        # max_tokens: reasoning models need more completion budget
        if reasoning_heavy:
            max_tok = 8192
            warnings.append(
                "Model often returns reasoning_content with empty content; "
                "raised max_tokens for headroom."
            )
        else:
            max_tok = 4096
        # tool rounds: weaker tool compliance → more rounds
        if tool_ok and avg < 8:
            rounds = 12
        elif tool_ok:
            rounds = 16
        else:
            rounds = 20
        # context
        if context_from_card:
            ctx = context_from_card
        else:
            # Name heuristics
            low = resolved_model.lower()
            if "128k" in low:
                ctx = 131072
            elif "32k" in low:
                ctx = 32768
            elif "8k" in low:
                ctx = 8192
            else:
                ctx = int(current.get("context_tokens") or 32768)
        # fraction: smaller models / weak tools keep more room for tools
        if ctx >= 65536:
            frac = 0.3
        elif tool_ok:
            frac = 0.25
        else:
            frac = 0.2

        recommended.update(
            {
                "api_mode": normalize_api_mode(best_api_mode),
                "context_tokens": int(ctx),
                "max_context_fraction": float(frac),
                "max_tokens": int(max_tok),
                "max_tool_rounds": int(rounds),
                "timeout_seconds": int(timeout_rec),
                "max_concurrent_agents": 1,
            }
        )

        tests.append(
            {
                "id": "latency",
                "ok": True,
                "detail": f"avg={avg:.2f}s p95≈{p95:.2f}s → timeout={timeout_rec}s",
                "seconds": round(avg, 3),
            }
        )

    # Diff vs current
    changes: dict[str, dict[str, Any]] = {}
    for k, v in recommended.items():
        if k not in DEFAULT_UI_SETTINGS:
            continue
        cur = current.get(k)
        if cur != v:
            changes[k] = {"from": cur, "to": v}

    applied = False
    if apply:
        from vulnforge.settings import save_ui_settings

        save_ui_settings(recommended)
        applied = True

    summary_bits = [
        f"model={resolved_model}",
        f"api={recommended['api_mode']}",
        f"tools={'yes' if tool_ok else 'NO'}",
        f"ctx={recommended['context_tokens']}",
        f"rounds={recommended['max_tool_rounds']}",
        f"timeout={recommended['timeout_seconds']}s",
    ]

    return {
        "ok": True,
        "error": None,
        "summary": "; ".join(summary_bits),
        "tests": tests,
        "warnings": warnings,
        "recommended": recommended,
        "changes": changes,
        "current": current,
        "resolved_model": resolved_model,
        "listed_models": listed,
        "tool_calls_ok": tool_ok,
        "applied": applied,
        "base_url": base,
    }
