"""Probe a live LLM endpoint and recommend UI settings.

Used by dashboard **Settings → Auto-tune**. Tests are sequential and
read-only against the model server (no target tree access).

Context recommendation order is empirical probe, then model card, then a
name heuristic (any ``Nk`` / ``Nm`` marker, including 256k-class windows).
The probe uses tiny completions and walks the ladder upward from a small
prompt. A rung that does not finish, or a slow accept followed by a rung
above the local cap, stops the climb. That measured size is the practical
window. A fast server still reaches the 256k-class rungs inside the budget.
Runtime recommendations use more of a large discovered window than a
conservative local default. ``max_tokens`` is max output and stays capped
separately from context.
"""

from __future__ import annotations

import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Optional
from urllib.parse import quote

import httpx

from vulnforge.packet import estimate_tokens
from vulnforge.settings import (
    DEFAULT_UI_SETTINGS,
    build_llm_base_url,
    load_ui_settings,
    normalize_api_key,
    normalize_api_mode,
    normalize_hunt_perspectives,
)

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

_CONTEXT_KEYS_RUNTIME = (
    "n_ctx",
    "max_model_len",
    "context_length",
    "max_context_length",
    "context_window",
    "max_input_tokens",
    "context_size",
)
_CONTEXT_KEYS_ARCH = (
    "max_position_embeddings",
    "max_seq_len",
    "max_sequence_length",
    "n_ctx_train",
)
_CONTEXT_KEYS = _CONTEXT_KEYS_RUNTIME + _CONTEXT_KEYS_ARCH
_NESTED_CONTEXT_KEYS = (
    "settings",
    "meta",
    "metadata",
    "parameters",
    "llama.cpp",
    "llama_cpp",
    "details",
    "config",
    "model_info",
    "info",
    "architecture",
)

_OVER_CTX_RE = re.compile(
    r"(context|n_ctx|too many|too long|"
    r"max(?:imum)?[_\s-]*(?:context|tokens?|length|seq(?:uence)?(?:[_\s-]*len(?:gth)?)?)|"
    r"token[s]?[_\s-]*(?:limit|length|budget|window|exceed)|"
    r"(?:prompt|input)[_\s-]*(?:too long|too large|exceed)|"
    r"length[_\s-]*(?:limit|exceed)|"
    r"out of memory|\boom\b)",
    re.I,
)

CONTEXT_PROBE_BUDGET_S = 45.0
# 1M-class cap. 256k (262144) is a rung, not the ceiling.
CONTEXT_PROBE_MAX_TOKENS = 1048576
CONTEXT_PROBE_MIN_TOKENS = 1024
CONTEXT_PROBE_COMPLETION_TOKENS = 4
CONTEXT_PROBE_PER_REQUEST_S = 25.0
# Coarse rungs. Binary search fills the gaps. The probe walks these upward.
# A fast server still reaches the large rungs. A slow one stops at the last
# accept instead of opening on a 256k prompt that consumes the whole budget.
CONTEXT_PROBE_STEPS = (
    4096,
    8192,
    32768,
    131072,
    262144,
    524288,
    1048576,
)
# After a slow accept, do not send a prompt larger than this. A shared local
# GPU can spend minutes on a 100k-class prefill.
CONTEXT_PROBE_LOCAL_CAP = 98304
CONTEXT_PROBE_SLOW_SECONDS = 8.0
# Kept so older callers can read the old start rung. The walk no longer uses it.
CONTEXT_PROBE_LARGE_START = 262144
_NAMED_CONTEXT_RE = re.compile(
    r"(?<![a-z0-9])(\d+(?:\.\d+)?)[\s_\-]*([km])(?![a-z0-9])",
    re.IGNORECASE,
)

PostJsonFn = Callable[..., tuple[int, dict[str, Any] | str, float]]
ProgressFn = Callable[[dict[str, Any]], None]


class ProbeCancelled(Exception):
    """The operator cancelled an auto-tune job between steps."""


def _base_url(host: str, port: int) -> str:
    """OpenAI-compatible root; supports https://host and host+port forms."""
    return build_llm_base_url(host, port)


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


def _coerce_context_int(v: Any) -> Optional[int]:
    """Parse a context-window number; accepts ints and strings like ``32k``."""
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        n = int(v)
        return n if n >= 1024 else None
    if isinstance(v, str):
        s = v.strip().lower().replace(",", "").replace("_", "")
        m = re.match(r"^(\d+(?:\.\d+)?)\s*([km])?$", s)
        if not m:
            return None
        n = float(m.group(1))
        suf = m.group(2)
        if suf == "k":
            n *= 1024
        elif suf == "m":
            n *= 1024 * 1024
        n = int(n)
        return n if n >= 1024 else None
    return None


def _extract_context_tokens(model_obj: dict[str, Any], *, _depth: int = 0) -> Optional[int]:
    """Best-effort context window from /v1/models payload variants.

    Prefers runtime keys (``n_ctx``, ``max_model_len``, ``context_length``, …)
    over architecture / train-time keys. Walks ``architecture``, ``parameters``,
    ``settings``, ``meta`` / ``metadata``, and llama.cpp-style nested objects.
    """
    if not isinstance(model_obj, dict) or _depth > 4:
        return None
    for key in _CONTEXT_KEYS:
        n = _coerce_context_int(model_obj.get(key))
        if n is not None:
            return n
    for key in _NESTED_CONTEXT_KEYS:
        nested = model_obj.get(key)
        if isinstance(nested, dict):
            n = _extract_context_tokens(nested, _depth=_depth + 1)
            if n is not None:
                return n
    if _depth < 3:
        skip = set(_NESTED_CONTEXT_KEYS) | set(_CONTEXT_KEYS)
        for key, val in model_obj.items():
            if key in skip or not isinstance(val, dict):
                continue
            n = _extract_context_tokens(val, _depth=_depth + 1)
            if n is not None:
                return n
    return None


def _unwrap_model_payload(payload: Any) -> Optional[dict[str, Any]]:
    if isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, dict):
            return data
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    return item
        return payload
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                return item
    return None


def _named_context_tokens(name: str) -> Optional[int]:
    """Largest context-size token in a model id (``8k``, ``256k``, ``1m``).

    The marker is a number plus a ``k`` or ``m`` suffix on its own, so
    ``128k`` is 131072 and is not read as ``8k``. ``8b`` parameter counts
    do not match. Returns None when the name has no such marker.
    """
    best: Optional[int] = None
    for match in _NAMED_CONTEXT_RE.finditer(name or ""):
        qty = float(match.group(1))
        mult = 1024 if match.group(2).lower() == "k" else 1024 * 1024
        n = int(qty * mult)
        if n < 1024 or n > 16 * 1024 * 1024:
            continue
        if best is None or n > best:
            best = n
    return best


def _context_from_model_name(name: str, fallback: int) -> int:
    named = _named_context_tokens(name)
    if named is not None:
        return named
    return max(1024, int(fallback or 32768))


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
    client: httpx.Client,
    url: str,
    body: dict[str, Any],
    timeout: float | None = None,
) -> tuple[int, dict[str, Any] | str, float]:
    t0 = time.perf_counter()
    try:
        kwargs: dict[str, Any] = {"json": body}
        if timeout is not None:
            kwargs["timeout"] = timeout
        r = client.post(url, **kwargs)
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


def _choice_message(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return {}
    msg = choices[0].get("message")
    return msg if isinstance(msg, dict) else {}


def message_reasoning_text(msg: Any) -> str:
    """Thinking text from either OpenAI-style field local servers use.

    llama.cpp and many proxies send ``reasoning_content``. Flint and some
    other local servers send ``reasoning``. A list under ``reasoning_details``
    is accepted when the string fields are empty.
    """
    if not isinstance(msg, dict):
        return ""
    for key in ("reasoning_content", "reasoning"):
        val = msg.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    details = msg.get("reasoning_details")
    if isinstance(details, list):
        parts: list[str] = []
        for item in details:
            if isinstance(item, str) and item.strip():
                parts.append(item.strip())
            elif isinstance(item, dict):
                for key in ("text", "content", "summary"):
                    val = item.get(key)
                    if isinstance(val, str) and val.strip():
                        parts.append(val.strip())
                        break
        if parts:
            return "\n".join(parts)
    return ""


def message_content_text(msg: Any) -> str:
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content")
    if isinstance(content, str):
        return content.strip()
    return ""


def _usage_counts(data: Any) -> tuple[Optional[int], Optional[int]]:
    """Server ``usage.prompt_tokens`` and ``completion_tokens``, when present."""
    if not isinstance(data, dict):
        return None, None
    usage = data.get("usage")
    if not isinstance(usage, dict):
        return None, None

    def one(key: str) -> Optional[int]:
        val = usage.get(key)
        if val is None or isinstance(val, bool):
            return None
        try:
            n = int(val)
        except (TypeError, ValueError):
            return None
        return n if n >= 0 else None

    return one("prompt_tokens"), one("completion_tokens")


def _message_content_nonempty(data: dict[str, Any]) -> bool:
    msg = _choice_message(data)
    if message_content_text(msg):
        return True
    # Reasoning-only models sometimes only fill a reasoning field.
    return bool(message_reasoning_text(msg))


def _is_slow(status: int, data: Any, elapsed: float, per_req: float) -> bool:
    """A request that did not finish inside its own deadline.

    That is not an over-context error. The previous accept is the practical
    window for this budget.
    """
    if status == 0:
        text = _error_text(data).lower()
        if "timeout" in text or "timed out" in text:
            return True
    if per_req and elapsed >= max(1.0, float(per_req) * 0.92) and status != 200:
        return True
    return False


def _check_cancel(cancel_event: Any) -> None:
    if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
        raise ProbeCancelled("cancelled")


def _emit(on_progress: Optional[ProgressFn], event: dict[str, Any]) -> None:
    if on_progress is not None:
        on_progress(event)


def _error_text(data: dict[str, Any] | str) -> str:
    if isinstance(data, str):
        return data
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict):
            return str(err.get("message") or err)
        if err:
            return str(err)
        return str(data.get("message") or "")[:500]
    return str(data)[:500]


def _is_over_context(status: int, data: dict[str, Any] | str) -> bool:
    # 413 is almost always payload-too-large. 400 is too common for other
    # client errors — require context-like text unless the body is empty.
    if status == 413:
        return True
    text = _error_text(data)
    if status == 400 and not text.strip():
        return True
    return bool(text and _OVER_CTX_RE.search(text))


def _is_chat_ok(status: int, data: dict[str, Any] | str) -> bool:
    return status == 200 and isinstance(data, dict) and "choices" in data


def _incompressible_pad(n_chars: int) -> str:
    if n_chars <= 0:
        return ""
    out: list[str] = []
    i = 0
    size = 0
    while size < n_chars:
        chunk = f"{i:08x}abcdef0123456789"
        out.append(chunk)
        size += len(chunk)
        i += 1
    return "".join(out)[:n_chars]


def messages_for_prompt_tokens(target_tokens: int) -> list[dict[str, str]]:
    """Build a user message whose ``estimate_tokens`` is about ``target_tokens``."""
    prefix = "Ignore the padding below. Reply with the single word ok.\n"
    n = max(CONTEXT_PROBE_MIN_TOKENS, int(target_tokens))
    target_chars = n * 4
    pad_len = max(0, target_chars - len(prefix))
    content = prefix + _incompressible_pad(pad_len)
    # estimate_tokens is len//4; snap to the requested size.
    want = n * 4
    if len(content) > want:
        content = content[:want]
    elif len(content) < want:
        content = content + ("x" * (want - len(content)))
    return [{"role": "user", "content": content}]


def prompt_tokens_of(messages: list[dict]) -> int:
    text = "".join(str(m.get("content") or "") for m in messages if isinstance(m, dict))
    return estimate_tokens(text)


def _fetch_model_card(
    client: httpx.Client, base: str, model_id: str
) -> Optional[dict[str, Any]]:
    mid = (model_id or "").strip()
    if not mid:
        return None
    paths = []
    for raw in (quote(mid, safe=""), quote(mid, safe="/"), mid):
        url = f"{base}/models/{raw}"
        if url not in paths:
            paths.append(url)
    for url in paths:
        try:
            r = client.get(url)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        try:
            payload = r.json()
        except Exception:
            continue
        obj = _unwrap_model_payload(payload)
        if isinstance(obj, dict):
            return obj
    return None


def recommend_runtime_settings(
    *,
    ctx: int,
    reasoning_heavy: bool,
    tool_ok: bool,
    avg_latency_s: float,
    p95_latency_s: float,
    gen_seconds: Optional[float] = None,
    gen_completion_tokens: Optional[int] = None,
    concurrent_parallel: Optional[bool] = None,
) -> dict[str, Any]:
    """Map a known context window to ferocious (but bounded) runtime settings.

    ``concurrent_parallel`` overrides the latency guess when a two-request
    probe actually ran. ``gen_seconds`` is a finished completion sample, not
    a truncated 16-token ping.
    """
    ctx = max(1024, int(ctx))
    if reasoning_heavy:
        max_tok = min(16384, max(8192, ctx // 4))
    else:
        max_tok = min(8192, max(4096, ctx // 6))
    if ctx >= 32768:
        max_tok = max(max_tok, min(8192, max(4096, ctx // 6)))
        if max_tok <= 4096:
            max_tok = min(8192, max(5461, ctx // 6))

    if ctx >= 131072:
        rounds = 24
    elif ctx >= 32768:
        rounds = 20
    else:
        rounds = 12
    if not tool_ok:
        rounds += 4
    rounds = max(12, int(rounds))

    if ctx >= 131072:
        frac = 0.35
    elif ctx >= 32768:
        frac = 0.30
    elif (not tool_ok) and ctx < 16384:
        frac = 0.20
    else:
        frac = 0.25

    p95 = max(0.0, float(p95_latency_s))
    if reasoning_heavy:
        timeout_rec = int(max(600, min(1800, p95 * 200 + 300)))
    else:
        timeout_rec = int(max(180, min(1800, p95 * 80 + 120)))
    if ctx >= 131072 or reasoning_heavy:
        timeout_rec = max(timeout_rec, 900)

    workers = 1
    if concurrent_parallel is False:
        workers = 1
    elif concurrent_parallel is True and not reasoning_heavy:
        workers = 2
    elif tool_ok and float(avg_latency_s) < 3.0 and not reasoning_heavy:
        workers = 2

    if (
        gen_seconds is not None
        and gen_completion_tokens is not None
        and float(gen_seconds) > 0
        and int(gen_completion_tokens) > 0
    ):
        per_tok = float(gen_seconds) / float(gen_completion_tokens)
        projected = per_tok * int(max_tok) * 1.5 + 90
        timeout_rec = int(max(timeout_rec, min(1800, projected)))

    return {
        "max_tokens": int(max_tok),
        "max_tool_rounds": int(rounds),
        "max_context_fraction": float(frac),
        "timeout_seconds": int(timeout_rec),
        "max_concurrent_agents": int(workers),
    }


def probe_context_window(
    client: Any,
    chat_url: str,
    model: str,
    *,
    claimed: Optional[int] = None,
    budget_s: float = CONTEXT_PROBE_BUDGET_S,
    max_size: int = CONTEXT_PROBE_MAX_TOKENS,
    post_json: Optional[PostJsonFn] = None,
    on_progress: Optional[ProgressFn] = None,
    cancel_event: Any = None,
) -> dict[str, Any]:
    """Empirically find the largest prompt the endpoint accepts in this budget.

    Completions use ``max_tokens`` of 1–8 so only **prompt** capacity is tested.
    When the server reports ``usage.prompt_tokens``, that count is the measured
    size. The local chars/4 estimate only sizes the request.

    When ``claimed`` is set (model card or a context-size token in the model
    id), that size is tried first, then slightly above. An over-context reject
    binary-searches down. A timeout walks down to the largest rung that finishes.

    With no claim, the ladder starts at 4k and walks up. A rung that times out
    stops the climb. After an accept slower than
    ``CONTEXT_PROBE_SLOW_SECONDS``, the next rung above
    ``CONTEXT_PROBE_LOCAL_CAP`` is not sent. A fast server still climbs through
    the 256k-class rungs. Binary search closes a hard over-context gap.
    """
    post = post_json or _post_json
    t0 = time.perf_counter()
    last_ok: Optional[int] = None
    first_fail: Optional[int] = None
    attempts: list[dict[str, Any]] = []
    scales: list[float] = []
    time_bounded = False
    cap = max(CONTEXT_PROBE_MIN_TOKENS, min(int(max_size), CONTEXT_PROBE_MAX_TOKENS))
    budget = max(3.0, float(budget_s))

    def remaining() -> float:
        return budget - (time.perf_counter() - t0)

    def try_size(n: int) -> str:
        nonlocal last_ok, first_fail
        _check_cancel(cancel_event)
        n = max(CONTEXT_PROBE_MIN_TOKENS, min(int(n), cap))
        if remaining() < 2.0:
            return "timeout"
        per_req = min(CONTEXT_PROBE_PER_REQUEST_S, max(4.0, remaining() - 0.5))
        messages = messages_for_prompt_tokens(n)
        actual = prompt_tokens_of(messages)
        status, data, elapsed = post(
            client,
            chat_url,
            _chat_payload(
                model,
                messages=messages,
                max_tokens=CONTEXT_PROBE_COMPLETION_TOKENS,
            ),
            timeout=per_req,
        )
        outcome = "error"
        server_prompt: Optional[int] = None
        if _is_chat_ok(status, data):
            outcome = "ok"
            server_prompt, _completion = _usage_counts(data)
            recorded = actual
            if isinstance(server_prompt, int) and server_prompt >= 128 and actual > 0:
                recorded = server_prompt
                scales.append(server_prompt / actual)
            last_ok = recorded if last_ok is None else max(last_ok, recorded)
        elif _is_over_context(status, data):
            outcome = "over"
            first_fail = actual if first_fail is None else min(first_fail, actual)
        elif _is_slow(status, data, elapsed, per_req):
            outcome = "slow"
        attempt = {
            "tokens": actual,
            "outcome": outcome,
            "status": status,
            "seconds": round(elapsed, 3),
        }
        if server_prompt is not None:
            attempt["server_prompt"] = server_prompt
        attempts.append(attempt)
        _emit(
            on_progress,
            {
                "id": "context_attempt",
                "detail": f"{actual} tokens → {outcome} ({elapsed:.1f}s)",
                "tokens": actual,
                "outcome": outcome,
                "seconds": round(elapsed, 3),
            },
        )
        return outcome

    def binary_between(lo: int, hi: int) -> None:
        nonlocal time_bounded
        lo = max(CONTEXT_PROBE_MIN_TOKENS, int(lo))
        hi = max(lo + 1, int(hi))
        while hi - lo > 2048 and remaining() > 3.0:
            mid = (lo + hi) // 2
            result = try_size(mid)
            if result == "ok":
                lo = mid
            elif result == "over":
                hi = mid
            else:
                if result == "slow":
                    time_bounded = True
                break

    def steps_under(limit: int) -> list[int]:
        return [
            s
            for s in CONTEXT_PROBE_STEPS
            if CONTEXT_PROBE_MIN_TOKENS <= s <= cap and s < limit
        ]

    claimed_n: Optional[int] = None
    if claimed is not None:
        try:
            claimed_n = int(claimed)
        except (TypeError, ValueError):
            claimed_n = None
        if claimed_n is not None and claimed_n < CONTEXT_PROBE_MIN_TOKENS:
            claimed_n = None

    if claimed_n:
        target = min(cap, max(CONTEXT_PROBE_MIN_TOKENS, claimed_n))
        result = try_size(target)
        if result == "ok":
            above = min(cap, max(int(target * 1.1), target + 4096))
            if above > target and remaining() > 3.0:
                up = try_size(above)
                if up == "slow":
                    time_bounded = True
                elif up == "over" and last_ok is not None and first_fail is not None:
                    binary_between(last_ok, first_fail)
        elif result == "over":
            lo = CONTEXT_PROBE_MIN_TOKENS
            if remaining() > 3.0:
                low_try = try_size(lo)
                if low_try == "ok" and first_fail is not None:
                    binary_between(last_ok or lo, first_fail)
        elif result == "slow":
            time_bounded = True
            for step in reversed(steps_under(target)):
                if remaining() < 3.0:
                    break
                sub = try_size(step)
                if sub == "ok":
                    break
                if sub == "over":
                    break
                if sub == "slow":
                    continue
                break
        # other errors are not a measured window
    else:
        steps = [s for s in CONTEXT_PROBE_STEPS if CONTEXT_PROBE_MIN_TOKENS <= s <= cap]
        if not steps or steps[-1] != cap:
            steps.append(cap)
        prev_seconds = 0.0
        for step in steps:
            if remaining() < 3.0:
                break
            if prev_seconds > CONTEXT_PROBE_SLOW_SECONDS and step > CONTEXT_PROBE_LOCAL_CAP:
                time_bounded = True
                _emit(
                    on_progress,
                    {
                        "id": "context_stop",
                        "detail": (
                            f"stopped before {step} tokens; the previous accept "
                            f"took {prev_seconds:.1f}s"
                        ),
                    },
                )
                break
            result = try_size(step)
            if attempts:
                prev_seconds = float(attempts[-1].get("seconds") or 0.0)
            if result == "ok":
                continue
            if result == "over":
                if last_ok is not None and first_fail is not None and first_fail > last_ok:
                    binary_between(last_ok, first_fail)
                elif last_ok is None and remaining() > 3.0:
                    if try_size(CONTEXT_PROBE_MIN_TOKENS) == "ok" and first_fail is not None:
                        binary_between(last_ok or CONTEXT_PROBE_MIN_TOKENS, first_fail)
                break
            if result == "slow":
                time_bounded = True
                break
            break

    elapsed = time.perf_counter() - t0
    measured = last_ok
    ok = last_ok is not None
    token_scale = (sum(scales) / len(scales)) if scales else None
    if ok:
        detail = (
            f"last_ok={last_ok} first_fail={first_fail} attempts={len(attempts)}"
            + (" time_bounded" if time_bounded else "")
        )
    else:
        detail = f"no successful prompt-capacity probe ({len(attempts)} attempt(s))"
    return {
        "ok": ok,
        "last_ok": last_ok,
        "first_fail": first_fail,
        "measured_tokens": measured,
        "seconds": round(elapsed, 3),
        "attempts": attempts,
        "detail": detail,
        "claimed": claimed_n,
        "time_bounded": time_bounded,
        "token_scale": token_scale,
    }


def _recommend_context_tokens(
    *,
    last_ok: Optional[int],
    claimed: Optional[int],
    heuristic: int,
    ceiling: bool = True,
    time_bounded: bool = False,
) -> tuple[int, Optional[int], str]:
    """Return (recommended, measured, source).

    ``source`` is ``empirical``, ``model_card``, or ``heuristic``.
    A partial accept with no over-context ceiling does not override a
    larger model-card or name-heuristic window (the ladder ran out of
    budget before the real limit). A time-bounded accept does: the next
    size did not finish, so the larger name is not usable here.
    """
    if last_ok is not None and time_bounded:
        measured = int(last_ok)
        rec = max(CONTEXT_PROBE_MIN_TOKENS, int(measured * 0.9))
        return rec, measured, "empirical"
    if last_ok is not None:
        measured = int(last_ok)
        larger_prior = max(int(claimed or 0), int(heuristic or 0))
        if ceiling or measured >= larger_prior:
            rec = max(CONTEXT_PROBE_MIN_TOKENS, int(measured * 0.9))
            return rec, measured, "empirical"
    if claimed is not None:
        n = max(CONTEXT_PROBE_MIN_TOKENS, int(claimed))
        return n, n, "model_card"
    n = max(CONTEXT_PROBE_MIN_TOKENS, int(heuristic))
    return n, n, "heuristic"


def _endpoint_from_settings(current: dict[str, Any]) -> tuple[str, Any, str, str]:
    """Host, port, model, api key for the global budget probe.

    Prefers the flat fields (legacy callers). Otherwise the default role's host.
    """
    if current.get("host") or (isinstance(current.get("model"), str) and current.get("model")):
        return (
            str(current.get("host") or "127.0.0.1"),
            current.get("port") if current.get("port") is not None else 1234,
            str(current.get("model") or "") if not isinstance(current.get("model"), dict) else "",
            str(current.get("api_key") or ""),
        )
    ref = current.get("model") if isinstance(current.get("model"), dict) else None
    hosts = current.get("hosts") or []
    if isinstance(ref, dict) and isinstance(hosts, list):
        hid = str(ref.get("host_id") or "")
        for host in hosts:
            if isinstance(host, dict) and str(host.get("id") or "") == hid:
                return (
                    str(host.get("base_url") or ""),
                    None,
                    str(ref.get("model_id") or ""),
                    str(host.get("api_key") or ""),
                )
    return ("127.0.0.1", 1234, "", "")


def list_model_ids(base_url: str, api_key: str = "", *, timeout: float = 20.0) -> list[str]:
    """GET ``{base_url}/models``. Raises on transport or non-200."""
    key = normalize_api_key(api_key)
    headers: dict[str, str] = {}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    url = str(base_url or "").rstrip("/") + "/models"
    with httpx.Client(timeout=timeout, headers=headers) as client:
        response = client.get(url)
        response.raise_for_status()
        body = response.json()
    data = body.get("data") if isinstance(body, dict) else body
    if not isinstance(data, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in data:
        if isinstance(item, dict) and item.get("id"):
            mid = str(item["id"]).strip()
        elif isinstance(item, str):
            mid = item.strip()
        else:
            continue
        if not mid or mid in seen:
            continue
        seen.add(mid)
        out.append(mid)
    return out


def verify_model_pair(
    *,
    base_url: str,
    api_mode: str,
    api_key: str = "",
    model_id: str,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """One completion against this host and model. Does not search other hosts."""
    mode = normalize_api_mode(api_mode)
    key = normalize_api_key(api_key)
    headers: dict[str, str] = {}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    base = str(base_url or "").rstrip("/")
    model_id = str(model_id or "").strip()
    if mode == "responses":
        url = base + "/responses"
        payload: dict[str, Any] = {
            "model": model_id,
            "input": "Reply with ok",
            "max_output_tokens": 16,
        }
    elif mode == "messages":
        url = base + "/messages"
        payload = {
            "model": model_id,
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "Reply with ok"}],
        }
    else:
        url = base + "/chat/completions"
        payload = {
            "model": model_id,
            "messages": [{"role": "user", "content": "Reply with ok"}],
            "max_tokens": 16,
        }
    try:
        with httpx.Client(timeout=timeout, headers=headers) as client:
            response = client.post(url, json=payload)
    except Exception as exc:
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}
    if response.status_code != 200:
        detail = f"HTTP {response.status_code}"
        try:
            body = response.json()
            if isinstance(body, dict) and body.get("error"):
                detail = f"{detail} {body.get('error')}"[:240]
        except ValueError:
            pass
        return {"ok": False, "detail": detail}
    try:
        data = response.json()
    except Exception:
        return {"ok": False, "detail": "response was not JSON"}
    if isinstance(data, dict) and data.get("error"):
        return {"ok": False, "detail": str(data.get("error"))[:240]}
    msg = _choice_message(data)
    if message_reasoning_text(msg) and not message_content_text(msg):
        return {
            "ok": True,
            "detail": (
                f"HTTP 200 {mode}; thinking used the token budget and no answer came back. "
                "Auto-tune will raise max output."
            ),
        }
    return {"ok": True, "detail": f"HTTP 200 {mode}"}


def _probe_concurrency(
    post: PostJsonFn,
    client: Any,
    chat_url: str,
    model: str,
) -> dict[str, Any]:
    """Two short requests at once, against one request alone.

    A result under 50ms on both sides is too fast to trust (unit-test fakes).
    Parallel means the pair finished in under 1.7× the single request.
    """
    payload = _chat_payload(
        model,
        messages=[{"role": "user", "content": "Reply with ok. concurrency-probe"}],
        max_tokens=8,
    )
    status, _data, one = post(client, chat_url, payload, timeout=20)
    if status != 200:
        return {
            "measured": False,
            "parallel": None,
            "one_seconds": round(one, 3),
            "two_seconds": None,
            "detail": f"baseline HTTP {status}",
        }
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(post, client, chat_url, payload, 20) for _ in range(2)]
        rows = [fut.result() for fut in futures]
    wall = time.perf_counter() - t0
    ok = all(row[0] == 200 for row in rows)
    if not ok or (one < 0.05 and wall < 0.05):
        return {
            "measured": False,
            "parallel": None,
            "one_seconds": round(one, 3),
            "two_seconds": round(wall, 3),
            "detail": "too fast to measure" if ok else "a parallel request failed",
        }
    parallel = wall < (one * 1.7)
    how = "overlapped" if parallel else "ran one after the other"
    return {
        "measured": True,
        "parallel": parallel,
        "one_seconds": round(one, 3),
        "two_seconds": round(wall, 3),
        "detail": f"one={one:.2f}s two={wall:.2f}s ({how})",
    }


def _first_tool_call(data: Any) -> Optional[dict[str, Any]]:
    msg = _choice_message(data)
    calls = msg.get("tool_calls")
    if isinstance(calls, list):
        for call in calls:
            if isinstance(call, dict):
                return call
    function_call = msg.get("function_call")
    if isinstance(function_call, dict) and function_call.get("name"):
        return {"id": "probe", "type": "function", "function": function_call}
    return None


def _probe_tool_loop(
    post: PostJsonFn,
    client: Any,
    chat_url: str,
    model: str,
    first: dict[str, Any] | str,
) -> dict[str, Any]:
    """Second turn: feed the tool result back and ask for a short answer.

    One toy tool call is not a hunt loop. This checks the model can read a
    tool result and answer. A server that only echoes the first call still
    counts as a failed loop, not a failed probe.
    """
    call = _first_tool_call(first)
    if call is None:
        return {"ok": False, "detail": "no tool call to continue", "seconds": 0.0}
    call_id = str(call.get("id") or "probe")
    function = call.get("function") if isinstance(call.get("function"), dict) else {}
    status, data, elapsed = post(
        client,
        chat_url,
        _chat_payload(
            model,
            messages=[
                {
                    "role": "user",
                    "content": "Call the ping tool now with message pong.",
                },
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [call],
                },
                {
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": "pong",
                },
                {
                    "role": "user",
                    "content": "The tool returned. Reply with the single word pong.",
                },
            ],
            max_tokens=256,
        ),
        timeout=30,
    )
    msg = _choice_message(data)
    content = message_content_text(msg)
    ok = status == 200 and bool(content)
    name = function.get("name") or "tool"
    detail = f"HTTP {status} after {name}"
    if ok:
        detail = f"continued after {name}"
    elif status == 200:
        detail = f"HTTP 200 but no answer after {name}"
    return {"ok": ok, "detail": detail, "seconds": round(elapsed, 3)}


def build_setting_recommendations(
    *,
    host_id: str = "",
    model_id: str = "",
    recommended: dict[str, Any],
    context_source: str,
    time_bounded: bool,
    measured_context: Optional[int],
    token_scale: Optional[float],
    reasoning_heavy: bool,
    reasoning_field: str,
    tool_ok: bool,
    tool_loop_ok: Optional[bool],
    gen_seconds: Optional[float],
    gen_completion_tokens: Optional[int],
    concurrency: Optional[dict[str, Any]],
) -> list[dict[str, Any]]:
    """One row per knob the operator can accept on its own."""
    rows: list[dict[str, Any]] = []

    def add(
        key: str,
        scope: str,
        confidence: str,
        reason: str,
        measurements: dict[str, Any],
    ) -> None:
        if recommended.get(key) is None:
            return
        row: dict[str, Any] = {
            "key": key,
            "value": recommended.get(key),
            "scope": scope,
            "confidence": confidence,
            "reason": reason,
            "measurements": measurements,
        }
        if scope == "pair":
            row["host_id"] = host_id
            row["model_id"] = model_id
        rows.append(row)

    if context_source == "empirical" and not time_bounded:
        ctx_confidence = "high"
        ctx_reason = (
            f"Largest prompt the server accepted"
            + (f" ({measured_context} tokens)" if measured_context else "")
            + ". The next size was rejected as over context. "
            "The recommendation keeps 90% of that accept."
        )
    elif context_source == "empirical" and time_bounded:
        ctx_confidence = "medium"
        ctx_reason = (
            "Largest prompt that finished inside the probe budget"
            + (f" ({measured_context} tokens)" if measured_context else "")
            + ". The next size did not finish, so this is a practical window, "
            "not a hard maximum. The recommendation keeps 90% of that accept."
        )
    elif context_source == "model_card":
        ctx_confidence = "medium"
        ctx_reason = "Taken from the model card. The prompt probe did not confirm it."
    else:
        ctx_confidence = "low"
        ctx_reason = "No measurement and no model card. This is the name heuristic or the current seed."
    if token_scale and token_scale > 1.15:
        ctx_reason += (
            f" The server's prompt token count was about {token_scale:.2f}× the local estimate, "
            "and the measured size uses the server count."
        )
    add(
        "context_tokens",
        "pair",
        ctx_confidence,
        ctx_reason,
        {
            "measured_tokens": measured_context,
            "source": context_source,
            "time_bounded": time_bounded,
            "token_scale": token_scale,
        },
    )

    if reasoning_heavy:
        tok_confidence = "medium" if not gen_completion_tokens else "high"
        field = reasoning_field or "reasoning"
        tok_reason = (
            f"The model writes thinking in `{field}` before the answer. "
            "A short max output is spent on thinking and the hunt sees an empty reply. "
            f"Max output is {recommended.get('max_tokens')} so a turn can finish thinking and still answer."
        )
    else:
        tok_confidence = "medium"
        tok_reason = (
            f"Max output {recommended.get('max_tokens')} is a share of the context window, "
            "capped so one completion cannot consume the whole window."
        )
    add(
        "max_tokens",
        "pair",
        tok_confidence,
        tok_reason,
        {
            "reasoning_heavy": reasoning_heavy,
            "gen_seconds": gen_seconds,
            "gen_completion_tokens": gen_completion_tokens,
        },
    )

    conc = concurrency or {}
    if conc.get("measured") and conc.get("parallel") is False:
        workers_confidence = "high"
        workers_reason = (
            "Two short requests ran one after the other. "
            "This server handles a single completion at a time, so concurrent agents stay at 1."
        )
    elif conc.get("measured") and conc.get("parallel") is True:
        workers_confidence = "high"
        workers_reason = (
            "Two short requests overlapped, so two agents can run."
            if not reasoning_heavy
            else "Two short requests overlapped, but a reasoning model holds the GPU for a long turn, so concurrent agents stay at 1."
        )
    elif int(recommended.get("max_concurrent_agents") or 1) >= 2:
        workers_confidence = "low"
        workers_reason = (
            "Not measured. Latency on the tiny probes was low, so the guess is 2. "
            "Two concurrent prefills can OOM a local GPU."
        )
    else:
        workers_confidence = "low"
        workers_reason = "Not measured. Left at 1, which is the safe default for a local GPU."
    add(
        "max_concurrent_agents",
        "pair",
        workers_confidence,
        workers_reason,
        {
            "one_seconds": conc.get("one_seconds"),
            "two_seconds": conc.get("two_seconds"),
            "parallel": conc.get("parallel"),
        },
    )

    if tool_loop_ok:
        rounds_confidence = "medium"
        rounds_reason = (
            f"The model called a tool and then answered from the tool result. "
            f"Max tool rounds is {recommended.get('max_tool_rounds')}."
        )
    elif tool_ok:
        rounds_confidence = "low"
        rounds_reason = (
            "The model emitted one tool call. A follow-up turn was not confirmed. "
            f"Max tool rounds is {recommended.get('max_tool_rounds')}."
        )
    else:
        rounds_confidence = "low"
        rounds_reason = (
            "The model did not emit a tool call. Extra rounds leave room for a later salvage. "
            "Recon can still end with no submit."
        )
    add("max_tool_rounds", "global", rounds_confidence, rounds_reason, {"tool_ok": tool_ok, "tool_loop_ok": tool_loop_ok})

    if gen_seconds and gen_completion_tokens:
        timeout_confidence = "medium"
        rate = float(gen_completion_tokens) / float(gen_seconds) if gen_seconds else 0
        per_tok = float(gen_seconds) / float(gen_completion_tokens)
        max_tok = int(recommended.get("max_tokens") or 0)
        projected = int(min(1800, per_tok * max_tok * 1.5 + 90)) if max_tok else 0
        chosen = int(recommended.get("timeout_seconds") or 0)
        if reasoning_heavy and chosen > projected + 30:
            timeout_reason = (
                f"A {gen_completion_tokens}-token completion took {gen_seconds:.1f}s "
                f"({rate:.1f} tok/s). That sample would only need about {projected}s. "
                f"The timeout stays at {chosen}s because this model thinks before it answers, "
                "and a short sample does not show a full thinking turn."
            )
        else:
            timeout_reason = (
                f"A {gen_completion_tokens}-token completion took {gen_seconds:.1f}s "
                f"({rate:.1f} tok/s). The timeout covers the recommended max output, "
                "with room for prefill, and is capped at 1800s."
            )
    elif reasoning_heavy:
        timeout_confidence = "medium"
        timeout_reason = (
            "No finished generation sample. A reasoning model needs a long timeout; "
            f"{recommended.get('timeout_seconds')}s is the floor for that case."
        )
    else:
        timeout_confidence = "low"
        timeout_reason = (
            "Derived from the tiny probe latencies, not from a full completion. "
            "Raise it if hunts die on a read timeout."
        )
    add(
        "timeout_seconds",
        "global",
        timeout_confidence,
        timeout_reason,
        {"gen_seconds": gen_seconds, "gen_completion_tokens": gen_completion_tokens},
    )

    add(
        "max_context_fraction",
        "global",
        "low",
        (
            f"Fraction {recommended.get('max_context_fraction')} of the context window "
            "is packed into one prompt. This stays global and is not written onto the model row."
        ),
        {},
    )
    return rows


def optimize_ui_settings(
    *,
    host: Optional[str] = None,
    port: Optional[int] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    apply: bool = False,
    timeout_seconds: float = 90.0,
    test_context: bool = True,
    strict_model: bool = False,
    on_progress: Optional[ProgressFn] = None,
    cancel_event: Any = None,
) -> dict[str, Any]:
    """Probe endpoint and return recommendations.

    Parameters
    ----------
    host, port, model, api_key
        Form overrides; defaults from current ui_settings.
        api_key blank/none is fine (no Authorization header).
    apply
        If True, save recommended settings (still returns full report).
    test_context
        If True (default), empirically probe prompt capacity. Set False to
        use only the model card / name heuristic.
    """
    current = load_ui_settings()
    derived_host, derived_port, derived_model, derived_key = _endpoint_from_settings(current)
    host = (host if host is not None else derived_host or "127.0.0.1").strip()
    try:
        port = int(port if port is not None else derived_port or 1234)
    except (TypeError, ValueError):
        port = 1234
    model_req = (model if model is not None else derived_model or "").strip()
    key = normalize_api_key(api_key if api_key is not None else derived_key)

    tests: list[dict[str, Any]] = []
    warnings: list[str] = []
    recommended = dict(DEFAULT_UI_SETTINGS)
    # Fresh lists — do not share mutable defaults. Keep hunt slots the operator
    # already saved; optimize must not reset them or copy validate_models.
    recommended["validate_models"] = list(DEFAULT_UI_SETTINGS.get("validate_models") or [])
    recommended["model_validate"] = current.get("model_validate")
    recommended["hunt_moa"] = bool(current.get("hunt_moa", False))
    recommended["hunt_perspectives"] = normalize_hunt_perspectives(
        current.get("hunt_perspectives")
    )
    # Preserve operator caps that are not model-derived
    recommended["host"] = host
    recommended["port"] = port
    recommended["model"] = model_req or recommended["model"]
    recommended["api_key"] = key  # never invent a key; preserve form/current
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
    reasoning_field = ""
    measured_context_tokens: Optional[int] = None
    context_source = "heuristic"
    time_bounded = False
    token_scale: Optional[float] = None
    gen_seconds: Optional[float] = None
    gen_completion_tokens: Optional[int] = None
    tool_loop_ok: Optional[bool] = None
    concurrency: dict[str, Any] = {}
    optimize_t0 = time.perf_counter()

    def progress(step: str, detail: str, **extra: Any) -> None:
        _check_cancel(cancel_event)
        event: dict[str, Any] = {"id": step, "detail": detail}
        event.update(extra)
        _emit(on_progress, event)

    probe_headers: dict[str, str] = {}
    if key:
        probe_headers["Authorization"] = f"Bearer {key}"

    with httpx.Client(timeout=timeout_seconds, headers=probe_headers) as client:
        # ---- 1. /v1/models ----
        progress("models", f"Listing models at {base}")
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
                    "measured_context_tokens": None,
                    "context_source": None,
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
                "measured_context_tokens": None,
                "context_source": None,
            }

        if strict_model and model_req not in listed:
            return {
                "ok": False,
                "error": f"{model_req or '(empty)'} is not listed on this host",
                "tests": tests,
                "recommended": recommended,
                "current": current,
                "applied": False,
                "warnings": warnings,
                "measured_context_tokens": None,
                "context_source": None,
                "resolved_model": None,
                "listed_models": listed,
            }
        candidates = _model_candidates(model_req, listed)
        if strict_model:
            # The selected id only. Do not fall through to another model on this host.
            candidates = [model_req]
        elif not candidates and listed:
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
                msg = _choice_message(data)
                if message_reasoning_text(msg) and not message_content_text(msg):
                    reasoning_heavy = True
                    if isinstance(msg.get("reasoning"), str) and msg.get("reasoning", "").strip():
                        reasoning_field = "reasoning"
                    else:
                        reasoning_field = "reasoning_content"
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
                "measured_context_tokens": None,
                "context_source": None,
            }

        resolved_model = picked
        recommended["model"] = resolved_model

        for m in model_objs:
            if str(m.get("id") or "") == resolved_model:
                context_from_card = _extract_context_tokens(m)
                break

        if context_from_card is None:
            card = _fetch_model_card(client, base, resolved_model)
            if card:
                context_from_card = _extract_context_tokens(card)
                tests.append(
                    {
                        "id": "model_card",
                        "ok": context_from_card is not None,
                        "detail": (
                            f"GET /models/{{id}} context={context_from_card}"
                            if context_from_card
                            else "GET /models/{id} had no context field"
                        ),
                        "seconds": 0.0,
                    }
                )

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
            timeout=8,
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
            timeout=8,
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
        tool_body: Any = data if tool_ok else None
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
            if tool_ok:
                tool_body = data2
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
        elif tool_body is not None:
            progress("tool_loop", "Sending the tool result back for a second turn")
            loop = _probe_tool_loop(post=_post_json, client=client, chat_url=chat_url, model=resolved_model, first=tool_body)
            tool_loop_ok = bool(loop.get("ok"))
            tests.append(
                {
                    "id": "tool_loop",
                    "ok": tool_loop_ok,
                    "detail": loop.get("detail") or "",
                    "seconds": loop.get("seconds") or 0.0,
                }
            )
            if not tool_loop_ok:
                warnings.append(
                    "The model emitted a tool call but did not answer after the tool result."
                )

        # A finished completion, not the 16–32 token ping. Reasoning models
        # spend a short budget on thinking and never answer.
        progress("generation", "Measuring a finished completion")
        sample_max = 1024 if reasoning_heavy else 256
        status, gen_data, gen_elapsed = _post_json(
            client,
            chat_url,
            _chat_payload(
                resolved_model,
                messages=[
                    {
                        "role": "user",
                        "content": "Reply with exactly the single word ok",
                    }
                ],
                max_tokens=sample_max,
            ),
            timeout=45,
        )
        latencies.append(gen_elapsed)
        gen_msg = _choice_message(gen_data)
        gen_content = message_content_text(gen_msg)
        gen_reason = message_reasoning_text(gen_msg)
        _gen_prompt, gen_completion_tokens = _usage_counts(gen_data)
        if gen_reason and not gen_content:
            reasoning_heavy = True
            if isinstance(gen_msg.get("reasoning"), str) and str(gen_msg.get("reasoning")).strip():
                reasoning_field = "reasoning"
            elif not reasoning_field:
                reasoning_field = "reasoning_content"
        if status == 200 and gen_content:
            gen_seconds = gen_elapsed
            if not gen_completion_tokens:
                gen_completion_tokens = max(1, len(gen_content) // 4)
        tests.append(
            {
                "id": "generation",
                "ok": status == 200 and bool(gen_content),
                "detail": (
                    f"answer in {gen_elapsed:.2f}s"
                    + (f", {gen_completion_tokens} completion tokens" if gen_completion_tokens else "")
                    + (", reasoning field held the tokens" if reasoning_heavy and not gen_content else "")
                ),
                "seconds": round(gen_elapsed, 3),
            }
        )

        progress("concurrency", "Checking whether two requests run together")
        concurrency = _probe_concurrency(_post_json, client, chat_url, resolved_model)
        tests.append(
            {
                "id": "concurrency",
                "ok": True,
                "detail": concurrency.get("detail") or "",
                "seconds": concurrency.get("two_seconds") or concurrency.get("one_seconds") or 0.0,
            }
        )

        # ---- 5. Context window (card + optional empirical probe) ----
        progress("context", "Walking the context window upward")
        named_ctx = _named_context_tokens(resolved_model)
        heuristic_ctx = (
            named_ctx
            if named_ctx is not None
            else max(1024, int(current.get("context_tokens") or 32768))
        )
        # Try the card first. A size token in the model id is only a probe
        # hint — it must not be recorded as model_card.
        probe_hint = context_from_card if context_from_card is not None else named_ctx
        last_ok_ctx: Optional[int] = None
        probe_ceiling = False
        if test_context:
            used = time.perf_counter() - optimize_t0
            remaining = max(5.0, float(timeout_seconds) - used)
            budget = min(CONTEXT_PROBE_BUDGET_S, remaining)
            probe = probe_context_window(
                client,
                chat_url,
                resolved_model,
                claimed=probe_hint,
                budget_s=budget,
                max_size=CONTEXT_PROBE_MAX_TOKENS,
                on_progress=on_progress,
                cancel_event=cancel_event,
            )
            last_ok_ctx = probe.get("last_ok")
            time_bounded = bool(probe.get("time_bounded"))
            token_scale = probe.get("token_scale")
            aimed = probe_hint if probe_hint is not None else CONTEXT_PROBE_MAX_TOKENS
            aimed = min(int(CONTEXT_PROBE_MAX_TOKENS), int(aimed))
            reached_aim = last_ok_ctx is not None and int(last_ok_ctx) >= int(aimed * 0.9)
            probe_ceiling = probe.get("first_fail") is not None or reached_aim
            tests.append(
                {
                    "id": "context_window",
                    "ok": bool(probe.get("ok")),
                    "detail": probe.get("detail") or "",
                    "seconds": probe.get("seconds") or 0.0,
                    "measured_tokens": probe.get("measured_tokens"),
                    "source": "empirical" if probe.get("ok") else (
                        "model_card" if context_from_card else "heuristic"
                    ),
                    "last_ok": last_ok_ctx,
                    "first_fail": probe.get("first_fail"),
                    "claimed": context_from_card,
                }
            )
            if not probe.get("ok"):
                warnings.append(
                    "Context window was not empirically verified; using "
                    "model card / name heuristic. Large prompt probes may have "
                    "timed out or the server rejected the capacity test."
                )
        else:
            tests.append(
                {
                    "id": "context_window",
                    "ok": context_from_card is not None,
                    "detail": (
                        f"skipped empirical test; card={context_from_card}"
                        if context_from_card
                        else "skipped empirical test; no model-card window"
                    ),
                    "seconds": 0.0,
                    "measured_tokens": context_from_card,
                    "source": "model_card" if context_from_card else "heuristic",
                }
            )

        rec_ctx, measured_context_tokens, context_source = _recommend_context_tokens(
            last_ok=last_ok_ctx,
            claimed=context_from_card,
            heuristic=heuristic_ctx,
            ceiling=probe_ceiling,
            time_bounded=time_bounded,
        )
        for row in tests:
            if row.get("id") == "context_window":
                row["source"] = context_source
                break
        if (
            test_context
            and last_ok_ctx is not None
            and context_source != "empirical"
        ):
            warnings.append(
                "Context probe accepted a prompt but did not reach an "
                "over-context ceiling before the time budget; using the "
                "model card or name heuristic."
            )
        known_ctx = int(rec_ctx)

        # ---- 6. Latency + ferocious runtime heuristics ----
        p95 = sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)] if latencies else 5.0
        avg = sum(latencies) / len(latencies) if latencies else 5.0
        runtime = recommend_runtime_settings(
            ctx=int(known_ctx),
            reasoning_heavy=reasoning_heavy,
            tool_ok=tool_ok,
            avg_latency_s=avg,
            p95_latency_s=p95,
            gen_seconds=gen_seconds,
            gen_completion_tokens=gen_completion_tokens,
            concurrent_parallel=concurrency.get("parallel") if concurrency.get("measured") else None,
        )
        if reasoning_heavy:
            warnings.append(
                "Model returns thinking in a reasoning field with empty content; "
                "raised max_tokens so a turn can finish thinking and still answer."
            )
        if token_scale and float(token_scale) > 1.15:
            warnings.append(
                "The server counted more prompt tokens than the local estimate. "
                "The measured context window uses the server count."
            )
        if runtime["max_concurrent_agents"] >= 2:
            warnings.append(
                "Recommending max_concurrent_agents=2. Two concurrent prefills "
                "can OOM a local GPU — drop to 1 if VRAM is tight."
            )

        recommended.update(
            {
                "api_mode": normalize_api_mode(best_api_mode),
                "context_tokens": int(rec_ctx),
                "max_context_fraction": float(runtime["max_context_fraction"]),
                "max_tokens": int(runtime["max_tokens"]),
                "max_tool_rounds": int(runtime["max_tool_rounds"]),
                "timeout_seconds": int(runtime["timeout_seconds"]),
                "max_concurrent_agents": int(runtime["max_concurrent_agents"]),
            }
        )

        tests.append(
            {
                "id": "latency",
                "ok": True,
                "detail": (
                    f"avg={avg:.2f}s p95≈{p95:.2f}s → "
                    f"timeout={runtime['timeout_seconds']}s"
                ),
                "seconds": round(avg, 3),
            }
        )

    # Diff vs current (never echo raw api_key secrets)
    changes: dict[str, dict[str, Any]] = {}
    for k, v in recommended.items():
        if k not in DEFAULT_UI_SETTINGS:
            continue
        cur = current.get(k)
        if cur != v:
            if k == "api_key":
                changes[k] = {
                    "from": "(set)" if normalize_api_key(cur) else "(empty)",
                    "to": "(set)" if normalize_api_key(v) else "(empty)",
                }
            else:
                changes[k] = {"from": cur, "to": v}

    applied = False
    if apply:
        from vulnforge.settings import save_ui_settings

        # Legacy single-endpoint apply writes globals only.
        # Per-pair apply is optimize_selected_pairs.
        save_ui_settings(
            {
                "context_tokens": recommended.get("context_tokens"),
                "max_context_fraction": recommended.get("max_context_fraction"),
                "max_tokens": recommended.get("max_tokens"),
                "max_tool_rounds": recommended.get("max_tool_rounds"),
                "timeout_seconds": recommended.get("timeout_seconds"),
                "max_concurrent_agents": recommended.get("max_concurrent_agents"),
            }
        )
        applied = True

    summary_bits = [
        f"model={resolved_model}",
        f"api={recommended['api_mode']}",
        f"tools={'yes' if tool_ok else 'NO'}",
        f"ctx={recommended['context_tokens']}",
        f"ctx_src={context_source}",
        f"rounds={recommended['max_tool_rounds']}",
        f"timeout={recommended['timeout_seconds']}s",
    ]
    if measured_context_tokens is not None:
        summary_bits.append(f"measured={measured_context_tokens}")

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
        "measured_context_tokens": measured_context_tokens,
        "context_source": context_source,
        "time_bounded": time_bounded,
        "recommendations": build_setting_recommendations(
            recommended=recommended,
            context_source=context_source,
            time_bounded=time_bounded,
            measured_context=measured_context_tokens,
            token_scale=float(token_scale) if token_scale else None,
            reasoning_heavy=reasoning_heavy,
            reasoning_field=reasoning_field,
            tool_ok=tool_ok,
            tool_loop_ok=tool_loop_ok,
            gen_seconds=gen_seconds,
            gen_completion_tokens=gen_completion_tokens,
            concurrency=concurrency,
        ),
    }


def optimize_selected_pairs(
    *,
    targets: list[dict[str, Any]],
    apply: bool = False,
    timeout_seconds: float = 90.0,
    test_context: bool = True,
    on_progress: Optional[ProgressFn] = None,
    cancel_event: Any = None,
) -> dict[str, Any]:
    """Probe each selected ``(host_id, model_id)`` on that host.

    Explicit only: callers pass the pairs. This does not run on settings
    open and does not pick a single global model. Recommendations for
    ``max_tokens`` and ``context_tokens`` stay on that pair. Globals,
    including ``max_context_fraction``, are not rewritten. ``apply`` writes
    the two knobs onto the matching available rows and leaves every other
    pair untouched.
    """
    from vulnforge.settings.catalog import (
        apply_submitted_budgets,
        find_host,
        pair_available,
    )
    from vulnforge.settings.ui import save_ui_settings

    current = load_ui_settings()
    results: list[dict[str, Any]] = []
    for raw in targets or []:
        if not isinstance(raw, dict):
            results.append(
                {
                    "host_id": "",
                    "model_id": "",
                    "ok": False,
                    "error": "not an available (host, model) pair",
                }
            )
            continue
        hid = str(raw.get("host_id") or "").strip()
        mid = str(raw.get("model_id") or "").strip()
        host = find_host(current.get("hosts"), hid)
        if host is None or not pair_available(current.get("available"), hid, mid):
            results.append(
                {
                    "host_id": hid,
                    "model_id": mid,
                    "ok": False,
                    "error": f"{mid or '(empty)'} on host {hid or '(empty)'} is not available",
                }
            )
            continue
        _check_cancel(cancel_event)
        _emit(
            on_progress,
            {"id": "pair", "detail": f"{mid} on {hid}", "host_id": hid, "model_id": mid},
        )
        try:
            probed = optimize_ui_settings(
                host=str(host.get("base_url") or ""),
                port=None,
                model=mid,
                api_key=str(host.get("api_key") or ""),
                apply=False,
                timeout_seconds=timeout_seconds,
                test_context=test_context,
                strict_model=True,
                on_progress=on_progress,
                cancel_event=cancel_event,
            )
        except ProbeCancelled:
            results.append(
                {
                    "host_id": hid,
                    "model_id": mid,
                    "ok": False,
                    "error": "cancelled",
                    "recommendations": [],
                }
            )
            break
        rec = probed.get("recommended") if isinstance(probed.get("recommended"), dict) else {}
        ok = bool(probed.get("ok"))
        recommendations = []
        for item in probed.get("recommendations") or []:
            if not isinstance(item, dict):
                continue
            stamped = dict(item)
            if stamped.get("scope") == "pair":
                stamped["host_id"] = hid
                stamped["model_id"] = mid
            recommendations.append(stamped)
        results.append(
            {
                "host_id": hid,
                "model_id": mid,
                "ok": ok,
                "error": None if ok else (probed.get("error") or "probe failed"),
                "context_tokens": rec.get("context_tokens") if ok else None,
                "max_tokens": rec.get("max_tokens") if ok else None,
                "max_concurrent_agents": rec.get("max_concurrent_agents") if ok else None,
                "measured_context_tokens": probed.get("measured_context_tokens"),
                "context_source": probed.get("context_source"),
                "summary": probed.get("summary") or "",
                "warnings": list(probed.get("warnings") or []),
                "tests": list(probed.get("tests") or []),
                "recommendations": recommendations,
                "base_url": str(host.get("base_url") or ""),
            }
        )
        if not ok and probed.get("error") == "cancelled":
            break

    applied = False
    if apply:
        submitted = [
            {
                "host_id": row["host_id"],
                "model_id": row["model_id"],
                "max_tokens": row.get("max_tokens"),
                "context_tokens": row.get("context_tokens"),
            }
            for row in results
            if row.get("ok") and row.get("max_tokens") and row.get("context_tokens")
        ]
        if submitted:
            updated = apply_submitted_budgets(list(current.get("available") or []), submitted)
            save_ui_settings({"available": updated})
            applied = True

    failed = [row for row in results if not row.get("ok")]
    summary = "; ".join(
        (
            f"{row['model_id']}@{row['host_id']} ctx={row.get('context_tokens')} max={row.get('max_tokens')}"
            if row.get("ok")
            else f"{row.get('model_id') or '?'}@{row.get('host_id') or '?'}: {row.get('error')}"
        )
        for row in results
    )
    return {
        "ok": bool(results) and not failed,
        "error": None if not failed else (failed[0].get("error") or "probe failed"),
        "summary": summary,
        "targets": results,
        "applied": applied,
        "current": current,
        "warnings": [w for row in results for w in (row.get("warnings") or [])],
        "recommendations": [
            item
            for row in results
            for item in (row.get("recommendations") or [])
            if isinstance(item, dict)
        ],
    }


_JOBS_LOCK = threading.Lock()
_JOBS: dict[str, dict[str, Any]] = {}
_JOB_KEEP = 40


def start_optimize_job(
    *,
    targets: list[dict[str, Any]],
    test_context: bool = True,
    timeout_seconds: float = 180.0,
) -> str:
    """Run pair auto-tune on a daemon thread. Poll with ``get_optimize_job``."""
    job_id = uuid.uuid4().hex
    cancel_event = threading.Event()
    job: dict[str, Any] = {
        "id": job_id,
        "status": "running",
        "events": [],
        "result": None,
        "error": None,
        "_cancel": cancel_event,
    }
    with _JOBS_LOCK:
        _JOBS[job_id] = job
        if len(_JOBS) > _JOB_KEEP:
            for old in list(_JOBS):
                if len(_JOBS) <= _JOB_KEEP:
                    break
                if old != job_id and _JOBS[old].get("status") != "running":
                    _JOBS.pop(old, None)

    def on_progress(event: dict[str, Any]) -> None:
        row = dict(event)
        row["at"] = time.time()
        with _JOBS_LOCK:
            events = job["events"]
            events.append(row)
            if len(events) > 200:
                del events[: len(events) - 200]

    def run() -> None:
        try:
            result = optimize_selected_pairs(
                targets=targets,
                apply=False,
                timeout_seconds=timeout_seconds,
                test_context=test_context,
                on_progress=on_progress,
                cancel_event=cancel_event,
            )
            status = "cancelled" if result.get("error") == "cancelled" else "done"
            with _JOBS_LOCK:
                if job["status"] != "cancelling":
                    job["status"] = status
                else:
                    job["status"] = "cancelled"
                job["result"] = result
        except ProbeCancelled:
            with _JOBS_LOCK:
                job["status"] = "cancelled"
                job["error"] = "cancelled"
        except Exception as exc:
            with _JOBS_LOCK:
                job["status"] = "error"
                job["error"] = f"{type(exc).__name__}: {exc}"

    threading.Thread(target=run, name=f"vf-autotune-{job_id[:8]}", daemon=True).start()
    return job_id


def get_optimize_job(job_id: str) -> Optional[dict[str, Any]]:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            return None
        return {
            "ok": True,
            "job_id": job_id,
            "status": job["status"],
            "events": list(job["events"]),
            "result": job["result"],
            "error": job["error"],
        }


def cancel_optimize_job(job_id: str) -> bool:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            return False
        job["_cancel"].set()
        if job["status"] == "running":
            job["status"] = "cancelling"
    return True
