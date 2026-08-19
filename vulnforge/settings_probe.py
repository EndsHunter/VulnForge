"""Probe a live LLM endpoint and recommend UI settings.

Used by dashboard **Settings → Optimize AI settings**. Tests are sequential and
read-only against the model server (no target tree access).

Context is taken from the model card when present, then empirically verified
with tiny-completion prompt-capacity probes (step + binary search). Runtime
recommendations use more of a large discovered window than a conservative
local-server default.
"""

from __future__ import annotations

import re
import time
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
CONTEXT_PROBE_MAX_TOKENS = 262144
CONTEXT_PROBE_MIN_TOKENS = 1024
CONTEXT_PROBE_COMPLETION_TOKENS = 4
CONTEXT_PROBE_PER_REQUEST_S = 25.0
CONTEXT_PROBE_STEPS = (
    1024,
    2048,
    4096,
    8192,
    16384,
    32768,
    65536,
    98304,
    131072,
    196608,
    262144,
)

PostJsonFn = Callable[..., tuple[int, dict[str, Any] | str, float]]


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


def _context_from_model_name(name: str, fallback: int) -> int:
    low = (name or "").lower()
    if "128k" in low:
        return 131072
    if "64k" in low:
        return 65536
    if "32k" in low:
        return 32768
    if "16k" in low:
        return 16384
    if "8k" in low:
        return 8192
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
) -> dict[str, Any]:
    """Map a known context window to ferocious (but bounded) runtime settings."""
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
    if tool_ok and float(avg_latency_s) < 3.0 and not reasoning_heavy:
        workers = 2

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
) -> dict[str, Any]:
    """Empirically find the largest prompt (chars/4 tokens) the endpoint accepts.

    Completions use ``max_tokens`` of 1–8 so only **prompt** capacity is tested.
    When ``claimed`` is set (model card), that size is tried first, then slightly
    above; a fail binary-searches down. Otherwise sizes step up, then binary
    search between last-ok and first-fail.
    """
    post = post_json or _post_json
    t0 = time.perf_counter()
    last_ok: Optional[int] = None
    first_fail: Optional[int] = None
    attempts: list[dict[str, Any]] = []
    cap = max(CONTEXT_PROBE_MIN_TOKENS, min(int(max_size), CONTEXT_PROBE_MAX_TOKENS))
    budget = max(3.0, float(budget_s))

    def remaining() -> float:
        return budget - (time.perf_counter() - t0)

    def try_size(n: int) -> str:
        nonlocal last_ok, first_fail
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
        if _is_chat_ok(status, data):
            outcome = "ok"
            last_ok = actual if last_ok is None else max(last_ok, actual)
        elif _is_over_context(status, data):
            outcome = "over"
            first_fail = actual if first_fail is None else min(first_fail, actual)
        attempts.append(
            {
                "tokens": actual,
                "outcome": outcome,
                "status": status,
                "seconds": round(elapsed, 3),
            }
        )
        return outcome

    def binary_between(lo: int, hi: int) -> None:
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
                break

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
                if up == "over" and last_ok is not None and first_fail is not None:
                    binary_between(last_ok, first_fail)
        elif result == "over":
            lo = CONTEXT_PROBE_MIN_TOKENS
            if remaining() > 3.0:
                low_try = try_size(lo)
                if low_try == "ok" and first_fail is not None:
                    binary_between(last_ok or lo, first_fail)
        # error / timeout: do not treat as a measured window
    else:
        for step in CONTEXT_PROBE_STEPS:
            if step > cap:
                break
            if remaining() < 3.0:
                break
            result = try_size(step)
            if result == "over":
                break
            if result != "ok":
                break
        if last_ok is not None and first_fail is not None and first_fail > last_ok:
            binary_between(last_ok, first_fail)

    elapsed = time.perf_counter() - t0
    measured = last_ok
    ok = last_ok is not None
    if ok:
        detail = f"last_ok={last_ok} first_fail={first_fail} attempts={len(attempts)}"
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
    }


def _recommend_context_tokens(
    *,
    last_ok: Optional[int],
    claimed: Optional[int],
    heuristic: int,
) -> tuple[int, Optional[int], str]:
    """Return (recommended, measured, source)."""
    if last_ok is not None:
        measured = int(last_ok)
        rec = max(CONTEXT_PROBE_MIN_TOKENS, int(measured * 0.9))
        return rec, measured, "empirical"
    if claimed is not None:
        n = max(CONTEXT_PROBE_MIN_TOKENS, int(claimed))
        return n, n, "model_card"
    n = max(CONTEXT_PROBE_MIN_TOKENS, int(heuristic))
    return n, n, "heuristic"


def optimize_ui_settings(
    *,
    host: Optional[str] = None,
    port: Optional[int] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    apply: bool = False,
    timeout_seconds: float = 90.0,
    test_context: bool = True,
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
    host = (host if host is not None else current.get("host") or "127.0.0.1").strip()
    try:
        port = int(port if port is not None else current.get("port") or 1234)
    except (TypeError, ValueError):
        port = 1234
    model_req = (model if model is not None else current.get("model") or "").strip()
    key = normalize_api_key(
        api_key if api_key is not None else current.get("api_key")
    )

    tests: list[dict[str, Any]] = []
    warnings: list[str] = []
    recommended = dict(DEFAULT_UI_SETTINGS)
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
    measured_context_tokens: Optional[int] = None
    context_source = "heuristic"
    optimize_t0 = time.perf_counter()

    probe_headers: dict[str, str] = {}
    if key:
        probe_headers["Authorization"] = f"Bearer {key}"

    with httpx.Client(timeout=timeout_seconds, headers=probe_headers) as client:
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

        # ---- 5. Context window (card + optional empirical probe) ----
        heuristic_ctx = _context_from_model_name(
            resolved_model, int(current.get("context_tokens") or 32768)
        )
        last_ok_ctx: Optional[int] = None
        if test_context:
            used = time.perf_counter() - optimize_t0
            remaining = max(5.0, float(timeout_seconds) - used)
            budget = min(CONTEXT_PROBE_BUDGET_S, remaining)
            probe = probe_context_window(
                client,
                chat_url,
                resolved_model,
                claimed=context_from_card,
                budget_s=budget,
                max_size=CONTEXT_PROBE_MAX_TOKENS,
            )
            last_ok_ctx = probe.get("last_ok")
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
        )
        known_ctx = last_ok_ctx or context_from_card or heuristic_ctx

        # ---- 6. Latency + ferocious runtime heuristics ----
        p95 = sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)] if latencies else 5.0
        avg = sum(latencies) / len(latencies) if latencies else 5.0
        runtime = recommend_runtime_settings(
            ctx=int(known_ctx),
            reasoning_heavy=reasoning_heavy,
            tool_ok=tool_ok,
            avg_latency_s=avg,
            p95_latency_s=p95,
        )
        if reasoning_heavy:
            warnings.append(
                "Model often returns reasoning_content with empty content; "
                "raised max_tokens for headroom."
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

        save_ui_settings(recommended)
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
    }
