"""Context-window pressure for hunt/recon tool loops.

When the conversation nears the model window, inject a nudge that the agent
must call ``continue_hunt`` / ``continue_recon`` (child Ralph task, fresh
context) instead of dying on CONTEXT_LENGTH.
"""

from __future__ import annotations

from typing import Any, Optional

from vulnforge.packet import estimate_tokens

# Default fraction of context_tokens at which we first instruct continue_*.
DEFAULT_CONTINUE_FRACTION = 0.70
# Stronger "MUST call now" band above the warn fraction.
MUST_FRACTION_BUMP = 0.15
MUST_FRACTION_CAP = 0.92

CONTINUE_TOOLS = ("continue_hunt", "continue_recon")


def context_window_tokens(cfg: Optional[dict[str, Any]]) -> int:
    llm = (cfg or {}).get("llm") if isinstance(cfg, dict) else None
    if not isinstance(llm, dict):
        return 32768
    try:
        n = int(llm.get("context_tokens") or 32768)
    except (TypeError, ValueError):
        n = 32768
    return max(1024, n)


def continue_warn_fraction(cfg: Optional[dict[str, Any]]) -> float:
    llm = (cfg or {}).get("llm") if isinstance(cfg, dict) else None
    raw = None
    if isinstance(llm, dict):
        raw = llm.get("continue_context_fraction")
    try:
        frac = float(raw if raw is not None else DEFAULT_CONTINUE_FRACTION)
    except (TypeError, ValueError):
        frac = DEFAULT_CONTINUE_FRACTION
    if frac <= 0:
        return DEFAULT_CONTINUE_FRACTION
    return min(0.95, frac)


def must_fraction(warn_frac: float) -> float:
    return min(MUST_FRACTION_CAP, float(warn_frac) + MUST_FRACTION_BUMP)


def continue_enabled(cfg: Optional[dict[str, Any]]) -> bool:
    llm = (cfg or {}).get("llm") if isinstance(cfg, dict) else None
    if not isinstance(llm, dict):
        return True
    if "continue_on_context" not in llm:
        return True
    return bool(llm.get("continue_on_context"))


def continue_tool_from_schema(tools_schema: list | None) -> Optional[str]:
    names: set[str] = set()
    for t in tools_schema or []:
        if not isinstance(t, dict):
            continue
        fn = t.get("function") if isinstance(t.get("function"), dict) else t
        if isinstance(fn, dict) and fn.get("name"):
            names.add(str(fn["name"]))
    for n in CONTINUE_TOOLS:
        if n in names:
            return n
    return None


def estimate_messages_tokens(messages: list | None) -> int:
    """Rough token count for an OpenAI-style message list."""
    total = 0
    for m in messages or []:
        if not isinstance(m, dict):
            continue
        content = m.get("content")
        if isinstance(content, str):
            total += estimate_tokens(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    text = block.get("text") or block.get("content") or ""
                    if isinstance(text, str):
                        total += estimate_tokens(text)
                    else:
                        total += estimate_tokens(str(block))
                elif isinstance(block, str):
                    total += estimate_tokens(block)
        tcs = m.get("tool_calls")
        if tcs:
            total += estimate_tokens(str(tcs))
    return max(0, total)


def usage_prompt_tokens(usage: Any) -> int:
    if usage is None:
        return 0
    try:
        return int(getattr(usage, "prompt_tokens", 0) or 0)
    except (TypeError, ValueError):
        pass
    if isinstance(usage, dict):
        try:
            return int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0)
        except (TypeError, ValueError):
            return 0
    return 0


def pressure_level(used_tokens: int, window_tokens: int, warn_frac: float) -> str:
    """Return ``none`` | ``warn`` | ``must``."""
    if window_tokens <= 0 or used_tokens <= 0:
        return "none"
    ratio = used_tokens / float(window_tokens)
    if ratio >= must_fraction(warn_frac):
        return "must"
    if ratio >= warn_frac:
        return "warn"
    return "none"


def is_context_overflow_error(error: str | None, classification: Any = None) -> bool:
    err = str(error or "").lower()
    cls = ""
    if classification is not None:
        cls = str(getattr(classification, "value", classification) or "").lower()
    blob = f"{err} {cls}"
    needles = (
        "context_length",
        "context length",
        "context window",
        "maximum context",
        "max context",
        "too many tokens",
        "prompt is too long",
        "please reduce the length",
        "n_ctx",
        "over the context",
    )
    if any(n in blob for n in needles):
        return True
    # finish_reason=length with empty content is often a *completion* budget
    # problem, not a window overflow — only treat as overflow when the error
    # also mentions context / window.
    if "context" in blob and ("length" in blob or "token" in blob):
        return True
    return False


def nudge_text(
    tool_name: str,
    *,
    used_tokens: int,
    window_tokens: int,
    level: str,
) -> str:
    pct = int(round(100.0 * used_tokens / window_tokens)) if window_tokens else 0
    if level == "must":
        return (
            f"CONTEXT CRITICAL ({pct}% of {window_tokens} tokens used). "
            f"You MUST call `{tool_name}` NOW with a detailed handoff of remaining "
            "work (paths already inspected, what is left, open questions). "
            "Do not read more files. After the tool succeeds this task stops; "
            "Ralph will run the child with a fresh context window."
        )
    return (
        f"Context is high ({pct}% of {window_tokens} tokens). "
        f"Call `{tool_name}` soon with remaining work, explored paths, and "
        "what the child should do next. Do not dump huge file reads. "
        "If you already have a candidate or a solid none, submit that instead."
    )


def next_nudge_level(current: str | None, incoming: str) -> str | None:
    """Return a level we have not yet issued (warn < must). None if no new nudge."""
    rank = {None: 0, "none": 0, "": 0, "warn": 1, "must": 2}
    if rank.get(incoming, 0) > rank.get(current, 0) and incoming in ("warn", "must"):
        return incoming
    return None
