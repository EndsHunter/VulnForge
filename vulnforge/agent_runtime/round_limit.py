"""Hard fallback when the agent exhausts tool rounds without submit_*."""

from __future__ import annotations

from typing import Any, Callable, Optional

from vulnforge.llm import LLMResult, ResponseClass

TERMINAL_TOOLS = frozenset(
    {"submit_candidate", "submit_none", "submit_architecture"}
)


def force_submit_enabled(cfg: Optional[dict[str, Any]] = None) -> bool:
    llm = (cfg or {}).get("llm") if isinstance(cfg, dict) else None
    if not isinstance(llm, dict):
        return True  # default on
    if "force_submit_on_round_limit" not in llm:
        return True
    return bool(llm.get("force_submit_on_round_limit"))


def tool_names_from_schema(tools_schema: list | None) -> set[str]:
    names: set[str] = set()
    for t in tools_schema or []:
        if not isinstance(t, dict):
            continue
        fn = t.get("function") if isinstance(t.get("function"), dict) else t
        if isinstance(fn, dict) and fn.get("name"):
            names.add(str(fn["name"]))
    return names


def try_force_terminal_submit(
    tool_handler: Callable[[str, dict], dict],
    tools_schema: list | None,
    *,
    max_rounds: int,
    reason_prefix: str = "auto",
) -> tuple[str | None, dict[str, Any] | None]:
    """Call submit_none or submit_architecture when rounds are exhausted.

    Prefer submit_none (hunt). Recon gets a minimal architecture summary so the
    task does not die without a terminal.
    Returns (tool_name, result) on success, else (None, None).
    """
    names = tool_names_from_schema(tools_schema)
    reason = (
        f"{reason_prefix}: exhausted max_tool_rounds ({max_rounds}) without a "
        f"successful submit_*; residual uncertainty after tool-loop thrash. "
        f"Operator should re-queue if deeper coverage is needed."
    )

    if "submit_none" in names:
        try:
            out = tool_handler("submit_none", {"reason": reason})
        except Exception as e:
            out = {"ok": False, "error": str(e)}
        if isinstance(out, dict) and out.get("ok") is True:
            out = dict(out)
            out["forced"] = True
            out["forced_reason"] = "max_tool_rounds"
            return "submit_none", out

    if "submit_architecture" in names:
        body = {
            "summary": (
                "Incomplete recon: hit max_tool_rounds before a full architecture "
                "map could be submitted. This is an automatic fallback — treat "
                "components/boundaries as partial and re-run recon if needed."
            ),
            "trust_boundaries": [],
            "components": [],
            "input_surfaces": [],
            "hunt_focus": [],
        }
        try:
            out = tool_handler("submit_architecture", body)
        except Exception as e:
            out = {"ok": False, "error": str(e)}
        if isinstance(out, dict) and out.get("ok") is True:
            out = dict(out)
            out["forced"] = True
            out["forced_reason"] = "max_tool_rounds"
            return "submit_architecture", out

    return None, None


def apply_round_limit_fallback(
    result: LLMResult,
    tool_handler: Callable[[str, dict], dict],
    packet: Any,
    *,
    max_rounds: int,
    cfg: Optional[dict[str, Any]] = None,
    transcript: list | None = None,
) -> LLMResult:
    """If result is max_tool_rounds/no_submit thrash, force a terminal submit.

    When successful, returns ok=True so hunt/recon stages store the fallback
    none/architecture instead of aborted coverage thrash.
    """
    if not force_submit_enabled(cfg):
        return result
    if result.ok:
        return result
    err = str(result.error or "").lower()
    # Only auto-submit on round thrash / missing submit — not infra
    if err not in ("max_tool_rounds", "no_submit") and "max_tool_rounds" not in err:
        return result

    schema = getattr(packet, "tools_schema", None) or []
    name, out = try_force_terminal_submit(
        tool_handler, schema, max_rounds=max_rounds
    )
    if not name or not out:
        return result

    tr = list(transcript if transcript is not None else (result.transcript or []))
    tr.append(
        {
            "role": "tool",
            "name": name,
            "content": __import__("json").dumps(out),
        }
    )
    tr.append(
        {
            "role": "assistant",
            "content": (
                f"[harness] Forced {name} after {result.error or 'round limit'} "
                f"(max_tool_rounds={max_rounds})."
            ),
        }
    )
    return LLMResult(
        ok=True,
        classification=ResponseClass.OK,
        content=result.content,
        tool_calls=list(result.tool_calls or [])
        + [{"name": name, "arguments": {"reason": out.get("forced_reason")}}],
        raw={
            **(result.raw if isinstance(result.raw, dict) else {"prior": result.raw}),
            "forced_terminal": name,
            "forced_reason": "max_tool_rounds",
        },
        model_id=result.model_id,
        error=None,
        transcript=tr,
        usage=result.usage,
    )
