"""
OpenAI-compatible LLM client for LM Studio (Ornith, etc.).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

import httpx


class ResponseClass(str, Enum):
    OK = "ok"
    EMPTY = "empty"
    TRUNCATED = "truncated"
    ERROR_TEXT = "error_text"
    CONTEXT_LENGTH = "context_length"
    TRANSPORT = "transport"
    UNKNOWN = "unknown"


@dataclass
class TokenUsage:
    """Normalized token accounting for one LLM HTTP call (or a summed loop)."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    reasoning_tokens: int = 0
    source: str = "none"  # provider | estimate | none
    raw: Optional[dict] = None
    llm_calls: int = 1

    def add(self, other: Optional["TokenUsage"]) -> "TokenUsage":
        if other is None:
            return self
        src = self.source
        if other.source == "provider" or (
            other.source == "estimate" and src in ("none", "estimate")
        ):
            if src == "none":
                src = other.source
            elif src == "estimate" and other.source == "provider":
                src = "provider"
            elif src == "provider" and other.source == "estimate":
                src = "mixed"
            elif src != other.source and other.source != "none":
                src = "mixed" if src != "none" else other.source
        if self.source == "provider" and other.source == "provider":
            src = "provider"
        if self.source == "mixed" or other.source == "mixed":
            src = "mixed"
        return TokenUsage(
            prompt_tokens=int(self.prompt_tokens) + int(other.prompt_tokens),
            completion_tokens=int(self.completion_tokens) + int(other.completion_tokens),
            total_tokens=int(self.total_tokens) + int(other.total_tokens),
            reasoning_tokens=int(self.reasoning_tokens) + int(other.reasoning_tokens),
            source=src if src != "none" else other.source,
            raw=None,
            llm_calls=int(self.llm_calls) + int(other.llm_calls),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "prompt_tokens": int(self.prompt_tokens),
            "completion_tokens": int(self.completion_tokens),
            "total_tokens": int(self.total_tokens),
            "reasoning_tokens": int(self.reasoning_tokens),
            "source": self.source,
            "llm_calls": int(self.llm_calls),
        }

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> Optional["TokenUsage"]:
        if not isinstance(data, dict):
            return None
        return cls(
            prompt_tokens=int(data.get("prompt_tokens") or 0),
            completion_tokens=int(data.get("completion_tokens") or 0),
            total_tokens=int(data.get("total_tokens") or 0),
            reasoning_tokens=int(data.get("reasoning_tokens") or 0),
            source=str(data.get("source") or "none"),
            raw=data.get("raw") if isinstance(data.get("raw"), dict) else None,
            llm_calls=int(data.get("llm_calls") or 1),
        )


def parse_usage_from_body(body: Any) -> TokenUsage:
    """Extract usage from OpenAI chat, Responses API, or Anthropic Messages bodies."""
    if not isinstance(body, dict):
        return TokenUsage(source="none", llm_calls=1)
    usage = body.get("usage")
    if not isinstance(usage, dict):
        # Some proxies nest under response.usage
        resp = body.get("response")
        if isinstance(resp, dict) and isinstance(resp.get("usage"), dict):
            usage = resp["usage"]
        else:
            return TokenUsage(source="none", llm_calls=1, raw=None)

    def _i(*keys: str) -> int:
        for k in keys:
            if k in usage and usage[k] is not None:
                try:
                    return max(0, int(usage[k]))
                except (TypeError, ValueError):
                    continue
        return 0

    prompt = _i("prompt_tokens", "input_tokens", "prompt_token_count")
    completion = _i("completion_tokens", "output_tokens", "completion_token_count")
    total = _i("total_tokens")
    reasoning = 0
    details = usage.get("completion_tokens_details") or usage.get(
        "output_tokens_details"
    )
    if isinstance(details, dict):
        try:
            reasoning = max(0, int(details.get("reasoning_tokens") or 0))
        except (TypeError, ValueError):
            reasoning = 0
    if reasoning == 0:
        reasoning = _i("reasoning_tokens")
    if total <= 0:
        total = prompt + completion
    if prompt == 0 and completion == 0 and total == 0:
        return TokenUsage(source="none", llm_calls=1, raw=dict(usage))
    return TokenUsage(
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=total,
        reasoning_tokens=reasoning,
        source="provider",
        raw=dict(usage),
        llm_calls=1,
    )


def estimate_usage_from_messages(
    messages: list[dict],
    content: Optional[str] = None,
    tool_calls: Optional[list[dict]] = None,
) -> TokenUsage:
    """Char/4 estimate when the provider omits usage (common on some local servers)."""
    from vulnforge.packet import estimate_tokens

    prompt_chars = 0
    for m in messages or []:
        if not isinstance(m, dict):
            continue
        c = m.get("content")
        if isinstance(c, str):
            prompt_chars += len(c)
        elif c is not None:
            prompt_chars += len(json.dumps(c, default=str))
        tcs = m.get("tool_calls")
        if tcs:
            prompt_chars += len(json.dumps(tcs, default=str))
    comp_chars = len(content or "")
    if tool_calls:
        comp_chars += len(json.dumps(tool_calls, default=str))
    # Rough text: estimate_tokens is len//4
    prompt = max(1, estimate_tokens("x" * max(1, prompt_chars))) if prompt_chars else 0
    completion = (
        max(1, estimate_tokens("x" * max(1, comp_chars))) if comp_chars else 0
    )
    return TokenUsage(
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=prompt + completion,
        source="estimate",
        llm_calls=1,
    )


def _attach_usage(result: LLMResult, body: Any = None) -> LLMResult:
    """Populate result.usage from body when missing."""
    if result.usage is not None and result.usage.source not in ("none",):
        return result
    raw = body if body is not None else result.raw
    usage = parse_usage_from_body(raw)
    if usage.source == "none":
        # Leave none for callers that can estimate from messages
        result.usage = usage
    else:
        result.usage = usage
    return result


@dataclass
class LLMResult:
    ok: bool
    classification: ResponseClass
    content: Optional[str]
    tool_calls: list[dict]
    raw: Any
    model_id: Optional[str]
    error: Optional[str] = None
    # Full multi-turn chat log for dashboard (optional)
    transcript: list[dict] = field(default_factory=list)
    reasoning_content: Optional[str] = None
    usage: Optional[TokenUsage] = None


class InfraError(Exception):
    """Retryable infrastructure failure (Ralph exit 20)."""


class ConfigError(Exception):
    """Hard configuration error (Ralph exit 30)."""


_ERROR_PATTERNS = re.compile(
    r"(rate limit|overloaded|model not found|model unloaded|context length|"
    r"maximum context|out of memory|connection refused|econnreset|"
    r"error loading|failed to load)",
    re.I,
)


class LLMClient:
    def __init__(self, cfg: dict):
        llm = cfg.get("llm") or {}
        self.base_url = str(llm.get("base_url", "http://127.0.0.1:1234/v1")).rstrip("/")
        self.model = llm.get("model") or ""
        from vulnforge.settings import normalize_api_key, normalize_api_mode

        # Optional. Blank / none / null → no auth headers (local LM Studio, etc.).
        # When the key is omitted entirely from config, keep a harmless local default
        # for OpenAI-compatible servers that require a Bearer token string.
        if "api_key" in llm:
            self.api_key = normalize_api_key(llm.get("api_key"))
        else:
            self.api_key = "lm-studio"
        self.timeout = float(llm.get("timeout_seconds", 600))
        # Reasoning models (e.g. Ornith) spend tokens on reasoning_content first;
        # a low max_tokens yields empty content + finish_reason=length.
        self.default_max_tokens = int(llm.get("max_tokens", 4096))

        self.api_mode = normalize_api_mode(llm.get("api_mode"))
        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if self.api_mode == "messages":
            # Anthropic Messages API often requires a version header (proxies may ignore).
            headers["anthropic-version"] = str(
                llm.get("anthropic_version") or "2023-06-01"
            )
            if self.api_key and self.api_key != "lm-studio":
                headers["x-api-key"] = str(self.api_key)
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout,
            headers=headers,
        )
        self._resolved_model: Optional[str] = None

    def close(self) -> None:
        self._client.close()

    def fingerprint_model(self) -> str:
        try:
            r = self._client.get("/models")
            r.raise_for_status()
            data = r.json()
            ids = [m.get("id") for m in (data.get("data") or []) if m.get("id")]
        except Exception as e:
            raise InfraError(f"models list failed: {e}") from e
        from vulnforge.settings_probe import resolve_listed_model

        resolved = resolve_listed_model(self.model or "", ids)
        if resolved:
            self._resolved_model = resolved
            return resolved
        if ids:
            self._resolved_model = ids[0]
            return ids[0]
        raise InfraError("no models available at LM Studio endpoint")

    def chat(
        self,
        messages: list[dict],
        tools: Optional[list[dict]] = None,
        temperature: float = 0.3,
        max_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> LLMResult:
        model = self._resolved_model or self.model or self.fingerprint_model()
        mt = max_tokens if max_tokens is not None else self.default_max_tokens
        if self.api_mode == "responses":
            return self._chat_responses(
                model, messages, tools, temperature, mt, timeout=timeout
            )
        if self.api_mode == "messages":
            return self._chat_messages(
                model, messages, tools, temperature, mt, timeout=timeout
            )
        return self._chat_completions(
            model, messages, tools, temperature, mt, timeout=timeout
        )

    def _post_json(
        self,
        path: str,
        payload: dict[str, Any],
        model: str,
        *,
        timeout: Optional[float] = None,
    ) -> LLMResult | dict:
        """POST JSON; on transport failure return LLMResult, else parsed body dict + status via tuple.

        Returns either an error LLMResult or a dict with keys status_code, body.
        Optional ``timeout`` overrides the client default for this request only.
        """
        try:
            if timeout is not None:
                r = self._client.post(path, json=payload, timeout=float(timeout))
            else:
                r = self._client.post(path, json=payload)
        except Exception as e:
            return LLMResult(
                ok=False,
                classification=ResponseClass.TRANSPORT,
                content=None,
                tool_calls=[],
                raw=None,
                model_id=model,
                error=str(e),
            )
        try:
            body = r.json()
        except Exception:
            return LLMResult(
                ok=False,
                classification=ResponseClass.TRANSPORT,
                content=None,
                tool_calls=[],
                raw=r.text,
                model_id=model,
                error=f"non-json status={r.status_code}",
            )
        return {"status_code": r.status_code, "body": body}

    def _chat_completions(
        self,
        model: str,
        messages: list[dict],
        tools: Optional[list[dict]],
        temperature: float,
        max_tokens: int,
        *,
        timeout: Optional[float] = None,
    ) -> LLMResult:
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        out = self._post_json("/chat/completions", payload, model, timeout=timeout)
        if isinstance(out, LLMResult):
            return out
        return classify_response(out["status_code"], out["body"], model=model)

    def _chat_responses(
        self,
        model: str,
        messages: list[dict],
        tools: Optional[list[dict]],
        temperature: float,
        max_tokens: int,
        *,
        timeout: Optional[float] = None,
    ) -> LLMResult:
        payload: dict[str, Any] = {
            "model": model,
            "input": chat_messages_to_responses_input(messages),
            "temperature": temperature,
            "max_output_tokens": max_tokens,
            "store": False,
        }
        if tools:
            payload["tools"] = openai_tools_to_responses(tools)
            payload["tool_choice"] = "auto"
        out = self._post_json("/responses", payload, model, timeout=timeout)
        if isinstance(out, LLMResult):
            return out
        return classify_responses_api(out["status_code"], out["body"], model=model)

    def _chat_messages(
        self,
        model: str,
        messages: list[dict],
        tools: Optional[list[dict]],
        temperature: float,
        max_tokens: int,
        *,
        timeout: Optional[float] = None,
    ) -> LLMResult:
        system, anth_messages = chat_messages_to_anthropic(messages)
        payload: dict[str, Any] = {
            "model": model,
            "messages": anth_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = openai_tools_to_anthropic(tools)
        out = self._post_json("/messages", payload, model, timeout=timeout)
        if isinstance(out, LLMResult):
            return out
        return classify_messages_api(out["status_code"], out["body"], model=model)

    def run_tool_loop(
        self,
        packet: Any,
        tool_handler: Callable[[str, dict], dict],
        max_rounds: int,
        temperature: float,
    ) -> LLMResult:
        messages = messages_from_packet(packet)
        tools = getattr(packet, "tools_schema", None) or []
        last: Optional[LLMResult] = None
        submit_seen = False  # Track if any submit_* was attempted
        usage_acc = TokenUsage(source="none", llm_calls=0)

        def _accumulate(res: LLMResult) -> None:
            nonlocal usage_acc
            u = res.usage
            if u is None or u.source == "none":
                u = estimate_usage_from_messages(
                    messages, res.content, res.tool_calls
                )
                res.usage = u
            usage_acc = usage_acc.add(u) if usage_acc.llm_calls else u

        def _with_acc(res: LLMResult) -> LLMResult:
            res.usage = usage_acc if usage_acc.llm_calls else res.usage
            return res

        for _ in range(max_rounds):
            last = self.chat(messages, tools=tools or None, temperature=temperature)
            _accumulate(last)
            if not last.ok:
                last.transcript = list(messages)
                return _with_acc(last)

            # Warn only for tool names not present in this stage's schema
            # (or terminal submit_* tools). Recon tools like read_file/grep are
            # legitimate when offered — do not treat them as non-compliance.
            if last.tool_calls:
                schema_names: set[str] = {
                    "submit_candidate",
                    "submit_none",
                    "submit_architecture",
                }
                for t in tools or []:
                    if not isinstance(t, dict):
                        continue
                    fn = t.get("function") if isinstance(t.get("function"), dict) else t
                    if isinstance(fn, dict) and fn.get("name"):
                        schema_names.add(str(fn["name"]))
                invalid_calls = [
                    tc["name"]
                    for tc in last.tool_calls
                    if tc.get("name") and str(tc["name"]) not in schema_names
                ]
                if invalid_calls:
                    import logging

                    logger = logging.getLogger(__name__)
                    logger.warning(
                        "LLM called unknown tools: %s. "
                        "This may indicate non-compliance with expected tool schema.",
                        invalid_calls,
                    )

                asst: dict[str, Any] = {
                    "role": "assistant",
                    "content": last.content or "",
                    "tool_calls": [
                        {
                            "id": tc.get("id") or f"call_{i}",
                            "type": "function",
                            "function": {
                                "name": tc["name"],
                                "arguments": json.dumps(tc.get("arguments") or {}),
                            },
                        }
                        for i, tc in enumerate(last.tool_calls)
                    ],
                }
                if last.reasoning_content:
                    asst["reasoning_content"] = last.reasoning_content
                messages.append(asst)

                # Track if any submit_* call was made
                has_submit = False
                stop = False

                for tc in last.tool_calls:
                    name = tc["name"]
                    args = tc.get("arguments") or {}
                    if not isinstance(args, dict):
                        try:
                            args = json.loads(args)
                        except Exception:
                            args = {}

                    out = tool_handler(name, args)
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.get("id") or "call",
                            "name": name,
                            "content": json.dumps(out),
                        }
                    )

                    # Track submit_* calls for compliance checking
                    if name in ("submit_candidate", "submit_none", "submit_architecture"):
                        submit_seen = True
                        has_submit = True
                        if isinstance(out, dict) and out.get("ok") is True:
                            stop = True

                if stop:
                    last.transcript = list(messages)
                    return _with_acc(last)

                # If no submit_* was called in this round, continue to next round
                if not has_submit:
                    continue

            # Free text exit (no tool_calls) — silent failure path
            messages.append(
                {
                    "role": "assistant",
                    "content": last.content or "",
                    **(
                        {"reasoning_content": last.reasoning_content}
                        if last.reasoning_content
                        else {}
                    ),
                }
            )
            last.transcript = list(messages)

            # If we've exhausted rounds without any submit, mark as no_submit
            if not submit_seen and _ >= max_rounds - 1:
                return _with_acc(
                    LLMResult(
                        ok=False,
                        classification=ResponseClass.TRUNCATED,
                        content=last.content if last else None,
                        tool_calls=last.tool_calls if last else [],
                        raw=None,
                        model_id=self._resolved_model or self.model,
                        error="no_submit",  # Explicit no_submit error
                        transcript=list(messages),
                    )
                )

            return _with_acc(last)

        # Exhausted all rounds without successful submit
        if not submit_seen:
            return _with_acc(
                LLMResult(
                    ok=False,
                    classification=ResponseClass.TRUNCATED,
                    content=last.content if last else None,
                    tool_calls=last.tool_calls if last else [],
                    raw=None,
                    model_id=self._resolved_model or self.model,
                    error="no_submit",  # Explicit no_submit error when rounds exhausted
                    transcript=list(messages),
                )
            )

        return _with_acc(
            LLMResult(
                ok=False,
                classification=ResponseClass.TRUNCATED,
                content=last.content if last else None,
                tool_calls=last.tool_calls if last else [],
                raw=None,
                model_id=self._resolved_model or self.model,
                error="max_tool_rounds",
                transcript=list(messages),
            )
        )


@dataclass
class FakeLLMClient:
    """Scripted LLM for tests — no network."""

    responses: list[LLMResult] = field(default_factory=list)
    model_id: str = "fake-model"
    _i: int = 0

    def fingerprint_model(self) -> str:
        return self.model_id

    def close(self) -> None:
        pass

    def chat(
        self,
        messages,
        tools=None,
        temperature=0.3,
        max_tokens=None,
        timeout=None,
    ) -> LLMResult:
        if self._i >= len(self.responses):
            return LLMResult(
                ok=False,
                classification=ResponseClass.EMPTY,
                content=None,
                tool_calls=[],
                raw=None,
                model_id=self.model_id,
                error="fake exhausted",
            )
        r = self.responses[self._i]
        self._i += 1
        return r

    def run_tool_loop(self, packet, tool_handler, max_rounds, temperature) -> LLMResult:
        messages = messages_from_packet(packet)
        last: Optional[LLMResult] = None
        usage_acc = TokenUsage(source="none", llm_calls=0)

        def _accumulate(res: LLMResult) -> None:
            nonlocal usage_acc
            u = res.usage
            if u is None or u.source == "none":
                u = TokenUsage(
                    prompt_tokens=10,
                    completion_tokens=5,
                    total_tokens=15,
                    source="estimate",
                    llm_calls=1,
                )
                res.usage = u
            usage_acc = usage_acc.add(u) if usage_acc.llm_calls else u

        def _with_acc(res: LLMResult) -> LLMResult:
            res.usage = usage_acc if usage_acc.llm_calls else res.usage
            return res

        for _ in range(max_rounds):
            last = self.chat(messages, tools=packet.tools_schema, temperature=temperature)
            _accumulate(last)
            if not last.ok:
                last.transcript = list(messages)
                return _with_acc(last)
            if last.tool_calls:
                messages.append(
                    {
                        "role": "assistant",
                        "content": last.content or "",
                        "tool_calls": last.tool_calls,
                    }
                )
                for tc in last.tool_calls:
                    name = tc["name"]
                    args = tc.get("arguments") or {}
                    out = tool_handler(name, args)
                    messages.append(
                        {
                            "role": "tool",
                            "name": name,
                            "content": json.dumps(out),
                        }
                    )
                    if name in ("submit_candidate", "submit_none", "submit_architecture"):
                        if isinstance(out, dict) and out.get("ok") is True:
                            last.transcript = list(messages)
                            return _with_acc(last)
                continue
            messages.append({"role": "assistant", "content": last.content or ""})
            last.transcript = list(messages)
            return _with_acc(last)
        return _with_acc(
            LLMResult(
                ok=False,
                classification=ResponseClass.TRUNCATED,
                content=None,
                tool_calls=[],
                raw=None,
                model_id=self.model_id,
                error="max_tool_rounds",
                transcript=list(messages),
            )
        )


def looks_like_error(content: Optional[str]) -> bool:
    if not content:
        return False
    return bool(_ERROR_PATTERNS.search(content))


# Platform / transport signals that warrant retry as failed_infra.
_INFRA_ERROR_MARKERS = (
    "connection",
    "timeout",
    "timed out",
    "econnreset",
    "refused",
    "http 5",
    "http 429",
    "rate limit",
    "overloaded",
    "model unloaded",
    "model not found",
    "out of memory",
    "failed to load",
    "error loading",
    "models list failed",
    "no models available",
    "non-json",
)


def classify_llm_failure(result: LLMResult) -> str:
    """
    Map an unsuccessful LLMResult to stage status for the control plane.

    Returns:
      ``"failed_infra"`` — retryable transport/platform (Ralph EXIT_INFRA).
      ``"failed_task"`` — model thrash / empty / length / max_tool_rounds
      (terminal progress; do not poison the campaign with EXIT 20 loops).
    """
    err = (result.error or "").lower()
    content = (result.content or "").lower() if result.content else ""
    blob = f"{err} {content}"

    # Explicit tool-loop thrash is always terminal for this lease.
    if "max_tool_rounds" in err:
        return "failed_task"

    cls = result.classification
    if cls == ResponseClass.TRANSPORT:
        return "failed_infra"

    # Empty / truncated / context-length / unknown → task (stop EXIT 20 thrash).
    if cls in (
        ResponseClass.EMPTY,
        ResponseClass.TRUNCATED,
        ResponseClass.CONTEXT_LENGTH,
        ResponseClass.UNKNOWN,
    ):
        return "failed_task"

    # ERROR_TEXT: platform signals → infra; otherwise model/content → task.
    if cls == ResponseClass.ERROR_TEXT:
        if any(m in blob for m in _INFRA_ERROR_MARKERS):
            return "failed_infra"
        return "failed_task"

    # Fallback: error string markers.
    if any(m in err for m in _INFRA_ERROR_MARKERS):
        return "failed_infra"
    return "failed_task"


def normalize_tool_calls(raw: Any) -> list[dict]:
    if not raw:
        return []
    out: list[dict] = []
    for i, tc in enumerate(raw):
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function") or {}
        name = fn.get("name") or tc.get("name")
        args = fn.get("arguments", tc.get("arguments", {}))
        if isinstance(args, str):
            try:
                args = json.loads(args) if args else {}
            except json.JSONDecodeError:
                args = {"_raw": args}
        if not isinstance(args, dict):
            args = {}
        if not name:
            continue
        out.append(
            {
                "id": tc.get("id") or tc.get("call_id") or f"call_{i}",
                "name": name,
                "arguments": args,
            }
        )
    return out


def _openai_tool_fn(tool: dict) -> dict:
    """Extract {name, description, parameters} from OpenAI tools[] entry."""
    if not isinstance(tool, dict):
        return {}
    if tool.get("type") == "function" and isinstance(tool.get("function"), dict):
        fn = tool["function"]
        return {
            "name": fn.get("name") or "",
            "description": fn.get("description") or "",
            "parameters": fn.get("parameters") or {"type": "object", "properties": {}},
        }
    if tool.get("name"):
        return {
            "name": tool.get("name") or "",
            "description": tool.get("description") or "",
            "parameters": tool.get("parameters")
            or tool.get("input_schema")
            or {"type": "object", "properties": {}},
        }
    return {}


def openai_tools_to_responses(tools: list[dict]) -> list[dict]:
    """Chat Completions tools[] → Responses flat function tools."""
    out: list[dict] = []
    for t in tools or []:
        fn = _openai_tool_fn(t)
        if not fn.get("name"):
            continue
        out.append(
            {
                "type": "function",
                "name": fn["name"],
                "description": fn.get("description") or "",
                "parameters": fn.get("parameters") or {"type": "object", "properties": {}},
            }
        )
    return out


def openai_tools_to_anthropic(tools: list[dict]) -> list[dict]:
    """Chat Completions tools[] → Anthropic Messages tools."""
    out: list[dict] = []
    for t in tools or []:
        fn = _openai_tool_fn(t)
        if not fn.get("name"):
            continue
        out.append(
            {
                "name": fn["name"],
                "description": fn.get("description") or "",
                "input_schema": fn.get("parameters")
                or {"type": "object", "properties": {}},
            }
        )
    return out


def chat_messages_to_responses_input(messages: list[dict]) -> list[dict]:
    """
    Convert canonical OpenAI chat messages (tool loop state) to Responses API input items.
    """
    items: list[dict] = []
    for m in messages or []:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        if role in ("system", "user", "developer"):
            content = m.get("content")
            if content is None:
                content = ""
            items.append({"role": role, "content": content})
            continue
        if role == "assistant":
            tcs = m.get("tool_calls") or []
            if tcs:
                for tc in tcs:
                    if not isinstance(tc, dict):
                        continue
                    fn = tc.get("function") or {}
                    name = fn.get("name") or tc.get("name")
                    args = fn.get("arguments", tc.get("arguments", {}))
                    if isinstance(args, dict):
                        args = json.dumps(args)
                    elif args is None:
                        args = "{}"
                    else:
                        args = str(args)
                    call_id = tc.get("id") or tc.get("call_id") or "call"
                    if name:
                        items.append(
                            {
                                "type": "function_call",
                                "call_id": call_id,
                                "name": name,
                                "arguments": args,
                            }
                        )
                text = m.get("content")
                if text:
                    items.append(
                        {
                            "type": "message",
                            "role": "assistant",
                            "content": [{"type": "output_text", "text": str(text)}],
                        }
                    )
            else:
                content = m.get("content")
                if content is None:
                    content = ""
                items.append({"role": "assistant", "content": content})
            continue
        if role == "tool":
            call_id = m.get("tool_call_id") or m.get("id") or "call"
            out = m.get("content")
            if out is None:
                out = ""
            elif not isinstance(out, str):
                out = json.dumps(out)
            items.append(
                {
                    "type": "function_call_output",
                    "call_id": call_id,
                    "output": out,
                }
            )
    return items


def chat_messages_to_anthropic(messages: list[dict]) -> tuple[str, list[dict]]:
    """
    Convert canonical chat messages to Anthropic (system, messages[]).

    Tool results become user messages with tool_result content blocks.
    """
    system_parts: list[str] = []
    out: list[dict] = []
    pending_tool_results: list[dict] = []

    def flush_tools() -> None:
        nonlocal pending_tool_results
        if pending_tool_results:
            out.append({"role": "user", "content": pending_tool_results})
            pending_tool_results = []

    for m in messages or []:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        if role == "system":
            flush_tools()
            c = m.get("content")
            if c:
                system_parts.append(str(c))
            continue
        if role == "user":
            flush_tools()
            out.append({"role": "user", "content": m.get("content") or ""})
            continue
        if role == "assistant":
            flush_tools()
            tcs = m.get("tool_calls") or []
            if tcs:
                blocks: list[dict] = []
                text = m.get("content")
                if text:
                    blocks.append({"type": "text", "text": str(text)})
                for tc in tcs:
                    if not isinstance(tc, dict):
                        continue
                    fn = tc.get("function") or {}
                    name = fn.get("name") or tc.get("name")
                    args = fn.get("arguments", tc.get("arguments", {}))
                    if isinstance(args, str):
                        try:
                            args = json.loads(args) if args else {}
                        except json.JSONDecodeError:
                            args = {"_raw": args}
                    if not isinstance(args, dict):
                        args = {}
                    if not name:
                        continue
                    blocks.append(
                        {
                            "type": "tool_use",
                            "id": tc.get("id") or "call",
                            "name": name,
                            "input": args,
                        }
                    )
                out.append({"role": "assistant", "content": blocks or ""})
            else:
                out.append({"role": "assistant", "content": m.get("content") or ""})
            continue
        if role == "tool":
            content = m.get("content")
            if content is None:
                content = ""
            elif not isinstance(content, str):
                content = json.dumps(content)
            pending_tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": m.get("tool_call_id") or m.get("id") or "call",
                    "content": content,
                }
            )
    flush_tools()
    return "\n\n".join(system_parts).strip(), out


def _finalize_llm_result(
    *,
    content: Optional[str],
    tool_calls: list[dict],
    raw: Any,
    model: str,
    reasoning: Optional[str] = None,
    finish: str = "",
) -> LLMResult:
    """Shared empty / error-text / OK path after mode-specific parse."""
    usage = parse_usage_from_body(raw)
    if finish in ("length", "max_tokens") and not content and not tool_calls:
        return LLMResult(
            ok=False,
            classification=ResponseClass.CONTEXT_LENGTH,
            content=content,
            tool_calls=tool_calls,
            raw=raw,
            model_id=model,
            error="finish_reason=length (empty content; raise llm.max_tokens for reasoning models)",
            usage=usage,
        )
    if not content and not tool_calls:
        return LLMResult(
            ok=False,
            classification=ResponseClass.EMPTY,
            content=None,
            tool_calls=[],
            raw=raw,
            model_id=model,
            error="empty message",
            usage=usage,
        )
    if content and looks_like_error(content) and not tool_calls:
        return LLMResult(
            ok=False,
            classification=ResponseClass.ERROR_TEXT,
            content=content,
            tool_calls=[],
            raw=raw,
            model_id=model,
            error="error-like content",
            usage=usage,
        )
    return LLMResult(
        ok=True,
        classification=ResponseClass.OK,
        content=content,
        tool_calls=tool_calls,
        reasoning_content=reasoning if isinstance(reasoning, str) else None,
        raw=raw,
        model_id=model,
        usage=usage,
    )


def classify_responses_api(status_code: int, body: Any, model: str) -> LLMResult:
    """Parse OpenAI Responses API body into LLMResult."""
    if status_code != 200:
        err = None
        if isinstance(body, dict):
            e = body.get("error")
            if isinstance(e, dict):
                err = e.get("message") or str(e)
            elif e:
                err = str(e)
        return LLMResult(
            ok=False,
            classification=ResponseClass.TRANSPORT,
            content=None,
            tool_calls=[],
            raw=body,
            model_id=model,
            error=err or f"http {status_code}",
        )
    if not isinstance(body, dict):
        return LLMResult(
            ok=False,
            classification=ResponseClass.EMPTY,
            content=None,
            tool_calls=[],
            raw=body,
            model_id=model,
            error="body not object",
        )
    # Prefer SDK-style helper if present (some proxies add it)
    content: Optional[str] = None
    if isinstance(body.get("output_text"), str) and body.get("output_text"):
        content = body["output_text"]
    tool_calls: list[dict] = []
    reasoning_parts: list[str] = []
    for i, item in enumerate(body.get("output") or []):
        if not isinstance(item, dict):
            continue
        itype = item.get("type")
        if itype == "message":
            parts = item.get("content") or []
            texts: list[str] = []
            if isinstance(parts, str):
                texts.append(parts)
            elif isinstance(parts, list):
                for p in parts:
                    if isinstance(p, dict):
                        t = p.get("text") or p.get("output_text")
                        if t:
                            texts.append(str(t))
                        elif p.get("type") in ("output_text", "text") and p.get("text"):
                            texts.append(str(p["text"]))
                    elif isinstance(p, str):
                        texts.append(p)
            if texts:
                chunk = "\n".join(texts)
                content = f"{content}\n{chunk}" if content else chunk
        elif itype in ("function_call", "custom_tool_call"):
            name = item.get("name")
            args = item.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args) if args else {}
                except json.JSONDecodeError:
                    args = {"_raw": args}
            if not isinstance(args, dict):
                args = {}
            if name:
                tool_calls.append(
                    {
                        "id": item.get("call_id") or item.get("id") or f"call_{i}",
                        "name": name,
                        "arguments": args,
                    }
                )
        elif itype == "reasoning":
            summary = item.get("summary") or item.get("content") or []
            if isinstance(summary, list):
                for s in summary:
                    if isinstance(s, dict) and s.get("text"):
                        reasoning_parts.append(str(s["text"]))
                    elif isinstance(s, str):
                        reasoning_parts.append(s)
            elif isinstance(summary, str) and summary:
                reasoning_parts.append(summary)
    status = str(body.get("status") or "")
    finish = "length" if status in ("incomplete", "failed") else status
    incomplete = body.get("incomplete_details") or {}
    if isinstance(incomplete, dict) and incomplete.get("reason") in (
        "max_output_tokens",
        "max_tokens",
    ):
        finish = "length"
    reasoning = "\n".join(reasoning_parts) if reasoning_parts else None
    return _finalize_llm_result(
        content=content,
        tool_calls=tool_calls,
        raw=body,
        model=model,
        reasoning=reasoning,
        finish=finish,
    )


def classify_messages_api(status_code: int, body: Any, model: str) -> LLMResult:
    """Parse Anthropic-style Messages API body into LLMResult."""
    if status_code != 200:
        err = None
        if isinstance(body, dict):
            e = body.get("error")
            if isinstance(e, dict):
                err = e.get("message") or str(e)
            elif e:
                err = str(e)
        return LLMResult(
            ok=False,
            classification=ResponseClass.TRANSPORT,
            content=None,
            tool_calls=[],
            raw=body,
            model_id=model,
            error=err or f"http {status_code}",
        )
    if not isinstance(body, dict):
        return LLMResult(
            ok=False,
            classification=ResponseClass.EMPTY,
            content=None,
            tool_calls=[],
            raw=body,
            model_id=model,
            error="body not object",
        )
    content_parts: list[str] = []
    tool_calls: list[dict] = []
    blocks = body.get("content") or []
    if isinstance(blocks, str):
        content_parts.append(blocks)
    elif isinstance(blocks, list):
        for i, block in enumerate(blocks):
            if not isinstance(block, dict):
                if isinstance(block, str):
                    content_parts.append(block)
                continue
            btype = block.get("type")
            if btype in ("text", "output_text"):
                t = block.get("text")
                if t:
                    content_parts.append(str(t))
            elif btype in ("tool_use", "tool_call", "function"):
                name = block.get("name")
                args = block.get("input") or block.get("arguments") or {}
                if isinstance(args, str):
                    try:
                        args = json.loads(args) if args else {}
                    except json.JSONDecodeError:
                        args = {"_raw": args}
                if not isinstance(args, dict):
                    args = {}
                if name:
                    tool_calls.append(
                        {
                            "id": block.get("id") or f"call_{i}",
                            "name": name,
                            "arguments": args,
                        }
                    )
    content = "\n".join(content_parts) if content_parts else None
    stop = str(body.get("stop_reason") or body.get("stop_sequence") or "")
    finish = "length" if stop in ("max_tokens", "length") else stop
    return _finalize_llm_result(
        content=content,
        tool_calls=tool_calls,
        raw=body,
        model=model,
        finish=finish,
    )


def classify_response(status_code: int, body: Any, model: str) -> LLMResult:
    usage = parse_usage_from_body(body)
    if status_code != 200:
        return LLMResult(
            ok=False,
            classification=ResponseClass.TRANSPORT,
            content=None,
            tool_calls=[],
            raw=body,
            model_id=model,
            error=f"http {status_code}",
            usage=usage,
        )
    if not isinstance(body, dict):
        return LLMResult(
            ok=False,
            classification=ResponseClass.EMPTY,
            content=None,
            tool_calls=[],
            raw=body,
            model_id=model,
            error="body not object",
            usage=usage,
        )
    choices = body.get("choices") or []
    if not choices:
        return LLMResult(
            ok=False,
            classification=ResponseClass.EMPTY,
            content=None,
            tool_calls=[],
            raw=body,
            model_id=model,
            error="empty choices",
            usage=usage,
        )
    choice0 = choices[0] or {}
    finish = str(choice0.get("finish_reason") or "")
    msg = choice0.get("message") or {}
    content = msg.get("content")
    if content is not None and not isinstance(content, str):
        content = str(content)
    # Some local reasoning models put chain-of-thought in reasoning_content
    reasoning = msg.get("reasoning_content")
    tool_calls = normalize_tool_calls(msg.get("tool_calls"))

    if finish in ("length", "max_tokens"):
        if not content and not tool_calls:
            # Common when max_tokens is too small for reasoning models
            return LLMResult(
                ok=False,
                classification=ResponseClass.CONTEXT_LENGTH,
                content=content,
                tool_calls=tool_calls,
                raw=body,
                model_id=model,
                error="finish_reason=length (empty content; raise llm.max_tokens for reasoning models)",
                usage=usage,
            )
        # partial ok if tools present; else truncated
        if not tool_calls and (not content or not str(content).strip()):
            return LLMResult(
                ok=False,
                classification=ResponseClass.TRUNCATED,
                content=content,
                tool_calls=[],
                raw=body,
                model_id=model,
                error="truncated",
                usage=usage,
            )
        if not tool_calls and content and finish in ("length", "max_tokens"):
            # Have partial content — still usable but mark truncated? Prefer OK if non-empty.
            pass

    if not content and not tool_calls:
        return LLMResult(
            ok=False,
            classification=ResponseClass.EMPTY,
            content=None,
            tool_calls=[],
            raw=body,
            model_id=model,
            error="empty message",
            usage=usage,
        )

    if content and looks_like_error(content) and not tool_calls:
        return LLMResult(
            ok=False,
            classification=ResponseClass.ERROR_TEXT,
            content=content,
            tool_calls=[],
            raw=body,
            model_id=model,
            error="error-like content",
            usage=usage,
        )

    return LLMResult(
        ok=True,
        classification=ResponseClass.OK,
        content=content,
        tool_calls=tool_calls,
        reasoning_content=reasoning if isinstance(reasoning, str) else None,
        raw=body,
        model_id=model,
        usage=usage,
    )


def messages_from_packet(packet: Any) -> list[dict]:
    return [
        {"role": "system", "content": packet.system},
        {"role": "user", "content": packet.user},
    ]


def make_client(cfg: dict) -> Any:
    """Factory: fake if cfg['llm']['fake'] else real."""
    llm = cfg.get("llm") or {}
    if llm.get("fake"):
        return FakeLLMClient(
            responses=llm.get("fake_responses") or [],
            model_id=llm.get("model") or "fake",
        )
    return LLMClient(cfg)
