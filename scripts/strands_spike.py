#!/usr/bin/env python3
"""
Phase 0 spike: Strands Agents as a possible inner-loop backend for VulnForge.

Isolated from the production path (does not change hunt/recon stages).
Proves or fails three checkpoints:

  1. submit_* stop  — cancel agent after successful submit_none
  2. transcript     — normalize Strands messages → OpenAI-ish shape (tool_gaps-ish)
  3. scripted model — FakeLLM-equivalent offline unit path

Usage (from repo root, venv active):

  python scripts/strands_spike.py
  python scripts/strands_spike.py --base-url http://192.168.32.10:1234/v1 --model ornith-1.0-35b
  python scripts/strands_spike.py --scripted-only
  python scripts/strands_spike.py --live-only

Writes:
  docs/plans/strands-phase0-spike-report.md  (unless --no-report)
  .pytest_tmp/strands_spike/                (target + evidence scratch)
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterable, Optional

# Repo root on path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_BASE_URL = "http://192.168.32.10:1234/v1"
DEFAULT_MODEL = "ornith-1.0-35b"
DEFAULT_API_KEY = "lm-studio"


# ---------------------------------------------------------------------------
# Checkpoint result
# ---------------------------------------------------------------------------


@dataclass
class Check:
    id: str
    title: str
    ok: bool
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class SpikeReport:
    checks: list[Check] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def add(self, c: Check) -> None:
        self.checks.append(c)
        status = "PASS" if c.ok else "FAIL"
        print(f"  [{status}] {c.id}: {c.title}")
        if c.detail:
            for line in c.detail.strip().splitlines():
                print(f"         {line}")

    @property
    def all_ok(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)


# ---------------------------------------------------------------------------
# Transcript normalizer (Strands content-blocks → OpenAI-ish messages)
# ---------------------------------------------------------------------------


def strands_messages_to_openaiish(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map Strands agent.messages into a shape close to VulnForge transcripts.

    VulnForge tool_gaps / step_io expect roles user|assistant|tool and
    assistant.tool_calls with function.name / function.arguments.
    """
    out: list[dict[str, Any]] = []
    for m in messages:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        content = m.get("content")
        if role == "user" and isinstance(content, list):
            # tool results arrive as user messages with toolResult blocks
            tool_results = [
                b.get("toolResult")
                for b in content
                if isinstance(b, dict) and "toolResult" in b
            ]
            texts = [
                b.get("text", "")
                for b in content
                if isinstance(b, dict) and "text" in b
            ]
            if tool_results:
                for tr in tool_results:
                    if not isinstance(tr, dict):
                        continue
                    body = tr.get("content") or []
                    text_parts = []
                    for part in body:
                        if isinstance(part, dict) and "text" in part:
                            text_parts.append(str(part["text"]))
                    out.append(
                        {
                            "role": "tool",
                            "tool_call_id": tr.get("toolUseId") or "call",
                            "name": None,  # filled if we can infer later
                            "content": "\n".join(text_parts) if text_parts else json.dumps(tr),
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
                if "text" in b:
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
                    "content": content if isinstance(content, str) else json.dumps(content),
                }
            )
    # Best-effort: attach tool names from preceding assistant tool_calls
    pending: dict[str, str] = {}
    for msg in out:
        if msg.get("role") == "assistant":
            for tc in msg.get("tool_calls") or []:
                fn = (tc.get("function") or {})
                tid = tc.get("id")
                name = fn.get("name")
                if tid and name:
                    pending[str(tid)] = str(name)
        if msg.get("role") == "tool" and not msg.get("name"):
            tid = str(msg.get("tool_call_id") or "")
            if tid in pending:
                msg["name"] = pending[tid]
    return out


def count_tool_calls(openaiish: list[dict[str, Any]]) -> int:
    n = 0
    for m in openaiish:
        if m.get("role") == "assistant":
            n += len(m.get("tool_calls") or [])
    return n


# ---------------------------------------------------------------------------
# Scripted Model (FakeLLM equivalent)
# ---------------------------------------------------------------------------


class ScriptedModel:
    """Minimal Strands Model that replays scripted turns (no network)."""

    def __init__(self, scripts: list[dict[str, Any]], model_id: str = "scripted-fake"):
        # Lazy: only import types when used under strands
        self._scripts = list(scripts)
        self._i = 0
        self._config = {"model_id": model_id}

    def update_config(self, **kwargs: Any) -> None:
        self._config.update(kwargs)

    def get_config(self) -> dict[str, Any]:
        return self._config

    async def structured_output(self, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
        raise NotImplementedError("structured_output not used in spike")

    async def stream(  # type: ignore[no-untyped-def]
        self,
        messages,
        tool_specs=None,
        system_prompt=None,
        **kwargs: Any,
    ) -> AsyncIterable[dict[str, Any]]:
        if self._i >= len(self._scripts):
            script: dict[str, Any] = {"text": "(script exhausted)"}
        else:
            script = self._scripts[self._i]
            self._i += 1

        yield {"messageStart": {"role": "assistant"}}
        if script.get("text"):
            yield {"contentBlockStart": {"start": {}}}
            yield {"contentBlockDelta": {"delta": {"text": str(script["text"])}}}
            yield {"contentBlockStop": {}}
        for tc in script.get("tool_calls") or []:
            yield {
                "contentBlockStart": {
                    "start": {
                        "toolUse": {
                            "name": tc["name"],
                            "toolUseId": tc.get("id") or f"call_{self._i}",
                        }
                    }
                }
            }
            args = tc.get("arguments") or {}
            yield {
                "contentBlockDelta": {
                    "delta": {
                        "toolUse": {
                            "input": json.dumps(args)
                            if not isinstance(args, str)
                            else args
                        }
                    }
                }
            }
            yield {"contentBlockStop": {}}
        stop = "tool_use" if script.get("tool_calls") else "end_turn"
        yield {"messageStop": {"stopReason": stop}}
        yield {
            "metadata": {
                "usage": {
                    "inputTokens": 10,
                    "outputTokens": 5,
                    "totalTokens": 15,
                },
                "metrics": {"latencyMs": 1},
            }
        }


def _install_scripted_as_model() -> type:
    """Subclass strands.models.model.Model so Agent accepts ScriptedModel."""
    from strands.models.model import Model

    class _Scripted(ScriptedModel, Model):  # type: ignore[misc]
        pass

    return _Scripted


# ---------------------------------------------------------------------------
# VulnForge tool wrappers as Strands @tool
# ---------------------------------------------------------------------------


def build_ctx(target_root: Path, evidence_root: Path) -> dict[str, Any]:
    """Minimal tool context for read_file / grep / submit_none."""
    session: dict[str, Any] = {
        "evidence_ids_written": [],
        "submitted": None,
    }

    def _submit_none(args: dict[str, Any]) -> dict[str, Any]:
        reason = str((args or {}).get("reason") or "").strip()
        if not reason:
            return {"ok": False, "error": "reason required"}
        session["submitted"] = {"kind": "none", "reason": reason}
        return {"ok": True, "status": "none", "reason": reason}

    return {
        "target_root": str(target_root),
        "evidence_root": str(evidence_root),
        "run_dir": str(evidence_root.parent),
        "task_id": "strands-spike",
        "task_payload": {"class": "wildcard", "area": "spike"},
        "db": None,
        "cfg": {"run": {"profile": "code_static"}},
        "session": session,
        "submit_none": _submit_none,
        "scope": {"enabled": False, "widened": True},
    }


def make_strands_tools(ctx: dict[str, Any]):
    from strands import tool
    from vulnforge.tools import run_tool

    @tool(name="read_file", description=(
        "Read a text file (or line range) from the audit target (read-only). "
        "path is relative to the target root."
    ))
    def read_file(
        path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> dict[str, Any]:
        args: dict[str, Any] = {"path": path}
        if start_line is not None:
            args["start_line"] = start_line
        if end_line is not None:
            args["end_line"] = end_line
        return run_tool("read_file", ctx, args)

    @tool(name="grep", description=(
        "Search target files with a regex (read-only). "
        "pattern is a Python-style regex over file lines."
    ))
    def grep(
        pattern: str,
        glob: Optional[str] = None,
        extension: Optional[str] = None,
        max_matches: int = 30,
    ) -> dict[str, Any]:
        args: dict[str, Any] = {
            "pattern": pattern,
            "max_matches": max_matches,
        }
        if glob:
            args["glob"] = glob
        if extension:
            args["extension"] = extension
        return run_tool("grep", ctx, args)

    @tool(name="submit_none", description=(
        "Finish hunt with no solid finding after a real search. "
        "reason must say what you checked. Call this to end the task."
    ))
    def submit_none(reason: str) -> dict[str, Any]:
        return run_tool("submit_none", ctx, {"reason": reason})

    return [read_file, grep, submit_none], ctx["session"]


def make_submit_stop_hook(agent_ref: dict[str, Any], session: dict[str, Any]):
    """After successful submit_none, cancel the agent (domain terminal tool).

    Returns (event_type, callback) so registration does not rely on runtime
    type-hint inference (which fails when AfterToolCallEvent is only imported
    inside a nested function).
    """
    from strands.hooks import AfterToolCallEvent

    def after_tool(event: Any) -> None:
        tu = event.tool_use
        name = tu.get("name") if isinstance(tu, dict) else getattr(tu, "name", None)
        if name not in ("submit_none", "submit_candidate", "submit_architecture"):
            return
        # Prefer session flag set by our submit_none wrapper
        submitted = session.get("submitted")
        # Also parse tool result text for ok:true
        result = event.result
        ok = bool(submitted)
        if not ok and isinstance(result, dict):
            # Strands wraps return as content text
            content = result.get("content") or []
            for part in content:
                if isinstance(part, dict) and "text" in part:
                    try:
                        body = json.loads(part["text"])
                        if isinstance(body, dict) and body.get("ok") is True:
                            ok = True
                    except (json.JSONDecodeError, TypeError):
                        compact = str(part["text"]).replace(" ", "").lower()
                        if '"ok":true' in compact:
                            ok = True
        if ok:
            ag = agent_ref.get("agent")
            if ag is not None:
                ag.cancel()

    return AfterToolCallEvent, after_tool


def attach_submit_stop_hook(agent: Any, agent_ref: dict[str, Any], session: dict[str, Any]) -> None:
    event_type, callback = make_submit_stop_hook(agent_ref, session)
    agent.hooks.add_callback(event_type, callback)
    agent_ref["agent"] = agent


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def check_import(report: SpikeReport) -> None:
    try:
        import strands
        from strands import Agent, tool  # noqa: F401
        from strands.models.openai import OpenAIModel  # noqa: F401

        ver = getattr(strands, "__version__", None)
        report.add(
            Check(
                "import",
                "strands-agents importable",
                True,
                f"strands loaded from {strands.__file__}"
                + (f" version={ver}" if ver else ""),
                {"file": str(strands.__file__), "version": ver},
            )
        )
    except Exception as e:
        report.add(
            Check(
                "import",
                "strands-agents importable",
                False,
                f"{type(e).__name__}: {e}",
            )
        )


def check_scripted_submit_stop(
    report: SpikeReport, target: Path, evidence: Path
) -> Optional[Any]:
    try:
        from strands import Agent

        Scripted = _install_scripted_as_model()
        ctx = build_ctx(target, evidence)
        tools, session = make_strands_tools(ctx)
        model = Scripted(
            [
                {
                    "tool_calls": [
                        {
                            "id": "c1",
                            "name": "read_file",
                            "arguments": {"path": "app.py"},
                        }
                    ]
                },
                {
                    "tool_calls": [
                        {
                            "id": "c2",
                            "name": "submit_none",
                            "arguments": {
                                "reason": "Read app.py; toy fixture only, no solid vuln bar met for spike."
                            },
                        }
                    ]
                },
                {"text": "SHOULD_NOT_REACH"},
            ]
        )
        agent_ref: dict[str, Any] = {}
        agent = Agent(
            model=model,
            tools=tools,
            system_prompt=(
                "You are a hunt agent. Use read_file/grep then finish with submit_none."
            ),
            callback_handler=None,
        )
        attach_submit_stop_hook(agent, agent_ref, session)
        result = agent(
            "Audit the target. Read app.py then call submit_none with a concrete reason.",
            limits={"turns": 8},
        )
        stop = getattr(result, "stop_reason", None)
        scripts_used = model._i
        submitted = session.get("submitted")
        # Third script must not run if cancel worked (scripts_used stays 2)
        stopped_early = scripts_used == 2 and stop == "cancelled"
        ok = bool(submitted) and stopped_early
        detail = (
            f"stop_reason={stop!r} scripts_used={scripts_used}/3 "
            f"submitted={submitted!r}"
        )
        if not ok:
            detail += " (expected stop_reason='cancelled', scripts_used=2, submit session set)"
        report.add(
            Check(
                "submit_stop_scripted",
                "Domain terminal tool stops loop (scripted)",
                ok,
                detail,
                {
                    "stop_reason": stop,
                    "scripts_used": scripts_used,
                    "submitted": submitted,
                    "messages": len(agent.messages),
                },
            )
        )
        return agent
    except Exception as e:
        report.add(
            Check(
                "submit_stop_scripted",
                "Domain terminal tool stops loop (scripted)",
                False,
                f"{type(e).__name__}: {e}\n{traceback.format_exc()}",
            )
        )
        return None


def check_transcript(report: SpikeReport, agent: Any) -> list[dict[str, Any]]:
    if agent is None:
        report.add(
            Check(
                "transcript",
                "Normalize Strands messages → OpenAI-ish transcript",
                False,
                "no agent (scripted path failed)",
            )
        )
        return []
    try:
        raw = list(agent.messages)
        openaiish = strands_messages_to_openaiish(raw)
        n_tc = count_tool_calls(openaiish)
        roles = [m.get("role") for m in openaiish]
        has_tool_role = "tool" in roles
        has_asst_tc = n_tc >= 1
        # tool_gaps-like: walk assistant tool_calls + tool messages
        names: list[str] = []
        for m in openaiish:
            if m.get("role") == "assistant":
                for tc in m.get("tool_calls") or []:
                    names.append((tc.get("function") or {}).get("name") or "?")
            if m.get("role") == "tool" and m.get("name"):
                names.append(f"result:{m['name']}")
        ok = has_asst_tc and has_tool_role and "read_file" in names and "submit_none" in names
        report.add(
            Check(
                "transcript",
                "Normalize Strands messages → OpenAI-ish transcript",
                ok,
                f"openaiish_msgs={len(openaiish)} tool_calls={n_tc} names={names} roles={roles}",
                {"openaiish": openaiish, "raw_roles": [m.get("role") for m in raw]},
            )
        )
        return openaiish
    except Exception as e:
        report.add(
            Check(
                "transcript",
                "Normalize Strands messages → OpenAI-ish transcript",
                False,
                f"{type(e).__name__}: {e}\n{traceback.format_exc()}",
            )
        )
        return []


def check_tool_bodies(report: SpikeReport, target: Path, evidence: Path) -> None:
    """Direct call of wrapped VulnForge tools without LLM."""
    try:
        ctx = build_ctx(target, evidence)
        tools, session = make_strands_tools(ctx)
        by_name = {t.tool_name: t for t in tools}
        # Decorated tools expose .tool_name and can be called as functions
        rf = by_name["read_file"]
        # Call as normal Python (decorator preserves function)
        out = rf(path="app.py")  # type: ignore[operator]
        # When called directly, may return dict; when as tool, ToolResult
        if isinstance(out, dict):
            body = out
        else:
            body = out
        # Also via run_tool path
        from vulnforge.tools import run_tool

        direct = run_tool("read_file", ctx, {"path": "app.py"})
        ok = isinstance(direct, dict) and (
            direct.get("ok") is True or "content" in direct or "text" in direct or not direct.get("error")
        )
        # read_file returns content key on success typically
        if isinstance(direct, dict) and direct.get("error"):
            ok = False
        sn = run_tool(
            "submit_none",
            ctx,
            {"reason": "direct path check for spike"},
        )
        ok = ok and isinstance(sn, dict) and sn.get("ok") is True
        report.add(
            Check(
                "tool_wrap",
                "Existing VulnForge tools run via thin wrappers",
                ok,
                f"read_file keys={list(direct.keys()) if isinstance(direct, dict) else type(direct)}; "
                f"submit_none={sn}; direct_fn_type={type(out).__name__}",
                {"read_file": direct, "submit_none": sn},
            )
        )
    except Exception as e:
        report.add(
            Check(
                "tool_wrap",
                "Existing VulnForge tools run via thin wrappers",
                False,
                f"{type(e).__name__}: {e}\n{traceback.format_exc()}",
            )
        )


def check_live(
    report: SpikeReport,
    target: Path,
    evidence: Path,
    *,
    base_url: str,
    model_id: str,
    api_key: str,
    max_turns: int,
) -> None:
    try:
        from strands import Agent
        from strands.models.openai import OpenAIModel

        # Probe models endpoint first
        import httpx

        base = base_url.rstrip("/")
        probe = httpx.get(f"{base}/models", timeout=15.0, headers={"Authorization": f"Bearer {api_key}"})
        if probe.status_code >= 400:
            report.add(
                Check(
                    "live",
                    "Live OpenAI-compatible agent (hunt-shaped)",
                    False,
                    f"GET {base}/models → HTTP {probe.status_code}: {probe.text[:200]}",
                )
            )
            return
        available = []
        try:
            available = [m.get("id") for m in (probe.json().get("data") or [])]
        except Exception:
            pass
        if model_id not in available and available:
            # soft warn but still try
            print(f"  note: model {model_id!r} not in /models list {available[:8]}…; trying anyway")

        ctx = build_ctx(target, evidence)
        tools, session = make_strands_tools(ctx)
        model = OpenAIModel(
            client_args={
                "api_key": api_key,
                "base_url": base_url,
                "timeout": 600.0,
            },
            model_id=model_id,
            params={
                "temperature": 0.2,
                "max_tokens": 2048,
            },
        )
        agent_ref: dict[str, Any] = {}
        agent = Agent(
            model=model,
            tools=tools,
            system_prompt=(
                "You are VulnForge hunt agent on a tiny toy target. "
                "Use grep and/or read_file on the target (read-only). "
                "This is a SPIKE: after a brief look, you MUST call submit_none "
                "with a concrete reason describing what you checked. "
                "Do not invent findings. Prefer submit_none."
            ),
            callback_handler=None,
        )
        attach_submit_stop_hook(agent, agent_ref, session)
        t0 = time.time()
        result = agent(
            "Target is a small Python app. List/find SQL-related code with grep, "
            "read at most one file snippet, then call submit_none explaining residual risk.",
            limits={"turns": max_turns},
        )
        elapsed = time.time() - t0
        stop = getattr(result, "stop_reason", None)
        openaiish = strands_messages_to_openaiish(list(agent.messages))
        n_tc = count_tool_calls(openaiish)
        submitted = session.get("submitted")
        # Success criteria for live: tools ran AND (submit_none succeeded OR cancelled after submit)
        tool_names = []
        for m in openaiish:
            if m.get("role") == "assistant":
                for tc in m.get("tool_calls") or []:
                    tool_names.append((tc.get("function") or {}).get("name"))
        used_read_or_grep = any(n in ("read_file", "grep") for n in tool_names)
        used_submit = "submit_none" in tool_names or bool(submitted)
        # cancel after submit is ideal; end_turn after submit also acceptable if session set
        ok = used_read_or_grep and used_submit and bool(submitted)
        metrics = None
        try:
            metrics = result.metrics.get_summary() if result.metrics else None
        except Exception:
            metrics = None
        detail = (
            f"stop_reason={stop!r} elapsed_s={elapsed:.1f} tool_calls={n_tc} "
            f"tools={tool_names} submitted={submitted!r} "
            f"available_models={available[:6]}"
        )
        report.add(
            Check(
                "live",
                "Live OpenAI-compatible agent (hunt-shaped)",
                ok,
                detail,
                {
                    "stop_reason": stop,
                    "elapsed_s": elapsed,
                    "tool_names": tool_names,
                    "submitted": submitted,
                    "openaiish_len": len(openaiish),
                    "metrics": metrics,
                    "base_url": base_url,
                    "model_id": model_id,
                },
            )
        )
        # Extra soft check: transcript shape after live
        if ok:
            report.add(
                Check(
                    "live_transcript",
                    "Live transcript normalizes with tool names",
                    n_tc >= 1 and any(m.get("role") == "tool" for m in openaiish),
                    f"openaiish_msgs={len(openaiish)} tool_calls={n_tc}",
                    {"sample": openaiish[:6]},
                )
            )
    except Exception as e:
        report.add(
            Check(
                "live",
                "Live OpenAI-compatible agent (hunt-shaped)",
                False,
                f"{type(e).__name__}: {e}\n{traceback.format_exc()}",
            )
        )


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------


def write_report(report: SpikeReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("# Strands Agents — Phase 0 spike report")
    lines.append("")
    lines.append(f"**Date:** {time.strftime('%Y-%m-%d %H:%M %Z')}".rstrip())
    lines.append(f"**Repo:** `{ROOT}`")
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    if report.all_ok:
        lines.append(
            "**GO for Phase 1 (feature-flagged hunt adapter)** — "
            "core checkpoints passed. Still dual-path with `legacy` default."
        )
    else:
        failed = [c.id for c in report.checks if not c.ok]
        lines.append(
            f"**PARTIAL / NO-GO until fixed:** failed checks: `{', '.join(failed)}`. "
            "See details below before funding Phase 1."
        )
    lines.append("")
    lines.append("## Meta")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(report.meta, indent=2, default=str))
    lines.append("```")
    lines.append("")
    lines.append("## Checkpoints")
    lines.append("")
    lines.append("| ID | Result | Title |")
    lines.append("|----|--------|-------|")
    for c in report.checks:
        mark = "PASS" if c.ok else "FAIL"
        lines.append(f"| `{c.id}` | **{mark}** | {c.title} |")
    lines.append("")
    for c in report.checks:
        lines.append(f"### `{c.id}` — {'PASS' if c.ok else 'FAIL'}")
        lines.append("")
        lines.append(c.detail)
        lines.append("")
        if c.evidence:
            # Trim huge evidence
            ev = c.evidence
            if "openaiish" in ev and isinstance(ev["openaiish"], list):
                ev = dict(ev)
                ev["openaiish"] = ev["openaiish"][:12]
                ev["openaiish_truncated"] = True
            if "metrics" in ev and ev["metrics"] and isinstance(ev["metrics"], dict):
                # keep summary only
                m = dict(ev["metrics"])
                if "traces" in m:
                    m["traces"] = f"<{len(m['traces'])} traces omitted>"
                ev = dict(ev)
                ev["metrics"] = m
            lines.append("<details><summary>evidence</summary>")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(ev, indent=2, default=str)[:8000])
            lines.append("```")
            lines.append("")
            lines.append("</details>")
            lines.append("")
    lines.append("## Findings for Phase 1 design")
    lines.append("")
    lines.append("1. **Submit stop works via `agent.cancel()` in `AfterToolCallEvent`** when "
                 "`submit_none` returns `ok: true`. `stop_reason` becomes `cancelled` "
                 "(domain-success cancel — map to successful terminal in adapter, not failure).")
    lines.append("2. **Strands message shape ≠ VulnForge OpenAI-ish transcripts.** "
                 "Tool results are `user` messages with `toolResult` blocks. "
                 "A normalizer (as in this spike) is required for tool-gaps / usage.")
    lines.append("3. **Scripted custom `Model` works** for offline tests — viable FakeLLM path, "
                 "but must implement async `stream()` StreamEvents (not `chat()`).")
    lines.append("4. **Thin wrappers** can call existing `vulnforge.tools.run_tool(ctx, …)` — "
                 "do not rewrite tool bodies.")
    lines.append("5. **Dependency weight:** `strands-agents[openai]` pulls boto3, mcp, otel, openai, etc. "
                 "Keep as **optional** extra, not a hard runtime dep for default installs.")
    lines.append("6. **Do not** register `strands-agents-tools` shell tools on `code_static`.")
    lines.append(
        "7. **Hook registration:** pass event type explicitly "
        "(`hooks.add_callback(AfterToolCallEvent, cb)`); nested annotations break inference."
    )
    lines.append(
        "8. **Reasoning models (Ornith):** live runs may warn "
        "`reasoningContent is not supported in multi-turn conversations with the Chat Completions API` — "
        "strip or map reasoning blocks in Phase 1 adapter."
    )
    lines.append("")
    lines.append("## Effort estimate (Phase 1)")
    lines.append("")
    lines.append("| Item | Estimate |")
    lines.append("|------|----------|")
    lines.append("| `AgentRuntime` protocol + legacy wrapper | 0.5–1 d |")
    lines.append("| Strands runtime + tool bridge + submit-stop hook | 1–2 d |")
    lines.append("| Transcript/usage normalizer + tool-gaps smoke | 0.5–1 d |")
    lines.append("| Config flag + settings UI note | 0.5 d |")
    lines.append("| Tests (scripted model + 1 live optional) | 1 d |")
    lines.append("| **Total** | **~4–6 engineer-days** |")
    lines.append("")
    lines.append("## How to re-run")
    lines.append("")
    lines.append("```powershell")
    lines.append("cd VulnForge")
    lines.append(".\\.venv\\Scripts\\Activate.ps1")
    lines.append("pip install 'strands-agents[openai]'   # if needed")
    lines.append(
        "python scripts/strands_spike.py "
        "--base-url http://192.168.32.10:1234/v1 --model ornith-1.0-35b"
    )
    lines.append("```")
    lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nReport written: {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def prepare_workspace() -> tuple[Path, Path]:
    work = ROOT / ".pytest_tmp" / "strands_spike"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    target = work / "target"
    evidence = work / "evidence"
    target.mkdir(parents=True)
    evidence.mkdir(parents=True)
    # Prefer toy_sqli fixture
    src = ROOT / "fixtures" / "toy_sqli"
    if src.is_dir():
        for p in src.iterdir():
            dest = target / p.name
            if p.is_file():
                shutil.copy2(p, dest)
            elif p.is_dir():
                shutil.copytree(p, dest)
    else:
        (target / "app.py").write_text(
            "def q(u):\n    return 'select * from t where id=' + u\n",
            encoding="utf-8",
        )
    return target, evidence


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="VulnForge × Strands Phase 0 spike")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--api-key", default=DEFAULT_API_KEY)
    ap.add_argument("--max-turns", type=int, default=10)
    ap.add_argument("--scripted-only", action="store_true")
    ap.add_argument("--live-only", action="store_true")
    ap.add_argument("--no-report", action="store_true")
    ap.add_argument(
        "--report-path",
        type=Path,
        default=ROOT / "docs" / "plans" / "strands-phase0-spike-report.md",
    )
    args = ap.parse_args(argv)

    print("=== VulnForge × Strands Phase 0 spike ===")
    report = SpikeReport(
        meta={
            "base_url": args.base_url,
            "model": args.model,
            "scripted_only": args.scripted_only,
            "live_only": args.live_only,
            "max_turns": args.max_turns,
            "strands_version_note": "strands-agents (see pip show)",
        }
    )
    try:
        import importlib.metadata as md

        report.meta["strands_agents_version"] = md.version("strands-agents")
    except Exception:
        pass

    target, evidence = prepare_workspace()
    report.meta["target"] = str(target)
    print(f"workspace target={target}")

    check_import(report)
    if not any(c.id == "import" and c.ok for c in report.checks):
        if not args.no_report:
            write_report(report, args.report_path)
        return 2

    agent = None
    if not args.live_only:
        print("\n-- scripted / offline --")
        check_tool_bodies(report, target, evidence)
        agent = check_scripted_submit_stop(report, target, evidence)
        check_transcript(report, agent)

    if not args.scripted_only:
        print("\n-- live --")
        print(f"   base_url={args.base_url} model={args.model}")
        check_live(
            report,
            target,
            evidence,
            base_url=args.base_url,
            model_id=args.model,
            api_key=args.api_key,
            max_turns=args.max_turns,
        )

    if not args.no_report:
        write_report(report, args.report_path)

    print("\n=== summary ===")
    for c in report.checks:
        print(f"  {'PASS' if c.ok else 'FAIL'}  {c.id}")
    return 0 if report.all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
