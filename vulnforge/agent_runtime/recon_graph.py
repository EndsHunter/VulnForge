"""Phase 3: multi-agent recon as a sequential Strands Graph.

Each recon profile is a Graph node. Edges form a pipeline (agent0 → agent1 → …).
Domain tools (read/grep/submit_architecture) stay VulnForge-owned. Architecture
partials are collected via the shared tool session — Graph does **not** auto-confirm
findings (honesty rules unchanged).
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Optional

from vulnforge.llm import LLMResult, ResponseClass, TokenUsage
from vulnforge.agent_runtime.strands_loop import (
    _attach_reasoning_strip_hook,
    _attach_submit_stop_hook,
    _model_from_client,
    _openai_tools_to_strands,
    _require_strands,
    _usage_from_result,
)
from vulnforge.agent_runtime.transcript import strands_messages_to_openaiish

logger = logging.getLogger(__name__)


def run_recon_strands_graph(
    client: Any,
    agent_packets: list[dict[str, Any]],
    tool_handler: Callable[[str, dict], dict],
    *,
    temperature_default: float = 0.3,
    outer_session: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Run recon specialist agents as a sequential Strands Graph.

    Parameters
    ----------
    agent_packets:
        Each item: ``{id, packet, max_rounds, temperature}`` where ``packet``
        has ``.system``, ``.user``, ``.tools_schema``.

    Returns
    -------
    dict with keys:
      - ok: bool
      - node_results: list[{agent_id, result: LLMResult, session_snapshot}]
      - error: optional str
      - graph_status: optional
    """
    _require_strands()
    from strands import Agent
    from strands.multiagent import GraphBuilder

    if not agent_packets:
        return {"ok": False, "error": "no_agents", "node_results": []}

    # Shared session for terminal flags; architectures collected per node via handler wrap
    collected: list[dict[str, Any]] = []
    current_id: dict[str, str] = {"id": ""}
    sessions: dict[str, dict[str, Any]] = {}

    def wrapping_handler(name: str, args: dict) -> dict:
        out = tool_handler(name, args or {})
        if (
            name == "submit_architecture"
            and isinstance(out, dict)
            and out.get("ok") is True
        ):
            collected.append(
                {
                    "agent_id": current_id["id"],
                    "submit": args,
                    "result": out,
                }
            )
            # Snapshot architecture from outer recon session for this node
            if outer_session is not None and outer_session.get("architecture"):
                sessions.setdefault(current_id["id"], {})[
                    "architecture"
                ] = dict(outer_session["architecture"])
        return out

    builder = GraphBuilder()
    node_ids: list[str] = []
    agents_by_id: dict[str, Any] = {}

    for spec in agent_packets:
        aid = str(spec.get("id") or f"agent_{len(node_ids)}")
        packet = spec["packet"]
        max_rounds = int(spec.get("max_rounds") or 12)
        temp = float(
            spec["temperature"]
            if spec.get("temperature") is not None
            else temperature_default
        )
        session: dict[str, Any] = {
            "terminal_ok": False,
            "terminal_tool": None,
            "terminal_result": None,
            "agent_id": aid,
        }
        sessions[aid] = session
        tools = _openai_tools_to_strands(
            getattr(packet, "tools_schema", None) or [],
            wrapping_handler,
            session,
        )
        model = _model_from_client(client, temp)
        # Capture max_rounds via closure on Agent invoke — Graph uses agent()
        # without limits; set via agent property if available, else rely on
        # graph node timeout. We wrap invoke by subclassing is hard; use
        # Agent and set attribute for our custom runner below.
        agent = Agent(
            model=model,
            tools=tools,
            system_prompt=str(getattr(packet, "system", "") or "") or None,
            callback_handler=None,
            name=aid,
            agent_id=aid,
        )
        _attach_submit_stop_hook(agent, session)
        _attach_reasoning_strip_hook(agent)
        # Store packet user + limits on agent for custom node invoke
        agent._vf_user = str(getattr(packet, "user", "") or "")  # type: ignore[attr-defined]
        agent._vf_max_rounds = max_rounds  # type: ignore[attr-defined]
        agents_by_id[aid] = agent
        builder.add_node(agent, aid)
        node_ids.append(aid)

    for a, b in zip(node_ids, node_ids[1:]):
        builder.add_edge(a, b)
    if node_ids:
        builder.set_entry_point(node_ids[0])
    builder.set_max_node_executions(max(len(node_ids) * 2, 4))
    builder.set_execution_timeout(float(getattr(client, "timeout", 600) or 600) * len(node_ids))

    graph = builder.build()

    # Monkey-patch: before each node, set current_id. Use hook if available.
    try:
        from strands.hooks import BeforeNodeCallEvent

        def before_node(event: Any) -> None:
            nid = getattr(event, "node_id", None) or ""
            current_id["id"] = str(nid)
            # Reset terminal flag for this node
            if nid in sessions:
                sessions[nid]["terminal_ok"] = False

        graph.hooks.add_callback(BeforeNodeCallEvent, before_node)  # type: ignore[attr-defined]
    except Exception:
        # Fallback: set first agent id
        if node_ids:
            current_id["id"] = node_ids[0]

    # Prefer invoking each agent ourselves in sequence if Graph doesn't pass limits —
    # Graph's default agent() call may not apply max_rounds. Sequential manual run
    # with GraphBuilder only for structure is weaker; instead invoke graph with task
    # and then re-run with explicit sequential if needed.
    #
    # Practical approach: sequential explicit invoke with same agents (pipeline),
    # recording Graph topology in meta. True Graph.invoke may not pass per-node
    # limits; we sequential-invoke agents with limits for reliability.
    node_results: list[dict[str, Any]] = []
    prior_summary = ""
    ok_all = True
    for aid in node_ids:
        current_id["id"] = aid
        sessions[aid]["terminal_ok"] = False
        agent = agents_by_id[aid]
        user = str(getattr(agent, "_vf_user", "") or "Map the architecture and submit_architecture.")
        if prior_summary:
            user = (
                user
                + "\n\n## Prior agent architecture (refine / extend, do not blank-overwrite)\n"
                + prior_summary[:6000]
            )
        max_rounds = int(getattr(agent, "_vf_max_rounds", 12) or 12)
        try:
            result = agent(user, limits={"turns": max(1, max_rounds)})
        except Exception as e:
            ok_all = False
            node_results.append(
                {
                    "agent_id": aid,
                    "result": LLMResult(
                        ok=False,
                        classification=ResponseClass.TRANSPORT,
                        content=None,
                        tool_calls=[],
                        raw=None,
                        model_id=getattr(client, "model", None),
                        error=str(e),
                        transcript=[],
                    ),
                    "error": str(e),
                }
            )
            break

        openaiish = strands_messages_to_openaiish(list(agent.messages))
        packet = next(
            (s["packet"] for s in agent_packets if str(s.get("id")) == aid),
            None,
        )
        transcript: list[dict[str, Any]] = []
        if packet is not None and getattr(packet, "system", None):
            transcript.append({"role": "system", "content": packet.system})
        transcript.extend(openaiish)
        usage = _usage_from_result(result)
        terminal = bool(sessions[aid].get("terminal_ok"))
        stop = getattr(result, "stop_reason", None)
        content = None
        for m in reversed(openaiish):
            if m.get("role") == "assistant" and m.get("content"):
                content = m["content"]
                break
        llm_res = LLMResult(
            ok=terminal,
            classification=ResponseClass.OK if terminal else ResponseClass.TRUNCATED,
            content=content,
            tool_calls=[],
            raw={"stop_reason": stop, "strands": True, "recon_graph": True},
            model_id=getattr(client, "model", None),
            error=None if terminal else "no_submit",
            transcript=transcript,
            usage=usage,
        )
        if not terminal:
            ok_all = False
        arch_snap = None
        if outer_session is not None and outer_session.get("architecture"):
            arch_snap = dict(outer_session["architecture"])
            sessions[aid]["architecture"] = arch_snap
            # Clear so next node must submit fresh (merge handoff via prior_summary)
            outer_session["architecture"] = None
        elif sessions[aid].get("architecture"):
            arch_snap = dict(sessions[aid]["architecture"])

        node_results.append(
            {
                "agent_id": aid,
                "result": llm_res,
                "session": dict(sessions[aid]),
                "architecture": arch_snap,
            }
        )
        if arch_snap and arch_snap.get("summary"):
            prior_summary = json.dumps(
                {
                    "summary": arch_snap.get("summary"),
                    "components": arch_snap.get("components"),
                    "trust_boundaries": arch_snap.get("trust_boundaries"),
                    "input_surfaces": arch_snap.get("input_surfaces"),
                    "hunt_focus": arch_snap.get("hunt_focus"),
                },
                indent=2,
            )[:6000]
        elif content:
            prior_summary = str(content)[:4000]

    # Also try Graph topology validation for observability (built, not required to re-run)
    graph_meta = {"node_ids": node_ids, "edges": list(zip(node_ids, node_ids[1:])), "mode": "sequential_pipeline"}

    return {
        "ok": ok_all and bool(node_results),
        "node_results": node_results,
        "submits": collected,
        "graph": graph_meta,
        "error": None if ok_all else "graph_node_failed",
    }
