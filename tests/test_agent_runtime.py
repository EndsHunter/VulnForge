"""Agent runtime: Strands production path + FakeLLM offline tool loop."""

from __future__ import annotations

import json
from typing import Any, AsyncIterable

import pytest

from vulnforge.agent_runtime import run_tool_loop
from vulnforge.agent_runtime.transcript import (
    openaiish_to_strands_messages,
    strands_messages_to_openaiish,
)
from vulnforge.llm import FakeLLMClient, LLMResult, ResponseClass, TokenUsage
from vulnforge.packet import Packet


def test_run_tool_loop_fake_client():
    client = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content="",
                tool_calls=[
                    {
                        "id": "1",
                        "name": "submit_none",
                        "arguments": {"reason": "unit test clean"},
                    }
                ],
                raw=None,
                model_id="fake",
                usage=TokenUsage(
                    prompt_tokens=5,
                    completion_tokens=2,
                    total_tokens=7,
                    source="provider",
                ),
            )
        ]
    )
    packet = Packet(system="sys", user="user", tools_schema=[])

    def handler(name, args):
        assert name == "submit_none"
        return {"ok": True, "stored": "none"}

    result = run_tool_loop(
        client,
        packet,
        handler,
        max_rounds=4,
        temperature=0.1,
    )
    assert result.ok
    assert result.usage is not None
    assert result.usage.prompt_tokens == 5


def test_transcript_normalizer():
    raw = [
        {"role": "user", "content": [{"text": "go"}]},
        {
            "role": "assistant",
            "content": [
                {
                    "toolUse": {
                        "toolUseId": "c1",
                        "name": "read_file",
                        "input": {"path": "a.py"},
                    }
                }
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "toolResult": {
                        "toolUseId": "c1",
                        "status": "success",
                        "content": [{"text": '{"ok": true}'}],
                    }
                }
            ],
        },
    ]
    out = strands_messages_to_openaiish(raw)
    assert out[0]["role"] == "user"
    assert out[1]["role"] == "assistant"
    assert out[1]["tool_calls"][0]["function"]["name"] == "read_file"
    assert out[2]["role"] == "tool"
    assert out[2]["name"] == "read_file"
    assert "ok" in out[2]["content"]


def test_openaiish_roundtrip_and_tool_gaps():
    """Normalized Strands transcripts remain tool_gaps-scannable."""
    openaiish = [
        {"role": "user", "content": "hunt"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "1",
                    "type": "function",
                    "function": {
                        "name": "mystery_tool",
                        "arguments": '{"x": 1}',
                    },
                }
            ],
        },
        {
            "role": "tool",
            "tool_call_id": "1",
            "name": "mystery_tool",
            "content": '{"ok": false, "error": "unknown tool"}',
        },
    ]
    strands = openaiish_to_strands_messages(openaiish)
    back = strands_messages_to_openaiish(strands)
    assert any(
        (tc.get("function") or {}).get("name") == "mystery_tool"
        for m in back
        if m.get("role") == "assistant"
        for tc in (m.get("tool_calls") or [])
    )
    # At minimum, names are recoverable for gap mining (tool_gaps walks tool_calls)
    names = []
    for m in openaiish:
        if m.get("role") == "assistant":
            for tc in m.get("tool_calls") or []:
                names.append((tc.get("function") or {}).get("name"))
    assert "mystery_tool" in names
    assert any(m.get("role") == "tool" for m in openaiish)


def test_strands_scripted_submit_stop():
    pytest.importorskip("strands")
    from strands import Agent
    from strands.models.model import Model
    from strands.tools.tools import PythonAgentTool

    from vulnforge.agent_runtime.strands_loop import (
        TERMINAL_TOOLS,
        _attach_submit_stop_hook,
    )
    from vulnforge.agent_runtime.transcript import strands_messages_to_openaiish

    class ScriptedModel(Model):
        def __init__(self, scripts: list[dict[str, Any]]):
            self._scripts = list(scripts)
            self._i = 0
            self._config = {"model_id": "scripted"}

        def update_config(self, **kwargs: Any) -> None:
            self._config.update(kwargs)

        def get_config(self) -> dict[str, Any]:
            return self._config

        async def structured_output(self, *a: Any, **k: Any):  # noqa: ANN401
            raise NotImplementedError

        async def stream(  # type: ignore[no-untyped-def]
            self, messages, tool_specs=None, system_prompt=None, **kwargs: Any
        ) -> AsyncIterable[dict[str, Any]]:
            if self._i >= len(self._scripts):
                script: dict[str, Any] = {"text": "exhausted"}
            else:
                script = self._scripts[self._i]
                self._i += 1
            yield {"messageStart": {"role": "assistant"}}
            if script.get("text"):
                yield {"contentBlockStart": {"start": {}}}
                yield {
                    "contentBlockDelta": {"delta": {"text": str(script["text"])}}
                }
                yield {"contentBlockStop": {}}
            for tc in script.get("tool_calls") or []:
                yield {
                    "contentBlockStart": {
                        "start": {
                            "toolUse": {
                                "name": tc["name"],
                                "toolUseId": tc.get("id") or "c",
                            }
                        }
                    }
                }
                yield {
                    "contentBlockDelta": {
                        "delta": {
                            "toolUse": {
                                "input": json.dumps(tc.get("arguments") or {})
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
                        "inputTokens": 3,
                        "outputTokens": 2,
                        "totalTokens": 5,
                    },
                    "metrics": {"latencyMs": 1},
                }
            }

    session: dict[str, Any] = {"terminal_ok": False}

    def make_tool(name: str) -> PythonAgentTool:
        def tool_func(tool_use: dict, **_k: Any) -> dict[str, Any]:
            args = tool_use.get("input") or {}
            if name == "submit_none":
                out = {"ok": True, "reason": args.get("reason")}
                session["terminal_ok"] = True
            else:
                out = {"ok": True, "path": args.get("path"), "content": "x=1"}
            return {
                "toolUseId": tool_use.get("toolUseId") or "c",
                "status": "success",
                "content": [{"text": json.dumps(out)}],
            }

        return PythonAgentTool(
            name,
            {
                "name": name,
                "description": name,
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "reason": {"type": "string"},
                        },
                    }
                },
            },
            tool_func,
        )

    model = ScriptedModel(
        [
            {
                "tool_calls": [
                    {
                        "id": "c1",
                        "name": "read_file",
                        "arguments": {"path": "a.py"},
                    }
                ]
            },
            {
                "tool_calls": [
                    {
                        "id": "c2",
                        "name": "submit_none",
                        "arguments": {"reason": "checked a.py"},
                    }
                ]
            },
            {"text": "SHOULD_NOT_REACH"},
        ]
    )
    agent = Agent(
        model=model,
        tools=[make_tool("read_file"), make_tool("submit_none")],
        system_prompt="hunt",
        callback_handler=None,
    )
    _attach_submit_stop_hook(agent, session)
    result = agent("go", limits={"turns": 6})
    assert session["terminal_ok"] is True
    assert result.stop_reason == "cancelled"
    assert model._i == 2  # third script not consumed
    openaiish = strands_messages_to_openaiish(list(agent.messages))
    names = []
    for m in openaiish:
        if m.get("role") == "assistant":
            for tc in m.get("tool_calls") or []:
                names.append((tc.get("function") or {}).get("name"))
    assert "read_file" in names
    assert "submit_none" in names
    assert "submit_none" in TERMINAL_TOOLS


def test_run_strands_tool_loop_with_scripted_client(monkeypatch):
    """Integration: run_strands_tool_loop maps terminal submit → ok LLMResult."""
    pytest.importorskip("strands")
    from strands.models.model import Model

    import vulnforge.agent_runtime.strands_loop as sl

    class ScriptedModel(Model):
        def __init__(self) -> None:
            self._i = 0
            self._config = {"model_id": "scripted"}

        def update_config(self, **kwargs: Any) -> None:
            self._config.update(kwargs)

        def get_config(self) -> dict[str, Any]:
            return self._config

        async def structured_output(self, *a: Any, **k: Any):  # noqa: ANN401
            raise NotImplementedError

        async def stream(  # type: ignore[no-untyped-def]
            self, messages, tool_specs=None, system_prompt=None, **kwargs: Any
        ) -> AsyncIterable[dict[str, Any]]:
            self._i += 1
            yield {"messageStart": {"role": "assistant"}}
            yield {
                "contentBlockStart": {
                    "start": {
                        "toolUse": {
                            "name": "submit_none",
                            "toolUseId": "t1",
                        }
                    }
                }
            }
            yield {
                "contentBlockDelta": {
                    "delta": {
                        "toolUse": {
                            "input": json.dumps(
                                {"reason": "integration scripted"}
                            )
                        }
                    }
                }
            }
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "tool_use"}}
            yield {
                "metadata": {
                    "usage": {
                        "inputTokens": 4,
                        "outputTokens": 1,
                        "totalTokens": 5,
                    },
                    "metrics": {"latencyMs": 1},
                }
            }

    def fake_model_from_client(client: Any, temperature: float) -> Any:
        return ScriptedModel()

    monkeypatch.setattr(sl, "_model_from_client", fake_model_from_client)

    class DummyClient:
        model = "scripted"
        base_url = "http://example.invalid/v1"
        api_key = "x"
        timeout = 30
        max_tokens = 256

    packet = Packet(
        system="sys",
        user="finish with submit_none",
        tools_schema=[
            {
                "type": "function",
                "function": {
                    "name": "submit_none",
                    "description": "done",
                    "parameters": {
                        "type": "object",
                        "properties": {"reason": {"type": "string"}},
                        "required": ["reason"],
                    },
                },
            }
        ],
    )

    def handler(name: str, args: dict) -> dict:
        assert name == "submit_none"
        return {"ok": True, "stored": "none"}

    result = sl.run_strands_tool_loop(
        DummyClient(), packet, handler, max_rounds=4, temperature=0.1
    )
    assert result.ok
    assert result.error is None
    assert any(
        m.get("role") == "tool" or m.get("role") == "assistant"
        for m in (result.transcript or [])
    )
    assert result.raw and result.raw.get("strands") is True


def test_operator_loop_fake_client():
    from vulnforge.operator_chat.loop import run_operator_loop

    client = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content="hello operator",
                tool_calls=[],
                raw=None,
                model_id="fake",
            )
        ]
    )
    result = run_operator_loop(
        client=client,
        system="sys",
        history=[],
        user_message="hi",
        tools=[],
        dispatch=lambda n, a: {"ok": True},
        max_rounds=3,
        session_id="s1",
        scope="home",
    )
    assert result["ok"]
    texts = [
        m.get("content")
        for m in result["messages"]
        if m.get("role") == "assistant"
    ]
    assert any("hello operator" in str(t) for t in texts)


def test_recon_graph_scripted_two_agents():
    pytest.importorskip("strands")
    from strands.models.model import Model

    import vulnforge.agent_runtime.recon_graph as rg

    class ScriptedModel(Model):
        def __init__(self, agent_label: str) -> None:
            self._label = agent_label
            self._i = 0
            self._config = {"model_id": f"scripted-{agent_label}"}

        def update_config(self, **kwargs: Any) -> None:
            self._config.update(kwargs)

        def get_config(self) -> dict[str, Any]:
            return self._config

        async def structured_output(self, *a: Any, **k: Any):  # noqa: ANN401
            raise NotImplementedError

        async def stream(  # type: ignore[no-untyped-def]
            self, messages, tool_specs=None, system_prompt=None, **kwargs: Any
        ) -> AsyncIterable[dict[str, Any]]:
            self._i += 1
            yield {"messageStart": {"role": "assistant"}}
            yield {
                "contentBlockStart": {
                    "start": {
                        "toolUse": {
                            "name": "submit_architecture",
                            "toolUseId": f"t-{self._label}",
                        }
                    }
                }
            }
            yield {
                "contentBlockDelta": {
                    "delta": {
                        "toolUse": {
                            "input": json.dumps(
                                {
                                    "summary": f"arch from {self._label}",
                                    "components": [],
                                }
                            )
                        }
                    }
                }
            }
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "tool_use"}}
            yield {
                "metadata": {
                    "usage": {
                        "inputTokens": 2,
                        "outputTokens": 2,
                        "totalTokens": 4,
                    },
                    "metrics": {"latencyMs": 1},
                }
            }

    models = {"a": ScriptedModel("a"), "b": ScriptedModel("b")}

    def fake_model(client: Any, temperature: float) -> Any:
        # alternate by call order
        fake_model.i = getattr(fake_model, "i", 0) + 1  # type: ignore[attr-defined]
        return models["a"] if fake_model.i % 2 == 1 else models["b"]  # type: ignore[attr-defined]

    monkey = pytest.MonkeyPatch()
    monkey.setattr(rg, "_model_from_client", fake_model)
    try:
        outer: dict[str, Any] = {"architecture": None}

        def handler(name: str, args: dict) -> dict:
            if name == "submit_architecture":
                outer["architecture"] = {
                    "summary": args.get("summary") or "",
                    "components": args.get("components") or [],
                    "trust_boundaries": [],
                    "input_surfaces": [],
                    "hunt_focus": [],
                }
                return {"ok": True}
            return {"ok": True}

        packets = [
            {
                "id": "a",
                "packet": Packet(
                    system="sa",
                    user="map a",
                    tools_schema=[
                        {
                            "type": "function",
                            "function": {
                                "name": "submit_architecture",
                                "description": "submit",
                                "parameters": {
                                    "type": "object",
                                    "properties": {
                                        "summary": {"type": "string"},
                                        "components": {"type": "array"},
                                    },
                                },
                            },
                        }
                    ],
                ),
                "max_rounds": 4,
                "temperature": 0.1,
            },
            {
                "id": "b",
                "packet": Packet(
                    system="sb",
                    user="map b",
                    tools_schema=[
                        {
                            "type": "function",
                            "function": {
                                "name": "submit_architecture",
                                "description": "submit",
                                "parameters": {
                                    "type": "object",
                                    "properties": {
                                        "summary": {"type": "string"},
                                        "components": {"type": "array"},
                                    },
                                },
                            },
                        }
                    ],
                ),
                "max_rounds": 4,
                "temperature": 0.1,
            },
        ]

        class DummyClient:
            model = "scripted"
            base_url = "http://example.invalid/v1"
            api_key = "x"
            timeout = 30
            max_tokens = 256

        gres = rg.run_recon_strands_graph(
            DummyClient(),
            packets,
            handler,
            outer_session=outer,
        )
        assert gres.get("ok")
        assert len(gres.get("node_results") or []) == 2
        for nr in gres["node_results"]:
            assert nr["result"].ok
            assert nr.get("architecture") and nr["architecture"].get("summary")
    finally:
        monkey.undo()
