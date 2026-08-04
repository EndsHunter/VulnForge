# Strands Agents — Phase 0 spike report

**Date:** 2026-08-04 11:50 Eastern Daylight Time
**Repo:** `C:\Users\jkooy\Desktop\VulnForge`

## Verdict

**GO for Phase 1 (feature-flagged hunt adapter)** — core checkpoints passed. Still dual-path with `legacy` default.

### Phase 1–3 + full transition (implemented)

**Production agent loop is Strands-only** (core dep `strands-agents[openai]`). Dual-runtime / `agent_runtime` / `VF_AGENT_RUNTIME` / hand-rolled `LLMClient.run_tool_loop` removed.

- Hunt / recon / develop_poc / operator chat → `vulnforge/agent_runtime/`
- Multi-agent recon: `ralph` | `inprocess` | `graph`
- Offline tests: `FakeLLMClient.run_tool_loop` only

## Meta

```json
{
  "base_url": "http://192.168.32.10:1234/v1",
  "model": "ornith-1.0-35b",
  "scripted_only": false,
  "live_only": false,
  "max_turns": 10,
  "strands_version_note": "strands-agents (see pip show)",
  "strands_agents_version": "1.50.2",
  "target": "C:\\Users\\jkooy\\Desktop\\VulnForge\\.pytest_tmp\\strands_spike\\target"
}
```

## Checkpoints

| ID | Result | Title |
|----|--------|-------|
| `import` | **PASS** | strands-agents importable |
| `tool_wrap` | **PASS** | Existing VulnForge tools run via thin wrappers |
| `submit_stop_scripted` | **PASS** | Domain terminal tool stops loop (scripted) |
| `transcript` | **PASS** | Normalize Strands messages → OpenAI-ish transcript |
| `live` | **PASS** | Live OpenAI-compatible agent (hunt-shaped) |
| `live_transcript` | **PASS** | Live transcript normalizes with tool names |

### `import` — PASS

strands loaded from C:\Users\jkooy\Desktop\VulnForge\.venv\Lib\site-packages\strands\__init__.py

<details><summary>evidence</summary>

```json
{
  "file": "C:\\Users\\jkooy\\Desktop\\VulnForge\\.venv\\Lib\\site-packages\\strands\\__init__.py",
  "version": null
}
```

</details>

### `tool_wrap` — PASS

read_file keys=['ok', 'path', 'content', 'total_lines', 'truncated']; submit_none={'ok': True, 'status': 'none', 'reason': 'direct path check for spike'}; direct_fn_type=dict

<details><summary>evidence</summary>

```json
{
  "read_file": {
    "ok": true,
    "path": "app.py",
    "content": "\"\"\"\nTiny intentional SQLi fixture for harness end-to-end tests later.\n\nWARNING: deliberately vulnerable \u2014 do not deploy.\n\"\"\"\n\n# TODO: expand into minimal Flask/FastAPI app with known SQLi for integration tests\n\ndef search_users(db_cursor, q: str):\n    # INTENTIONALLY VULNERABLE \u2014 fixture only\n    sql = f\"SELECT * FROM users WHERE name = '{q}'\"\n    return db_cursor.execute(sql)\n\n# mutated\n\n# mutated\n\n# mutated\n\n# mutated\n\n# mutated\n\n# mutated\n\n# mutated\n\n# mutated\n\n# mutated\n\n# mutated\n\n# mutated\n\n# mutated\n\n# mutated\n\n# mutated",
    "total_lines": 40,
    "truncated": false
  },
  "submit_none": {
    "ok": true,
    "status": "none",
    "reason": "direct path check for spike"
  }
}
```

</details>

### `submit_stop_scripted` — PASS

stop_reason='cancelled' scripts_used=2/3 submitted={'kind': 'none', 'reason': 'Read app.py; toy fixture only, no solid vuln bar met for spike.'}

<details><summary>evidence</summary>

```json
{
  "stop_reason": "cancelled",
  "scripts_used": 2,
  "submitted": {
    "kind": "none",
    "reason": "Read app.py; toy fixture only, no solid vuln bar met for spike."
  },
  "messages": 5
}
```

</details>

### `transcript` — PASS

openaiish_msgs=5 tool_calls=2 names=['read_file', 'result:read_file', 'submit_none', 'result:submit_none'] roles=['user', 'assistant', 'tool', 'assistant', 'tool']

<details><summary>evidence</summary>

```json
{
  "openaiish": [
    {
      "role": "user",
      "content": "Audit the target. Read app.py then call submit_none with a concrete reason."
    },
    {
      "role": "assistant",
      "content": "",
      "tool_calls": [
        {
          "id": "c1",
          "type": "function",
          "function": {
            "name": "read_file",
            "arguments": "{\"path\": \"app.py\"}"
          }
        }
      ]
    },
    {
      "role": "tool",
      "tool_call_id": "c1",
      "name": "read_file",
      "content": "{\"ok\": true, \"path\": \"app.py\", \"content\": \"\\\"\\\"\\\"\\nTiny intentional SQLi fixture for harness end-to-end tests later.\\n\\nWARNING: deliberately vulnerable \u2014 do not deploy.\\n\\\"\\\"\\\"\\n\\n# TODO: expand into minimal Flask/FastAPI app with known SQLi for integration tests\\n\\ndef search_users(db_cursor, q: str):\\n    # INTENTIONALLY VULNERABLE \u2014 fixture only\\n    sql = f\\\"SELECT * FROM users WHERE name = '{q}'\\\"\\n    return db_cursor.execute(sql)\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\", \"total_lines\": 40, \"truncated\": false}",
      "status": "success"
    },
    {
      "role": "assistant",
      "content": "",
      "tool_calls": [
        {
          "id": "c2",
          "type": "function",
          "function": {
            "name": "submit_none",
            "arguments": "{\"reason\": \"Read app.py; toy fixture only, no solid vuln bar met for spike.\"}"
          }
        }
      ]
    },
    {
      "role": "tool",
      "tool_call_id": "c2",
      "name": "submit_none",
      "content": "{\"ok\": true, \"status\": \"none\", \"reason\": \"Read app.py; toy fixture only, no solid vuln bar met for spike.\"}",
      "status": "success"
    }
  ],
  "raw_roles": [
    "user",
    "assistant",
    "user",
    "assistant",
    "user"
  ],
  "openaiish_truncated": true
}
```

</details>

### `live` — PASS

stop_reason='cancelled' elapsed_s=29.1 tool_calls=3 tools=['grep', 'read_file', 'submit_none'] submitted={'kind': 'none', 'reason': 'SPIKE scan of app.py — grep for SQL patterns found one clear case: `search_users()` at line 11 uses f-string interpolation (`f"SELECT * FROM users WHERE name = \'{q}\'"`) directly into cursor.execute(), which is a textbook SQL injection vulnerability. The file header comments indicate this is an intentional fixture ("deliberately vulnerable — do not deploy", "Tiny intentional SQLi fixture for harness end-to-end tests later"). Residual risk: (1) only one file was scanned; other files may contain similar unparameterized query patterns; (2) if this fixture were accidentally deployed or copied into production code, the vulnerability would be exploitable with zero additional changes. No further deep analysis performed per SPIKE scope.'} available_models=['ornith-1.0-35b', 'ornith-1.0-35b:2', 'phi-4-reasoning-plus-ud', 'phi-4-mini-instruct', 'gpt-oss-20b', 'text-embedding-nomic-embed-text-v1.5']

<details><summary>evidence</summary>

```json
{
  "stop_reason": "cancelled",
  "elapsed_s": 29.05294704437256,
  "tool_names": [
    "grep",
    "read_file",
    "submit_none"
  ],
  "submitted": {
    "kind": "none",
    "reason": "SPIKE scan of app.py \u2014 grep for SQL patterns found one clear case: `search_users()` at line 11 uses f-string interpolation (`f\"SELECT * FROM users WHERE name = '{q}'\"`) directly into cursor.execute(), which is a textbook SQL injection vulnerability. The file header comments indicate this is an intentional fixture (\"deliberately vulnerable \u2014 do not deploy\", \"Tiny intentional SQLi fixture for harness end-to-end tests later\"). Residual risk: (1) only one file was scanned; other files may contain similar unparameterized query patterns; (2) if this fixture were accidentally deployed or copied into production code, the vulnerability would be exploitable with zero additional changes. No further deep analysis performed per SPIKE scope."
  },
  "openaiish_len": 7,
  "metrics": {
    "total_cycles": 3,
    "total_duration": 29.045825481414795,
    "average_cycle_time": 9.681941827138266,
    "tool_usage": {
      "grep": {
        "tool_info": {
          "tool_use_id": "VQmJlpu6NJHWGA6dGzak2bBxKbMiK3Ur",
          "name": "grep",
          "input_params": {
            "pattern": "SELECT|INSERT|UPDATE|DELETE|execute|cursor|sql_query|f\".*SELECT|f\".*INSERT",
            "glob": "*.py",
            "max_matches": 30
          }
        },
        "execution_stats": {
          "call_count": 1,
          "success_count": 1,
          "error_count": 0,
          "total_time": 0.0040400028228759766,
          "average_time": 0.0040400028228759766,
          "success_rate": 1.0
        }
      },
      "read_file": {
        "tool_info": {
          "tool_use_id": "0Z02rM9sHVgXkUePFKF05Q85nDzrN2ry",
          "name": "read_file",
          "input_params": {
            "path": "app.py"
          }
        },
        "execution_stats": {
          "call_count": 1,
          "success_count": 1,
          "error_count": 0,
          "total_time": 0.003228902816772461,
          "average_time": 0.003228902816772461,
          "success_rate": 1.0
        }
      },
      "submit_none": {
        "tool_info": {
          "tool_use_id": "EoclVwEwSSAaT6LedsEyIs51J4hlRuoa",
          "name": "submit_none",
          "input_params": {
            "reason": "SPIKE scan of app.py \u2014 grep for SQL patterns found one clear case: `search_users()` at line 11 uses f-string interpolation (`f\"SELECT * FROM users WHERE name = '{q}'\"`) directly into cursor.execute(), which is a textbook SQL injection vulnerability. The file header comments indicate this is an intentional fixture (\"deliberately vulnerable \u2014 do not deploy\", \"Tiny intentional SQLi fixture for harness end-to-end tests later\"). Residual risk: (1) only one file was scanned; other files may contain similar unparameterized query patterns; (2) if this fixture were accidentally deployed or copied into production code, the vulnerability would be exploitable with zero additional changes. No further deep analysis performed per SPIKE scope."
          }
        },
        "execution_stats": {
          "call_count": 1,
          "success_count": 1,
          "error_count": 0,
          "total_time": 0.009382963180541992,
          "average_time": 0.009382963180541992,
          "success_rate": 1.0
        }
      }
    },
    "traces": "<3 traces omitted>",
    "accumulated_usage": {
      "inputTokens": 2626,
      "outputTokens": 815,
      "totalTokens": 3441
    },
    "accumulated_metrics": {
      "latencyMs": 0
    },
    "agent_invocations": [
      {
        "usage": {
          "inputTokens": 2626,
          "outputTokens": 815,
          "totalTokens": 3441
        },
        "cycles": [
          {
            "event_loop_cycle_id": "cabb0f0c-2c7c-4630-bb14-8e93eb5e70b5",
            "usage": {
              "inputTokens": 655,
              "outputTokens": 144,
              "totalTokens": 799
            }
          },
          {
            "event_loop_cycle_id": "08fb64b0-bfd6-44dc-abab-e87a4a1a1399",
            "usage": {
              "inputTokens": 870,
              "outputTokens": 56,
              "totalTokens": 926
            }
          },
          {
            "event_loop_cycle_id": "e53b6ac0-60b8-4527-86a2-6c9d9ec6cc31",
            "usage": {
              "inputTokens": 1101,
              "outputTokens": 615,
              "totalTokens": 1716
            }
          }
        ]
      }
    ]
  },
  "base_url": "http://192.168.32.10:1234/v1",
  "model_id": "ornith-1.0-35b"
}
```

</details>

### `live_transcript` — PASS

openaiish_msgs=7 tool_calls=3

<details><summary>evidence</summary>

```json
{
  "sample": [
    {
      "role": "user",
      "content": "Target is a small Python app. List/find SQL-related code with grep, read at most one file snippet, then call submit_none explaining residual risk."
    },
    {
      "role": "assistant",
      "content": "",
      "tool_calls": [
        {
          "id": "VQmJlpu6NJHWGA6dGzak2bBxKbMiK3Ur",
          "type": "function",
          "function": {
            "name": "grep",
            "arguments": "{\"pattern\": \"SELECT|INSERT|UPDATE|DELETE|execute|cursor|sql_query|f\\\".*SELECT|f\\\".*INSERT\", \"glob\": \"*.py\", \"max_matches\": 30}"
          }
        }
      ]
    },
    {
      "role": "tool",
      "tool_call_id": "VQmJlpu6NJHWGA6dGzak2bBxKbMiK3Ur",
      "name": "grep",
      "content": "{\"ok\": true, \"matches\": [{\"path\": \"app.py\", \"line\": 9, \"text\": \"def search_users(db_cursor, q: str):\"}, {\"path\": \"app.py\", \"line\": 11, \"text\": \"    sql = f\\\"SELECT * FROM users WHERE name = '{q}'\\\"\"}, {\"path\": \"app.py\", \"line\": 12, \"text\": \"    return db_cursor.execute(sql)\"}], \"truncated\": false, \"files_scanned\": 1, \"scoped\": false, \"glob\": \"*.py\"}",
      "status": "success"
    },
    {
      "role": "assistant",
      "content": "",
      "tool_calls": [
        {
          "id": "0Z02rM9sHVgXkUePFKF05Q85nDzrN2ry",
          "type": "function",
          "function": {
            "name": "read_file",
            "arguments": "{\"path\": \"app.py\"}"
          }
        }
      ]
    },
    {
      "role": "tool",
      "tool_call_id": "0Z02rM9sHVgXkUePFKF05Q85nDzrN2ry",
      "name": "read_file",
      "content": "{\"ok\": true, \"path\": \"app.py\", \"content\": \"\\\"\\\"\\\"\\nTiny intentional SQLi fixture for harness end-to-end tests later.\\n\\nWARNING: deliberately vulnerable \u2014 do not deploy.\\n\\\"\\\"\\\"\\n\\n# TODO: expand into minimal Flask/FastAPI app with known SQLi for integration tests\\n\\ndef search_users(db_cursor, q: str):\\n    # INTENTIONALLY VULNERABLE \u2014 fixture only\\n    sql = f\\\"SELECT * FROM users WHERE name = '{q}'\\\"\\n    return db_cursor.execute(sql)\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\\n\\n# mutated\", \"total_lines\": 40, \"truncated\": false}",
      "status": "success"
    },
    {
      "role": "assistant",
      "content": "",
      "tool_calls": [
        {
          "id": "EoclVwEwSSAaT6LedsEyIs51J4hlRuoa",
          "type": "function",
          "function": {
            "name": "submit_none",
            "arguments": "{\"reason\": \"SPIKE scan of app.py \\u2014 grep for SQL patterns found one clear case: `search_users()` at line 11 uses f-string interpolation (`f\\\"SELECT * FROM users WHERE name = '{q}'\\\"`) directly into cursor.execute(), which is a textbook SQL injection vulnerability. The file header comments indicate this is an intentional fixture (\\\"deliberately vulnerable \\u2014 do not deploy\\\", \\\"Tiny intentional SQLi fixture for harness end-to-end tests later\\\"). Residual risk: (1) only one file was scanned; other files may contain similar unparameterized query patterns; (2) if this fixture were accidentally deployed or copied into production code, the vulnerability would be exploitable with zero additional changes. No further deep analysis performed per SPIKE scope.\"}"
          }
        }
      ]
    }
  ]
}
```

</details>

## Live environment used

| Item | Value |
|------|--------|
| Endpoint | `http://192.168.32.10:1234/v1` |
| Model | `ornith-1.0-35b` |
| Elapsed | ~29 s for grep → read_file → submit_none |
| Stop | `cancelled` after successful submit (expected domain terminal) |

**Note:** Live run printed repeated warnings:
`reasoningContent is not supported in multi-turn conversations with the Chat Completions API.`
Ornith is a reasoning-class model; Strands OpenAI provider may strip or mishandle reasoning blocks on later turns. Phase 1 should either strip `reasoning_content` from history, use Responses API if available, or accept degraded multi-turn on reasoning models.

## Findings for Phase 1 design

1. **Submit stop works via `agent.cancel()` in `AfterToolCallEvent`** when `submit_none` returns `ok: true`. `stop_reason` becomes `cancelled` (domain-success cancel — map to successful terminal in adapter, not failure).
2. **Strands message shape ≠ VulnForge OpenAI-ish transcripts.** Tool results are `user` messages with `toolResult` blocks. A normalizer (as in this spike) is required for tool-gaps / usage.
3. **Scripted custom `Model` works** for offline tests — viable FakeLLM path, but must implement async `stream()` StreamEvents (not `chat()`).
4. **Thin wrappers** can call existing `vulnforge.tools.run_tool(ctx, …)` — do not rewrite tool bodies.
5. **Dependency weight:** `strands-agents[openai]` pulls boto3, mcp, otel, openai, etc. Keep as **optional** extra, not a hard runtime dep for default installs.
6. **Do not** register `strands-agents-tools` shell tools on `code_static`.
7. **Hook registration:** pass event type explicitly (`hooks.add_callback(AfterToolCallEvent, cb)`); nested annotations break type inference.
8. **Reasoning models (Ornith):** multi-turn Chat Completions + reasoningContent needs explicit handling in the adapter.

## Effort estimate (Phase 1)

| Item | Estimate |
|------|----------|
| `AgentRuntime` protocol + legacy wrapper | 0.5–1 d |
| Strands runtime + tool bridge + submit-stop hook | 1–2 d |
| Transcript/usage normalizer + tool-gaps smoke | 0.5–1 d |
| Config flag + settings UI note | 0.5 d |
| Tests (scripted model + 1 live optional) | 1 d |
| **Total** | **~4–6 engineer-days** |

## How to re-run

```powershell
cd VulnForge
.\.venv\Scripts\Activate.ps1
pip install 'strands-agents[openai]'   # if needed
python scripts/strands_spike.py --base-url http://192.168.32.10:1234/v1 --model ornith-1.0-35b
```

