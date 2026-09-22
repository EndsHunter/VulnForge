# Spike: context-cache hit rate and better model use

**Date:** 2026-09-22
**Issue:** [#69](https://github.com/EndsHunter/VulnForge/issues/69)
**Status:** Instrumentation landed. Anthropic system-prompt pin is **default off**. Local LM Studio / Ornith does not report cache fields.

Operators read cache hit and waste from the run usage files. This spike does not add a Mission or Report line.

## What providers expose

| Provider | Where | Hit (read) | Write (create) | In `prompt_tokens`? |
|----------|--------|------------|----------------|---------------------|
| OpenAI Chat Completions | `usage.prompt_tokens_details.cached_tokens` | yes | no | Yes. Cached tokens are a subset of `prompt_tokens`. |
| OpenAI Responses | `usage.input_tokens_details.cached_tokens` | yes | no | Yes, subset of `input_tokens`. |
| Anthropic Messages | `usage.cache_read_input_tokens`, `usage.cache_creation_input_tokens` | yes | yes | No. `input_tokens` is only the uncached remainder. |
| Local OpenAI-compatible (LM Studio, Ornith default) | usually omitted | — | — | Server does not implement prompt cache. |

VulnForge normalizes those into:

| Field | Meaning |
|-------|---------|
| `cache_read_tokens` | Tokens served from cache (OpenAI `cached_tokens` or Anthropic `cache_read_input_tokens`). |
| `cache_creation_tokens` | Tokens written into a cache (Anthropic `cache_creation_input_tokens`). OpenAI chat usage has no write counter; this stays 0. |
| `cache_source` | `provider` if any cache key was present (including an explicit 0), `none` if the body omitted them, `mixed` if a rollup combines both. |
| `cache_hit_rate` | `cache_read_tokens / basis` when `cache_source` is not `none` and `basis > 0`. Otherwise `null`. |

**Basis.** OpenAI: `basis = prompt_tokens` (cached tokens already sit inside it). Anthropic: `input_tokens` excludes cache read and cache create, so when `cache_read + cache_creation > prompt_tokens` the basis is `prompt_tokens + cache_read_tokens + cache_creation_tokens`. A reported zero is `0.0`. An omitted field is `null`, not 0%, so a local server does not look like a measured miss.

Strands' OpenAI and Anthropic adapters forward non-zero cache counts as `cacheReadInputTokens` / `cacheWriteInputTokens` on `accumulated_usage`. They drop a zero. A Strands summary with no cache key is `cache_source=none` ("not reported"), not a measured zero. The direct HTTP parser (`parse_usage_from_body`) keeps an explicit `0` as `cache_source=provider`.

Odd or missing shapes do not raise. No `usage` object → `source=none`, cache counts 0, `cache_source=none`, `cache_hit_rate=null`.

## How operators read it

Per run:

```text
runs/<target_id>/<run_id>/llm_usage.jsonl
runs/<target_id>/<run_id>/llm_usage_summary.json
```

Summary top level, and each `by_kind` / `by_model` / `by_task` row:

```json
{
  "prompt_tokens": 2000,
  "completion_tokens": 20,
  "total_tokens": 2020,
  "cache_read_tokens": 1500,
  "cache_creation_tokens": 0,
  "cache_source": "provider",
  "cache_hit_rate": 0.75
}
```

`llm_usage.jsonl` has the same fields on each call, plus `kind`, `model_id`, and `task_id`.

`cache_source=none` with zeros is the local-server case: the endpoint never said whether anything was cached. `cache_source=mixed` means some calls reported cache fields and some did not. The rate then counts omitted calls as zero reads, so it is a lower bound, not a full measurement.

The run-card payload (`llm_usage` on the home/run card JSON) copies the same totals. Mission and Report do not render them. No UI in this spike.

Task result dicts from `usage_fields_for_result` also carry `cache_read_tokens`, `cache_creation_tokens`, `cache_source`, and `cache_hit_rate`.

## Why VulnForge misses cache today

Hypotheses, from how packets are built (`vulnforge/packet.py`):

1. **Prompt churn.** Hunt `user` text is rebuilt every task: area slice of architecture, seed sinks, known findings, codemap slice, operator notes, continuation handoff. Only a byte-stable prefix can hit. The user body will not.
2. **Unpinned system prefix.** Hunt `system` is already stable (`PRINCIPLES.md` only). Recon `system` is preamble + a fixed stage blurb + the agent id. Anthropic does not cache that prefix unless the request sets `cache_control`. Default traffic never did.
3. **Stage packet rebuild.** Recon, hunt, disprove, and PoC each use a different system text. Tool allowlists change the tool schema between hunts. A cache breakpoint on tools would miss whenever the allowlist changes. Volatile inventory and codemap JSON live in the user message, after the system prefix, which is the right side of the breakpoint — but nothing sets the breakpoint.
4. **Provider silence.** Default config is LM Studio chat completions (`api_mode: chat_completions`, model Ornith). Those servers omit `prompt_tokens_details.cached_tokens`. OpenAI's automatic cache also wants a long identical prefix (on the order of 1024 tokens). `PRINCIPLES.md` may be shorter than that even against real OpenAI. No timestamp is prepended to the system prompt today; deleting a header would not create hits.

## Improvement in this spike

`llm.prompt_cache` in `config/default.yaml`, **default `false`**.

When it is `true` **and** `api_mode` is `messages`:

- Direct `LLMClient` (`validate_llm`, toolgen, some operator-chat calls) sends `system` as one text block with `cache_control: {type: ephemeral}`.
- The Strands hunt/recon loop passes `CacheConfig(strategy="anthropic", system_prompt_ttl=True, tools_ttl=False)` into `AnthropicModel`. That is the same system-prompt breakpoint. Tools stay uncached so allowlist churn does not spend a second breakpoint.

`chat_completions` and `responses` request bodies are unchanged even if the flag is on. Turning it on cannot alter Ornith calls.

Default off is deliberate. A local or proxy Messages endpoint that rejects `cache_control` must not break on upgrade. Operators who point `api_mode: messages` at Anthropic can set `prompt_cache: true` without a code change.

No packet rewrite. The stable prefix is already the system string. The missing piece on Anthropic is the breakpoint, not a volatile header.

## Blocked on the default provider

**Local LM Studio / Ornith (`api_mode: chat_completions`) omits cache usage fields.** This spike cannot show a non-null hit rate for that stack. After a run, `llm_usage_summary.json` should show `cache_source: "none"`, `cache_read_tokens: 0`, `cache_creation_tokens: 0`, `cache_hit_rate: null`. That is the signal, not a parser failure.

The Anthropic pin does nothing for that endpoint. It is ready for `api_mode: messages` and is not enabled in `config/default.yaml`.

Strands' OpenAI adapter will fill `cache_read_tokens` only when the server actually returns a non-zero `cached_tokens`. Until then the summary stays at `cache_source=none`.

## Follow-up PR split

### PR2 — turn the pin on for Anthropic, after one live smoke

- Run one `api_mode: messages` hunt with `prompt_cache: true` against real Anthropic (or a proxy that honors `cache_control`).
- Confirm the second call in a tool loop reports `cache_read_input_tokens` and the summary `cache_hit_rate` moves.
- Only then consider defaulting `prompt_cache` to true when `api_mode` is `messages`. Keep it off for `chat_completions`.

### PR3 — optional Mission one-liner

If operators want the rate without opening the JSON file: one muted line on the run card or Mission header (`cache 75%` or `cache n/a`). That is UI. It needs before/after screenshots. Do not build it until PR2 shows a real number worth displaying.

### Not worth a PR yet

- Tool-schema `cache_control`. Allowlists change per hunt class. Revisit only if a stage's tool list is stable across the whole run.
- Rewriting packet headers. System text is already the stable prefix.

## Out of scope

- Multi-host model load/unload.
- Mixture-of-agents hunt (#68 / follow-up wiring).
- Auto-confirm. Cache accounting does not touch finding state.

## Proof in this PR

| Artifact | Role |
|----------|------|
| `docs/harness/spikes/2026-09-22-context-cache.md` | This note |
| `vulnforge/llm.py` | `TokenUsage` cache fields, `parse_usage_from_body`, `prompt_cache` → Anthropic system block |
| `vulnforge/usage.py` | jsonl + summary rollup, `cache_hit_rate` recomputed on totals |
| `vulnforge/agent_runtime/strands_loop.py` | Strands `accumulated_usage` cache counters; `CacheConfig` when the flag is on |
| `config/default.yaml` | `llm.prompt_cache: false` |
| `tests/test_token_usage.py` | OpenAI body, Anthropic body, missing fields, explicit zero, rollup, flag off/on |

Jonathan owns merge. Ops may merge when the review bar passes.
