---
name: ai-llm
description: >-
  Hunts untrusted text reaching models/agents that drive privileged tools or
  sinks — confused-deputy paths (OWASP LLM / agentic risks). Use when tracing
  chat/RAG, tool-calling agents, MCP, prompt assembly from uploads/email/issues,
  model output to SQL/shell/HTTP/email/admin APIs, or coding-agent integrations.
  Prefer code-level missing re-authz over “LLM can be jailbroken.” Dual-file
  ban: same path+symbol never under both ai-llm and injection.
---

# Hunt class: ai-llm

## Principles

- **Prefer evidence over pre-training.** Cite tools, prompt assembly, and handler sites you read.
- **Be certain.** If tool authz is unclear, read the handler body before filing.
- **Provide evidence.** Taint source → assembly/tool → sink; boundary crossed.
- **Correctness over completeness.** One privileged tool path beats jailbreak party tricks.
- Honest `submit_none` when tools are tightly scoped and outputs encoded.

## When to use

- Chat/RAG, tool-calling agents, MCP, prompt assembly from untrusted input
- Acting on model output (SQL, shell, HTTP-internal, email, admin APIs)
- Coding-agent integrations; indirect injection via docs/uploads/email/issues/tool responses
- Excessive agency (service identity without per-user re-check); cross-tenant bleed

## When not to use / Scope

- Plain SQL/exec with **no** LLM on the path → `injection`
- Jailbreak party tricks with no tool/secret/cross-user effect
- Guardrail text treated as a security control; user summarizes **their own** doc only
- Related skills: `injection` for non-LLM sinks; `access-control` for pure authz; `client-side` for model HTML → XSS without agent tools; `feature-abuse` for non-LLM SSRF

## Decision tree

```
1. Map: tool identity, context sources, who can write each, where output/tools go
2. Start from most dangerous tools (exec, SQL, HTTP-internal, email, admin APIs)
3. Can untrusted text reach tool args or privileged context?
4. Authz INSIDE tool handlers — not only “user logged in to chat”
5. Retrieval filters at QUERY construction, not after
6. Tightly scoped tools + encoded outputs → submit_none
```

## Rules quick reference

| Rule | Summary |
|------|---------|
| Model is deputy | Untrusted text can steer tool args and context |
| Code gates | Prompt wording is not a security control |
| Tool re-authz | Per-user ACL inside handlers, not service SA alone |
| Indirect inject | RAG/uploads/email/issues fire in another session |
| Dual-file ban | Same path+sink never `ai-llm` + `injection` |
| Boundary | Name victim context, higher capability, secret, or server sink |
| Retrieval filter | Tenant/owner filters at query time |
| Output sinks | Model HTML/markdown → XSS is client-side if no tools |
| Cost loops | Denial-of-wallet needs unbounded path in code |
| Impact | Privileged action, data exfil, cross-tenant, not “said something bad” |

## Focus

- Indirect injection firing in another session
- Tool-argument injection → SQL/shell/path/HTTP without handler validation
- Excessive agency; delimiter forgery; context extraction of real secrets
- Insecure model HTML → XSS; cross-tenant bleed; MCP/sub-agent poisoning
- Coding-agent PR steering; denial-of-wallet loops with code path

## Hunt workflow

1. **Inventory** — tools, identities, context sources, RAG writers, MCP bindings
2. **Trace** — untrusted writers into prompts and tool results; dangerous tools first
3. **Prove** — missing re-authz/validation at code level; boundary crossed
4. **Evidence** — taint source → assembly/tool → sink; `write_evidence`
5. **Submit or none** — `weakness_class: ai-llm`, or honest `submit_none`

## Stack cues

```
openai|anthropic|chat\.completions|ChatCompletion|langchain|llama|ollama|litellm
system_prompt|system.*message|messages\.append|prompt\s*=
tool_call|function_call|tools\s*=|bind_tools|MCP|agent
RAG|embeddings|vector|similarity|pinecone|chroma|faiss|retrieve
dangerouslySetInnerHTML|markdown|marked\(|innerHTML
subprocess|execute|run_sql|http_request|browser\.|send_email
```

## Required evidence

- Taint source → assembly/tool → sink; boundary crossed
- Code-level missing re-authz or validation (not prompt wording)

## False positives

- User summarizes **their own** doc only
- Hallucination/misinfo without a security boundary
- Model cost theories without unbounded path in code
- Including user content in prompts alone

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| “LLM can be jailbroken” | No tool/secret/cross-user impact |
| System-prompt as control | Guardrails are not mitigations |
| Dual-submit with injection | Same sink, two classes |
| Party tricks | No privilege boundary crossed |
| Ignoring tool handlers | Prompt-only analysis misses re-authz |

## Submit checklist

- `write_evidence` first: taint source → assembly/tool → sink; boundary crossed
- `weakness_class: ai-llm`
- **Good:** *“Uploaded doc injects tool call; `tools.py:60` payments tool uses service SA with no beneficiary ACL.”*
- **Bad:** *“LLM can be jailbroken.”*
- Or honest `submit_none`
