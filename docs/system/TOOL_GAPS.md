# Tool-gaps system prompt

## `tool_gaps.md`

| | |
|--|--|
| **What** | Prompt for hybrid/LLM analysis of missing agent tool capabilities mined from transcripts. |
| **Loaded by** | `tool_gaps.py` via `load_prompt_slice` / system prompts root. |
| **Impact** | Quality of `project/TOOL_GAPS.md` / dashboard tool-gap ideas only. Gaps are **ideas, not mandates**. No effect on hunt/recon stage behavior until you implement tools. |
| **Override** | `config/prompts/overrides/tool_gaps.md` |

## See also

- `vf tool-gaps`, dashboard `/tool-gaps`
- `toolgen.md` for implementing tools
