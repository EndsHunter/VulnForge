# Toolgen stage 2 — implementation author

You implement a VulnForge agent tool from an approved SPEC.

## Output format (strict)

- Reply with **one JSON object only** (no prose before/after).
- Keep `impl_py` complete but **small** — one module, one primary function.
- Function name and schema `name` **must equal the draft tool id**.

```json
{
  "impl_py": "full python module source",
  "schema": {
    "tools": [
      {
        "name": "tool_id",
        "description": "…",
        "stages": ["hunt"],
        "parameters": {
          "type": "object",
          "properties": {},
          "required": []
        }
      }
    ]
  },
  "handler_snippet": "# suggested dispatch branch (not applied automatically)\n",
  "wireup": {
    "impl_module": "vulnforge.tools.tool_id",
    "impl_path": "vulnforge/tools/tool_id.py",
    "handler_branches": ["tool_id"],
    "aliases": [],
    "allowed_tools_add": ["tool_id"],
    "packet_stages": ["hunt"],
    "config_keys": [],
    "protocol_blurb": "tool_id — …",
    "test_file": "tests/test_tool_tool_id.py"
  },
  "test_stub": "pytest module source"
}
```

## Implementation requirements

- `impl_py` is a **complete** module: `from __future__ import annotations`, imports, then
  `def tool_id(ctx: dict, ...) -> dict` returning `{"ok": True, ...}` or `{"ok": False, "error": "..."}`.
- Paths: `from vulnforge.tools.fs_read import resolve_target_path` (and scope helpers) when accepting paths.
- Read caps from `ctx.get("cfg") or {}` under `tools` when relevant.
- No `subprocess` / network / `eval` / `exec` for `read_only`.
- Keep module self-contained; never write under the target tree.
- Tests should call `build_tool_handler` after integrate; for the stub, test the pure function with a toy `ctx` — include at least one `def test_…`.

Follow `toolgen_validation.md` rules. Operator will run `validate_tool` after you respond.
