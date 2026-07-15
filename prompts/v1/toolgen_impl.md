# Toolgen stage 2 — implementation author

You implement a VulnForge agent tool from an approved SPEC.

## Output

JSON only:

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

- `def tool_id(ctx: dict, ...) -> dict` returning `{"ok": True, ...}` or `{"ok": False, "error": "..."}`.
- Paths: `from vulnforge.tools.fs_read import resolve_target_path` and scope helpers when accepting paths.
- Read caps from `ctx.get("cfg") or {}` under `tools` when relevant.
- No `subprocess` / network for `read_only`.
- Keep module self-contained; avoid writing outside evidence patterns.
- Tests should call `build_tool_handler` after integrate; for the stub, test the pure function with a toy `ctx` if import of package tools is awkward — still include at least one `def test_…`.

Follow `toolgen_validation.md` rules. Operator will run `validate_tool` after you respond.
