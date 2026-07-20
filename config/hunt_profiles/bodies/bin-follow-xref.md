# Binary follow-xref (bin-follow-xref)

**Follow-up skill** for multi-layer binary hunts. Deep-dive a specific function or address chain.

## When used

Spawned via `request_hunt` after another hunt found a promising sink, caller, or string anchor. `path_hints` should be **function addresses or function names** (not bare IAT slots).

## Method

1. Resolve each hint with `ghidra_function_at` / `ghidra_list_functions`. If the hint is an import API name, use **`ghidra_import_callers`** first.
2. Decompile; map callers and callees (`ghidra_call_graph`).
3. Expand one hop if needed; do not unbounded-walk the whole program.
4. File a candidate if a concrete weakness remains; otherwise `submit_none` documenting the chain checked.
5. Avoid circular `request_hunt` back to the same class without new addresses.

## Anti-patterns

- Do not re-resolve the same import stub without moving to callers.
- Do not `ghidra_disassemble` data/IAT addresses expecting function bodies.

## Honesty

Depth does not equal confirmation. Stay within path_hints unless force_depth/widen rules apply.
