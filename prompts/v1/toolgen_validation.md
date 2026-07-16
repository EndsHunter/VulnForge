# Tool generation — validation rules (AI + humans)

These rules are enforced by `scripts/validate_tool.py` / `vulnforge.toolgen.validate`.
Your artifacts must pass **hard** checks before integrate.

## Contract

1. Every tool function takes `ctx: dict` first, then kwargs; returns a **dict** with `"ok": true|false`.
2. On failure return `{"ok": false, "error": "..."}` — never raise uncaught into the model.
3. Target tree is **read-only**. Never write/delete under `ctx["target_root"]`.
4. Evidence writes only via established evidence helpers patterns (not arbitrary target paths).
5. Path arguments must go through `resolve_target_path` and prefer `maybe_soft_jail` / `attach_scope_warning`.
6. **Forbidden** on `risk_class=read_only` or `evidence_write` and on `code_static` profile:
   - `subprocess`, `os.system`, `socket`, `requests`, `httpx`, unrestricted network
   - `eval` / `exec` / dynamic shell
7. `risk_class=exec` is only for future `code_exec` profile — do not add to `code_static` allowlist.
8. Prefer **extending** `grep` / `file_inventory` / `read_file` when the gap is only a filter or arg.
9. Primary function name **equals draft id**; schema tool `name` matches.

## Schema

- OpenAI function shape: `name`, `description`, `parameters: {type: object, properties, required}`.
- Required schema properties must appear in the implementation (`args.get("…")` or signature).
- Tool `name` must match draft id style: `[a-z][a-z0-9_]{0,47}`.

## Size / local models

- Keep `impl_py` compact (small single-purpose tools). Large modules risk truncation on
  reasoning models that spend tokens on chain-of-thought before JSON.
- Stay under validation size caps (hard `size_limits` check).

## Wire-up (operator integrate — you produce snippets only)

Do **not** import or install the draft yourself. Produce:

- `impl.py` — module body
- `schema.json` — `{"tools":[…]}`
- `handler_snippet.py` — suggested dispatch branch (documentation)
- `wireup.json` — `impl_module`, `impl_path`, `handler_branches`, `allowed_tools_add`, `packet_stages`, `test_file`
- `test_stub.py` — pytest using `build_tool_handler`

## Self-repair

When you receive `validation_report.json` with `hard_fail`, fix the listed check ids only.
Do not weaken safety to pass checks. Do not remove path jails.
