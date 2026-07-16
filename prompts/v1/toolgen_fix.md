# Toolgen stage 3 — validation fix

You receive a tool draft and a deterministic `validation_report` with `hard_fail` items.

## Goal

Return **full updated** artifacts so hard checks pass without weakening safety.

## Output format (strict)

- **One JSON object only** as the assistant content (no prose before/after).
- Include full `impl_py` / `schema` when those files failed checks (not diffs).

```json
{
  "impl_py": "…",
  "schema": {"tools": […]},
  "handler_snippet": "…",
  "wireup": {…},
  "test_stub": "…"
}
```

## Rules

- Fix only what the report requires.
- Do not add forbidden imports to silence checks.
- Do not remove path jails or `ok` keys.
- Prefer minimal diffs while still returning complete field values.
- Function name and schema `name` must stay equal to the draft id.
- Keep implementations small so local reasoning models finish within max_tokens.
- If a check cannot be satisfied safely, keep the safer code and still try to pass schema/impl structure checks.
