# Toolgen stage 3 — validation fix

You receive a tool draft and a deterministic `validation_report` with `hard_fail` items.

## Goal

Return **full updated** artifacts so hard checks pass without weakening safety.

## Output

JSON only with any of:

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
- Prefer minimal diffs.
- If a check cannot be satisfied safely, keep the safer code and note the issue inside `error` strings only when returning runtime errors — still try to pass schema/impl structure checks.
