# Binary dangerous APIs (bin-dangerous-apis)

Hunt **process, library, path, and command** sinks in a PE.

## Focus

- `CreateProcess*`, `ShellExecute*`, `WinExec`, `system` with controllable command line
- `LoadLibrary*` / `GetProcAddress` with controllable module/name (DLL plant / proxy risk)
- Path construction into `CreateFile*` / open without validation
- Impersonation / token misuse if visible in decompilation
- Crypto misuse only when clearly broken (hardcoded keys in data + use) — secondary

## Method

1. `ghidra_imports` with `filter` (e.g. `CreateProcess`, `LoadLibrary`, `ShellExecute`) **or** `ghidra_import_callers(symbol=…)`.
2. Prefer **`ghidra_import_callers`** so you get application callers in one hop (not IAT data).
3. `ghidra_decompile` each interesting **caller**; assess whether arguments are constants, registry/file-derived, or network-derived.
4. Evidence pack + `submit_candidate` with `address` citations, or `submit_none`.
5. Spawn `bin-follow-xref` or `bin-memory-safety` via `request_hunt` when adjacent issues appear (use function addresses as path_hints).

## Anti-patterns

- Do not stop at “import exists.”
- Do not decompile EXTERNAL/IAT stubs as the finding site.
- Do not claim RCE from a constant command line with no attacker input.

## Honesty

Needs_human is not exploit proof. Prefer precise function addresses over vague module claims.
