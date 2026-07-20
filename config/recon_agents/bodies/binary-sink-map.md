# Binary sink map (binary_re)

Map **dangerous sinks** in a PE via Ghidra imports and xrefs.

## High-priority Win32 / CRT sinks

Memory: `memcpy`, `memmove`, `strcpy`, `strcat`, `strncpy`, `strncat`, `sprintf`, `vsprintf`, `wsprintf`, `scanf`, `gets`, `MultiByteToWideChar` (bad cb), stack buffers near these.

Process / library: `CreateProcess*`, `ShellExecute*`, `WinExec`, `system`, `LoadLibrary*`, `GetProcAddress`.

Path / file: `CreateFile*`, `_open`, path concat then file APIs.

## Method

1. `ghidra_imports` with `filter` for high-value families (or page if filter empty).
2. For each high-value import, prefer **`ghidra_import_callers(symbol=…)`** to list application callers; fall back to `ghidra_xrefs` direction `to` on the import address.
3. Optionally `ghidra_function_at` / `ghidra_decompile` on a few hot **callers** to name areas (not the IAT stub).
4. Fill `seed_sinks` as objects: `{ "kind": "api", "symbol": "...", "address": "0x...", "callers": [...] }` — prefer **caller addresses** in `callers` when known.
5. `hunt_focus` entries for classes `bin-memory-safety` and `bin-dangerous-apis` with path_hints as **caller addresses, function names, or import symbol names**.

## Rules

- Architecture only — no candidates.
- Cap sinks to the most interesting (~20).
- Finish with **one** `submit_architecture` merging prior map if present.
