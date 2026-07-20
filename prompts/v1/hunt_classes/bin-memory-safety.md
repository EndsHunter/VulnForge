# Binary memory safety (bin-memory-safety)

Hunt **memory corruption** patterns in a PE via Ghidra decompilation and xrefs.

## Focus

- Unbounded or weakly bounded copies (`strcpy`, `strcat`, `sprintf`, `gets`, raw `memcpy` with attacker length)
- Integer wrap feeding allocation/copy sizes
- Format-string sinks (`printf`-family with non-literal format)
- Stack buffers adjacent to dangerous calls without length checks
- Off-by-one / wrong size arguments to CRT or Win32 converters

## Method

1. Start from `path_hints` / seed sinks (**prefer caller addresses or import symbol names**, not only IAT/stub VAs).
2. Resolve sinks with **`ghidra_import_callers`** (`symbol` e.g. `strcpy` / `memcpy`) **or** `ghidra_imports` with `filter` then xrefs.
3. **Decompile CALLER functions** (`ghidra_decompile` on caller name/entry) — never treat the import stub or IAT data slot as the vulnerability site alone.
4. Trace attacker-controlled data (network, file, argv, registry) toward the sink when possible.
5. Write evidence (decompilation excerpts + xref notes) via `write_evidence`.
6. `submit_candidate` with citations including `path` (binary name), `address`, `symbol`.
   Set `sink_address` and `sink_symbol` when known.
7. If a deeper caller chain is needed, `request_hunt` profile `bin-follow-xref` with **function** address path_hints — then still finish this task.
8. If nothing solid after real search, `submit_none` with concrete checked functions.

## Anti-patterns

- Do **not** decompile IAT/data addresses or EXTERNAL import thunks as if they were application code.
- Do **not** use wrong xref direction (for sinks: find refs **to** the import / callers of the API).
- Do **not** file “binary imports memcpy” without a caller and argument-control story.

## Honesty

Static RE is **not** exploit proof. State residual uncertainty. Do not claim confirmed without dynamic proof (out of scope here).
