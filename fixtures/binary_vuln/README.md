# binary_vuln — synthetic known-vuln PE fixture

## Purpose

Research fixture for VulnForge **`binary_re`** pipeline tests. It is a tiny
x64 PE console app with an **intentional unbounded `strcpy` sink** so static
reverse-engineering (Ghidra MCP) can ground-truth symbols and dangerous APIs.

- **Not malware.** No packing, no C2, no evasion, no obfuscation.
- **Do not treat as a weaponized exploit.** The bug is educational only.
- Finding candidates from automation still require **human review**; this
  fixture only exercises recon/hunt/validate plumbing.

## Layout

```
fixtures/binary_vuln/
  src/vuln_copy.c      # intentional strcpy-style overflow sink
  vuln_copy.exe        # prebuilt x64 PE (console), when present
  README.md            # this file
```

Optional rebuild: `scripts/build_binary_vuln_fixture.ps1` (repo root).

## Expected ground truth (static RE)

| Item | Expected |
|------|----------|
| Symbol / function | `vulnerable_copy` (PE export on the MSVC build script output) |
| Sink | `strcpy` import (`api-ms-win-crt-string-l1-1-0.dll` on MSVC `/MD`) |
| Call path | `main` → `vulnerable_copy` → `strcpy` with small stack buffer (~32 bytes) |
| Input | `argv[1]` when `argc > 1` |

The shipped MSVC build uses `/MD /Od /Oi- /Ob0` plus `/EXPORT:vulnerable_copy`
so both the **export name** and the **`strcpy` IAT entry** are easy for Ghidra
to recover. Even if a stripped rebuild drops the export, the IAT/`strcpy`
use and small stack buffer remain useful for `bin-memory-safety` /
`bin-dangerous-apis` hunts.

## Rebuild

From the VulnForge repo root:

```powershell
powershell -File scripts\build_binary_vuln_fixture.ps1
```

Manual rebuild (MSVC x64 Developer PowerShell / after `vcvars64.bat`):

```powershell
cl /nologo /MD /Od /Oi- /Ob0 /W3 /D_CRT_SECURE_NO_WARNINGS /TC fixtures\binary_vuln\src\vuln_copy.c ^
  /Fe:fixtures\binary_vuln\vuln_copy.exe /link /DEBUG:NONE /EXPORT:vulnerable_copy
```

MinGW alternative:

```powershell
gcc -O0 -fno-builtin-strcpy -o fixtures/binary_vuln/vuln_copy.exe fixtures/binary_vuln/src/vuln_copy.c
# or cross: x86_64-w64-mingw32-gcc -O0 -fno-builtin-strcpy -o fixtures/binary_vuln/vuln_copy.exe fixtures/binary_vuln/src/vuln_copy.c
```

Prefer a small **x64 PE console** binary. Ship source always; ship
`vuln_copy.exe` when a toolchain is available.

## Init as binary_re target

```powershell
vf init --target fixtures/binary_vuln/vuln_copy.exe --profile binary_re --i-am-authorized-for-binary-re
python scripts/ralph.py --run-dir runs\<target_id>\run-001 --task-timeout 900 --max-tasks 50
```

Requires Ghidra MCP setup as described in `AGENTS.md` (portable
`./ghidra` + `ghidra-mcp`, or config overrides).

## Honesty

- `needs_human` means mechanical gates passed — **not** exploit proof.
- `confirmed` is only set by **human** review in the dashboard Report.
- Agents must not execute this binary as proof of exploitability; the
  fixture exists for **static** RE and pipeline integration tests.
- Do not run the built binary against untrusted input outside a controlled
  lab. Compiling the fixture is fine; weaponizing it is out of scope.
