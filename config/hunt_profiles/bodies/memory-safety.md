---
name: memory-safety
description: >-
  Hunts spatial/temporal memory bugs and privileged native-interface flaws on
  attacker-controlled input in C/C++/ObjC, Ada (Unchecked_Conversion / Interfaces.C),
  Fortran, assembly, CUDA, Rust unsafe, parsers, kernels, FFI, and JIT. Use when
  tracing memcpy/strcpy/sprintf, length fields from packets/files, free/use sites,
  slice::from_raw/transmute, ioctl/copy_from_user, or decoder entry points.
  Prefer concrete input geometry over “C is unsafe.” Pure managed Java/Python/Go
  without JNI/unsafe/FFI → submit_none for this class. Planner must omit this
  class from hunt_focus without C/native/FFI inventory (A gating / hybrid).
---

# Hunt class: memory-safety

## Principles

- **Prefer evidence over pre-training.** Cite copy/free/use sites and length sources you read.
- **Be certain.** Bound every “length is safe” claim on the **worst** case path.
- **Provide evidence.** Input geometry (field → length → copy size) and observable; file:line on primitive sites.
- **Correctness over completeness.** One OOB write with controlled bytes beats “possible UAF somewhere.”
- Honest `submit_none` for pure managed code or fully bounded paths.
- **Planner omit:** without C/native/FFI inventory, this class must not appear in `hunt_focus` (hybrid A gating).

## When to use

- C/C++/ObjC, Ada (address overlays, Unchecked_Conversion, pragma Import C), Fortran, assembly, CUDA
- Rust `unsafe`, kernels/drivers, parsers/decoders, network daemons
- Firmware, JIT/runtimes, JNI/FFI bridges from managed languages (Java, Perl XS, Python C-API)
- Packet/file length fields driving alloc/copy; free without drain; type confusion

### Activation / omit policy (A gating + hybrid)

**Include in `hunt_focus` when inventory shows ANY of:**

- C/C++/ObjC/Ada/Fortran/assembly/CUDA sources or build (CMake, Meson, Autotools, `*.gpr`, …)
- Rust `unsafe` / FFI boundaries; JNI / Python C-API / Perl XS / cgo bridges
- Native parsers/decoders/packet handlers/ioctl paths taking attacker-controlled lengths

C/C++/ObjC/Ada/Fortran/unsafe Rust/CUDA parsers, kernels, and JNI/FFI are enough on their own to include this class.

**Must omit from `hunt_focus` when:**

- Pure managed Java/Python/Go/JS/TS **without** JNI/FFI/unsafe native, and the same for Ruby/PHP or other pure managed web/API trees **without** JNI/FFI/native extensions
- GraphQL/Node shops with no native inventory (Juice Shop–style pure web; DVGA–style GraphQL)

**Collection flag (hybrid):** keep `active: true` until live A2. Planner omit prevents A-path waste on pure web/API trees. When recon is shy and omits `hunt_focus`, the harness may still enqueue this class with the other active profiles — that B0 native-first fallback is accepted until focus reliability is measured.

**T3 gold shape:** `{memory-safety}` only on a pure C lab.

## When not to use / Scope

- Pure managed Java/Python/Go/JS/TS **without** JNI/FFI/unsafe native → `submit_none` (planner skips this class). Same for Ruby/PHP and other pure managed web/API trees **without** JNI/FFI/native extensions.
- Rust safe (no `unsafe` / FFI) → `submit_none`
- Null deref or assert crash inflated to RCE without a write-primitive or a clear high-impact DoS claim
- Unreachable test harnesses only
- Related skills: `injection` for managed interpreter sinks; `supply-chain` for poisoned native deps; `wildcard` only if residual and not a clean memory finding

## Decision tree

```
1. Inventory parsers, decoders, packet handlers, FFI, unsafe blocks
   — none / pure managed without JNI/FFI? → submit_none (planner should have omitted this class)
2. Find copy/alloc sites; bind claimed lengths to attacker-controlled fields
3. Bound every “length is safe” claim on the WORST case (multi-term precedence, sizeof)
4. For OOB write: which bytes become attacker-controlled; worst-case length
5. For UAF: free site, reclaim/use site, observable influence
6. Crash-only without write primitive / high-impact DoS story → do not inflate to RCE
7. Fully bounded on all paths → submit_none
```

## Rules quick reference

| Rule | Summary |
|------|---------|
| Geometry | Packet/file field → length → copy size must be explicit |
| Worst case | Multi-term length precedence; sizeof confusion |
| Crash ≠ RCE | Need write-primitive story or clear high-impact DoS |
| Temporal | Free site + use site + influence path |
| Uninit | Disclosure needs observable sink for secrets |
| Double-fetch | Kernel TOCTOU with privileged effect |
| Unsafe Rust | Only `unsafe`/FFI boundaries for this class |
| Managed ban | No pure Java/Python/Go memory-corruption claims |
| Incomplete fix | Sibling still-tainted copy after partial patch |
| Impact | RCE, sandbox escape, secret disclosure, high-impact DoS |
| Planner omit | No C/native/FFI inventory → not in hunt_focus |

## Focus

- Spatial: underflow, multi-term length precedence, sizeof confusion, unbounded copy
- Temporal: free without drain; base+offset across realloc
- Type confusion; uninit disclosure; privileged double-fetch TOCTOU
- Incomplete fix / trust asymmetry; write primitive into autoload/plugin paths

## Hunt workflow

1. **Inventory** — parsers, decoders, FFI, `unsafe`, ioctl/packet handlers; abort early if pure managed without JNI/FFI
2. **Trace** — attacker length/bytes → alloc/copy/free/use
3. **Prove** — worst-case size; controlled write bytes or UAF influence; no RCE inflation from a bare crash
4. **Evidence** — input geometry and observable; `write_evidence`
5. **Submit or none** — `weakness_class: memory-safety`, or honest `submit_none`

## Stack cues

```
memcpy|memmove|strcpy|strcat|sprintf|gets\(|scanf\(|recv\(|read\(
malloc|calloc|realloc|free\(|delete
Unchecked_Conversion|Interfaces\.C|pragma Import|System\.Address
unsafe |slice::from_raw|transmute|MaybeUninit
sizeof\(|offsetof|container_of
ioctl|copy_from_user|get_user|put_user
JNI_|Get(String|Byte|Int)Array|GetPrimitiveArrayCritical
parse_|decode_|deserialize|protobuf|flatbuffer|msgpack
```

## Required evidence

- **Input geometry:** name the attacker-controlled packet/file/IPC field, how it becomes a length/index, and the alloc/copy destination size (cite both the length source and the copy/free/use site with `start_line`)
- **Worst-case bound:** multi-term lengths, truncated casts, `sizeof` confusion, off-by-one on all relevant paths — state the worst case explicitly
- **Spatial effect:** which bytes become attacker-controlled past the bound (OOB write) or which out-of-bound read reaches an observable sink (OOB read / uninit disclosure)
- **Temporal effect (UAF/double-free):** free site + use/reclaim site + how the attacker influences the reuse
- **Impact honesty:** crash ≠ RCE without a write-primitive or sandbox-escape story; high-impact DoS only when the resource or availability break is concrete
- **Managed ban:** if the path has no native/unsafe/FFI → `submit_none` (do not file)
- `write_evidence` before `submit_candidate`

## False positives

- Bounded `memcpy` with correct `min(len, cap)` on **all** paths (including error and partial parses)
- Rust safe without `unsafe`/FFI
- Integer overflow notes that cannot affect allocation/copy size
- Unreachable test harnesses only
- Null deref / assert crash labeled RCE without a write primitive
- Pure managed “memory corruption” claims
- Sibling path already capped while filing an unrelated bounded copy

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| “C is unsafe” | No concrete geometry |
| Managed memory claims | Wrong language model |
| Crash = RCE | Need a write primitive or a real impact |
| Possible UAF somewhere | No free/use pair |
| Ignoring caps | Filing bounded copies |
| Enqueue on pure web via focus | Planner omit violation: no C/native/FFI inventory |

## Submit checklist

- `write_evidence` first with input geometry (field → length → copy) and observable
- `weakness_class: memory-safety`
- **Good:** *“`pkt->len` (u16) used in `memcpy` to 256-byte stack buf (`parse.c:90`) without cap; network OOB write.”*
- **Good:** *“Length = `hdr.size + hdr.ext` (`decode.c:55`) truncated to u16 then copied into `buf[hdr.size]` — sizeof/precedence confusion → OOB write.”*
- **Good:** *“`free(conn->buf)` at `net.c:200` then `conn->buf[i]` in callback at `net.c:240` without null/drain; attacker-controlled reclaim influence.”*
- **Good:** *“Partial fix capped `copy_a` but sibling `copy_b` (`parse.c:120`) still uses raw `len`.”*
- **Bad:** *“C is unsafe.”* / *“Null deref is RCE.”* / *“Python list index is memory corruption.”*
- Or honest `submit_none`
