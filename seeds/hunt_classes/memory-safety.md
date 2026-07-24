---
name: memory-safety
description: >-
  Hunts spatial/temporal memory bugs and privileged native-interface flaws on
  attacker-controlled input in C/C++/ObjC, Ada (Unchecked_Conversion / Interfaces.C),
  Fortran, assembly, CUDA, Rust unsafe, parsers, kernels, FFI, and JIT. Use when
  tracing memcpy/strcpy/sprintf, length fields from packets/files, free/use sites,
  slice::from_raw/transmute, ioctl/copy_from_user, or decoder entry points.
  Prefer concrete input geometry over “C is unsafe.” Pure managed Java/Python/Go
  without JNI/unsafe/FFI → submit_none for this class.
---

# Hunt class: memory-safety

## Principles

- **Prefer evidence over pre-training.** Cite copy/free/use sites and length sources you read.
- **Be certain.** Bound every “length is safe” claim on the **worst** case path.
- **Provide evidence.** Input geometry and observable; file:line on primitive sites.
- **Correctness over completeness.** One OOB write with controlled bytes beats “possible UAF somewhere.”
- Honest `submit_none` for pure managed code or fully bounded paths.

## When to use

- C/C++/ObjC, Ada (address overlays, Unchecked_Conversion, pragma Import C), Fortran, assembly, CUDA
- Rust `unsafe`, kernels/drivers, parsers/decoders, network daemons
- Firmware, JIT/runtimes, JNI/FFI bridges from managed languages (Java, Perl XS, Python C-API)
- Packet/file length fields driving alloc/copy; free without drain; type confusion

## When not to use / Scope

- Safe managed languages without native/unsafe (pure Go/Java/Python/Perl, Rust safe) → `submit_none`
- Null deref crash inflated to RCE without control claim
- Unreachable test harnesses only
- Related skills: `injection` for managed interpreter sinks; `supply-chain` for poisoned native deps; `wildcard` only if residual and not a clean memory finding

## Decision tree

```
1. Inventory parsers, decoders, packet handlers, FFI, unsafe blocks
2. Find copy/alloc sites; bind claimed lengths to attacker-controlled fields
3. Bound every “length is safe” claim on the WORST case
4. For OOB write: which bytes become attacker-controlled; worst-case length
5. For UAF: free site, reclaim/use site, observable influence
6. Managed languages without native/unsafe → submit_none
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

## Focus

- Spatial: underflow, multi-term length precedence, sizeof confusion, unbounded copy
- Temporal: free without drain; base+offset across realloc
- Type confusion; uninit disclosure; privileged double-fetch TOCTOU
- Incomplete fix / trust asymmetry; write primitive into autoload/plugin paths

## Hunt workflow

1. **Inventory** — parsers, decoders, FFI, `unsafe`, ioctl/packet handlers
2. **Trace** — attacker length/bytes → alloc/copy/free/use
3. **Prove** — worst-case size; controlled write bytes or UAF influence
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

- Input geometry and observable; citations on copy/free/use

## False positives

- Bounded `memcpy` with correct `min(len, cap)` on all paths
- Rust safe without `unsafe`/FFI
- Integer overflow notes that cannot affect allocation/copy size
- Unreachable test harnesses only

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| “C is unsafe” | No concrete geometry |
| Managed memory claims | Wrong language model |
| Crash = RCE | Need write primitive or real impact |
| Possible UAF somewhere | No free/use pair |
| Ignoring caps | Filing bounded copies |

## Submit checklist

- `write_evidence` first with input geometry and observable
- `weakness_class: memory-safety`
- **Good:** *“`pkt->len` (u16) used in `memcpy` to 256-byte stack buf (`parse.c:90`) without cap; network OOB write.”*
- **Bad:** *“C is unsafe.”*
- Or honest `submit_none`
