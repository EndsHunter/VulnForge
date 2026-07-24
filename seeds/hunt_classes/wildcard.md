---
name: wildcard
description: >-
  Residual hunt for weird trust edges and creative cross-class bugs other packs
  under-weight — still requiring full exploitability. Use when re-reading
  architecture for internal/legacy/debug routes, cross-service trust,
  incomplete coverage from other active classes, or odd surfaces the UI never
  calls. Prefer evidence from the target tree; prefer honest submit_none over
  speculative LOW spam. Clear single-class bugs belong under their dedicated id.
---

# Hunt class: wildcard

## Principles

- **Prefer evidence over pre-training.** Cite residual surfaces you grepped/read; no cloud theory out of tree.
- **Be certain.** Full self-verification gates still apply (REACHABLE, UNMITIGATED, CONCRETE, CITED).
- **Provide evidence.** Attacker, boundary, impact, citations — same bar as other classes.
- **Correctness over completeness.** Empty result is success; do not refile clear injection/IDOR.
- Honest `submit_none` when nothing solid.

## When to use

- Odd surfaces, internal routes, leftover debug, cross-service trust
- Incomplete coverage from other active classes; UI-never-called APIs
- Implicit trust (“internal” = safe); old API versions; feature-flag backdoors
- Residual deserialization/path/SSRF/XXE if not cleanly owned by another class

## When not to use / Scope

- Clear single-class bug → file under that class instead
- Speculative cloud misconfig not in tree; theoretical chains better as `chains` with real hops
- “Attacker who is already root” vacuous cases; pure style/hardening nits
- Related skills: dedicated class ids first; `chains` for multi-hop; `obvious` for dumb high-signal checklist

## Decision tree

```
1. Re-read architecture; list odd surfaces and trust assumptions
2. Diff main REST vs GraphQL/WS/admin/legacy/internal
3. Follow one weird data flow across a trust boundary end-to-end
4. REACHABLE + UNMITIGATED + CONCRETE + CITED?
     YES → candidate under wildcard only if no better class fit
     NO → drop
5. Nothing solid → submit_none (success). Do not refile clear injection/IDOR
```

## Rules quick reference

| Rule | Summary |
|------|---------|
| Residual only | Prefer bugs other classes under-weight |
| Class first | Clear SQLi/IDOR → that class, not wildcard |
| Same bar | Full gates; no lowered evidence standard |
| In-tree | Config/components must be in the target tree |
| Trust edges | “Internal” headers/networks need proof of external reach |
| Odd surfaces | Legacy/debug/v0/admin not behind same gates |
| One flow | Deep end-to-end beats shallow checklist |
| No dual-file | Do not refile the same path under a cleaner class |
| Empty OK | Honest submit_none is a good outcome |
| Impact | Real boundary cross, not creative padding |

## Focus

- Implicit trust (“internal” = safe); leftover admin/debug/feature flags; old API versions
- Deserialization, path traversal, SSRF, XXE if not owned by another class
- Dangerous defaults, install scripts left in prod tree
- Env assumptions (case-sensitive FS, trusted DNS, accurate clock)
- Names that lie: `temp`, `hack`, `legacy`, `compat`, `do_not_use`

## Hunt workflow

1. **Inventory** — architecture re-read; odd routes, internal trust, legacy versions
2. **Trace** — one weird flow across a trust boundary; compare gates vs main API
3. **Prove** — full self-verification; no blocked hops
4. **Evidence** — attacker, boundary, impact, citations; `write_evidence`
5. **Submit or none** — `weakness_class: wildcard` only if residual; else rehome or `submit_none`

## Stack cues

```
internal|trusted|skip.?auth|dangerously|do.?not.?use|legacy|deprecated
/v0/|/internal|graphql|websocket|grpc|admin
pickle|yaml\.load|unserialize|ObjectInputStream|gob\.Decode
\.\./|path\.join\(.*req|send_file|ZipSlip|zipfile
feature_flag|FEATURE_|launchdarkly|beta
child_process|postinstall|preinstall|auto.?update
```

## Required evidence

- Attacker, boundary, impact, citations — same bar as other classes

## False positives

- Speculative cloud misconfig not in tree
- “Attacker who is already root” vacuous cases
- Pure style/hardening nits; duplicate of cleaner class-specific finding

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| Speculative LOW spam | Avoids honest submit_none |
| Theoretical chains | Blocked hops or missing components |
| Creative padding | No proof, no boundary |
| Refiling clear bugs | Wrong class, dual noise |
| Out-of-tree config | Not confirmable in audit |

## Submit checklist

- `write_evidence` first with attacker, boundary, impact, citations
- `weakness_class: wildcard`
- **Good:** *“Legacy `/internal/export` mounted without auth (`routes.py:200`); unauth full DB export.”*
- **Bad:** *“Something creative might exist.”*
- Prefer honest `submit_none` over theoretical risk
