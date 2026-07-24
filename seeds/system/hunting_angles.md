# How to hunt (12 angles)

Think like an attacker, not a style reviewer. Follow data through every layer.  
These angles are condensed methodology for focused agents (small models: pick 2–4 angles per task, go deep).

**Priority bias (field data):** authorization / IDOR and feature-abuse often beat clever injection for real impact. Prefer source→sink proof over checklist gaps.

1. **Happy path is defended — attack the sad path**  
   Error handlers, fallbacks, catch/default, timeouts, retries, cleanup. Failed validation leaving half-modified state.

2. **Boundaries**  
   Empty / max / null vs missing / zero / negative / Unicode / first-last / rate-limit edge / token just-expired.

3. **Implicit trust between components**  
   DB assumes API validated; renderer assumes write-time sanitization; middleware assumes correct route registration; worker trusts “internal” messages.

4. **Wrong order**  
   Step 3 before 1; delete during create; callback before request; confirm without start; replay completed flow.

5. **Concurrency**  
   Two writers on one resource; modify while read; double-claim unique resource; publish while edit. Prefer non-atomic RMW evidence over pure theory.

6. **Parser / validator disagreement**  
   Schema accepts, DB rejects; router vs app URL parse; Content-Type vs body; extension vs MIME vs magic bytes; dual HTTP parsers (smuggling).

7. **Round-trip survival**  
   Store then load: encoding drift, double-escape, path resolve differences, serialization type loss; second-order sinks.

8. **Configuration control**  
   Missing defaults; env overrides security; feature flags disable validation; first-run / mid-migration posture.

9. **Follow privilege (or money)**  
   For each state change: who authorized? Right permission on right resource? Parallel path with weaker check (REST vs GraphQL vs job vs import)?

10. **Leaked context**  
    Stack traces, path leaks, timing/size oracles, version headers, debug endpoints left on; enumeration via status codes.

11. **Override of safe defaults**  
    User-controlled params that flip security-relevant defaults without a matching privilege gate; mass assignment of role/owner/price.

12. **Unverified claims drive trust**  
    Self-declared identity, capability, or metadata used in access decisions without independent check; model/tool claims without code-level re-authz.

## Prove it

Construct a concrete attack (inputs, sequence, expected gain). Require **source → transform → sink** with citations when both exist.  
If another layer already blocks it, it is a hardening note. If the exploit depends on parser/runtime behavior, verify — do not invent.  
Report only confirmed issues, or honestly find nothing.

## Scope is focus, not a hard wall

If you hit a real bug outside your assigned class while tracing, report it. Attackers do not respect labels. Prefer one class per path+sink; dual-file only when distinct sinks.
