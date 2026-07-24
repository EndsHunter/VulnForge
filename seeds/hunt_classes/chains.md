---
name: chains
description: >-
  Hunts multi-hop combinations that cross trust boundaries where each hop alone
  is limited but the combination yields privilege or data gain. Use when
  combining id leak + IDOR, open redirect + OAuth token theft, XSS + cookie
  action, second-order store→sink, incomplete fixes with sibling sinks, or
  cross-component trust/charset mismatches. Report the chain, not half-bugs;
  drop if any hop is blocked.
---

# Hunt class: chains

## Principles

- **Prefer evidence over pre-training.** Cite **per hop** from code you read.
- **Be certain.** If any hop is stopped by a real control, drop the chain.
- **Provide evidence.** Numbered hops with citations; final combined impact.
- **Correctness over completeness.** One verified multi-hop beats speculative stacks.
- Honest `submit_none` when no multi-hop exceeds single-hop classes.

## When to use

- Multi-step privilege/data gain where each hop alone is limited
- Second-order reuse; incomplete fixes leaving sibling sinks
- Cross-component trust / length-charset truncate mismatches
- Scope creep; TOCTOU; rollback/restore reintroduces access

## When not to use / Scope

- Single-hop issues better under their dedicated class
- Any hop blocked by a real control → drop the chain
- Config not in tree → notes / deployment test, not confirmed
- Related skills: file the strongest single class when one hop dominates; `wildcard` for residual single weird edges; do not dual-file every hop as CRITICAL plus the chain

## Decision tree

```
1. Inventory what a low-priv user CAN already do
2. Map trust boundaries: services, plugins, workers, caches, admin tools
3. Draft ordered hops; verify each hop’s code is real and unblocked
4. Document end-state privilege/data gain of the COMBINATION
5. No multi-hop path exceeds single-hop classes → submit_none (or file the single class)
```

## Rules quick reference

| Rule | Summary |
|------|---------|
| Report the chain | Combination is the finding, not orphan hops |
| Per-hop citations | Every hop needs path:line or path+symbol |
| Unblocked | Real control on any hop kills the chain |
| End-state | Privilege/data gain of the combination only |
| No dual CRITICAL | Do not spam every hop as separate CRITICAL + chain |
| Second-order | Safe store → dangerous re-use is a chain |
| Incomplete fix | One sink patched, sibling still tainted |
| In-tree | Out-of-tree config is not confirmed |
| Single-hop home | Clear IDOR alone → `access-control` |
| Impact | Cross-boundary gain, not “learns field names” |

## Focus

- Id leak + IDOR; open redirect + OAuth token theft; XSS + CSRF cookie action
- Cross-component trust / length-charset truncate mismatches
- Second-order: safe store → dangerous re-use
- Scope creep; TOCTOU; rollback/restore reintroduces access
- Incomplete fix: one sink patched, sibling still tainted

## Hunt workflow

1. **Inventory** — low-priv capabilities; trust boundaries; sibling sinks
2. **Trace** — ordered hops with code evidence per hop
3. **Prove** — each hop unblocked; combination end-state exceeds any single hop
4. **Evidence** — numbered hops with citations; final impact; `write_evidence`
5. **Submit or none** — `weakness_class: chains`, or rehome single hop / `submit_none`

## Stack cues

```
TODO|FIXME|trust|internal|service.?token|bypass
cache|ttl|invalidate|soft.?delete|restore|undelete|revision
plugin|hook|middleware|gateway|sidecar
redirect_uri|returnUrl|state=|oauth
render.*db|from_db|stored
```

## Required evidence

- Numbered hops with per-hop citations; final combined impact
- Attacker control of each hop

## False positives

- Theoretical chains needing admin + network + physical without evidence
- A hop that only “learns field names” presented as a full finding
- Speculative multi-precondition stacks

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| Every hop CRITICAL | Double-counting + chain spam |
| Blocked hop kept | Chain is not real |
| Out-of-tree config | Not confirmable |
| Half-bugs alone | Use dedicated class or drop |
| Speculative stacks | Many preconditions without code |

## Submit checklist

- `write_evidence` first: numbered hops with citations; final impact
- `weakness_class: chains`
- **Good:** *“(1) search oracle reveals private id (`a.py:40`) → (2) `GET /files/{id}` no owner check (`b.py:12`) → peer files.”*
- **Bad:** *“Could chain XSS with something.”*
- Or honest `submit_none`
