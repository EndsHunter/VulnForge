---
name: business-logic
description: >-
  Hunts breaks of money, workflow, identity, and quota invariants via allowed
  APIs — no classic injection required. Use when tracing checkout, transfer,
  redeem, invite, reset, approve, coupon, credit, or state-machine flows;
  client-supplied price/quantity; replayable one-time tokens; non-atomic
  RMW. Prefer evidence of server trust-of-client or skipped state checks over
  “business logic might be wrong.”
---

# Hunt class: business-logic

## Principles

- **Prefer evidence over pre-training.** Cite the field or transition you read, not imagined race theories.
- **Be certain.** If atomicity/uniqueness is unclear, read the transaction path before filing.
- **Provide evidence.** Ordered steps + illegal end-state + code site.
- **Correctness over completeness.** One profit/access/quota break beats LOW padding.
- Honest `submit_none` when invariants hold with atomic updates.

## When to use

- Checkout, transfer, redeem, invite, reset, approve, quota/credit flows
- Client-supplied price/quantity/discount; state machines with status transitions
- Replay of one-time codes/gift cards/invites/reset tokens
- Refund/cancel/upgrade paths that can credit more than charged
- Time edges and feature flags that alter billing or entitlement

## When not to use / Scope

- Missing authz on a mutator without a business invariant story → `access-control`
- Pure race theory without non-atomic path or missing uniqueness → note, not finding
- Harmless UX skips with no asset/integrity impact
- Related skills: `access-control` for IDOR/BFLA; `feature-abuse` for export/SSRF design; `chains` for multi-hop combinations

## Decision tree

```
1. Identify high-value flows; write the INVARIANTS (paid⇒fulfilled once; coupon once; balance≥0)
2. Map each step’s SERVER validation vs client-only checks
3. Unconventional order / replay / non-atomic RMW possible?
4. Price/role/limit from request vs server catalog?
5. Invariants enforced with atomic updates → submit_none
```

## Rules quick reference

| Rule | Summary |
|------|---------|
| Invariant first | State the broken rule before the steps |
| Server authority | Client price/qty/role must be re-derived server-side |
| State machine | Illegal transitions and skipped gates are the bug |
| Atomic RMW | Missing uniqueness/lock/transaction enables double-spend |
| Replay | One-time tokens need used_at / single-consume |
| Order attacks | Call step N without N−1 when server allows |
| Refund math | Credits must not exceed original charge |
| Flag edges | Feature flags that skip payment still need server gates |
| Race bar | File only with a code-level non-atomic path |
| Impact | Profit, free goods, quota overage, privilege, integrity |

## Focus

- Workflow skips (skip payment, skip 2FA, reuse intermediate tokens)
- Price/quantity/coupon trusted from client; negative/zero/overflow; currency tricks
- Replay of one-time codes/gift cards/invites/reset tokens
- Double-spend / double-redeem without atomic guard
- Refund/cancel/upgrade that credits more than charged
- Cross-operation bypass; time edges; feature flags that alter billing

## Hunt workflow

1. **Inventory** — list high-value flows and domain invariants from code/comments
2. **Trace** — request fields that should be server-authoritative; state transitions
3. **Prove** — scenario = roles + ordered steps + illegal end-state reachable in code
4. **Evidence** — invariant, steps, trust-of-client or missing state check site; `write_evidence`
5. **Submit or none** — `weakness_class: business-logic`, or honest `submit_none`

## Stack cues

```
price|amount|quantity|discount|coupon|promo|balance|credit|debit|refund
status.*=|state.*=|transition|workflow|approve|pending|complete
redeem|voucher|gift|invite|referral|one.?time|nonce|used_at
rate.?limit|quota|usage|credits|tokens_remaining
optimistic|version|lock|select for update|transaction|atomic
```

## Required evidence

- Invariant broken, ordered steps, code that trusts client or skips state check
- Illegal end-state (profit, access, quota, integrity)

## False positives

- Client validation fully mirrored on server
- Admin-only price overrides correctly privileged
- Harmless UX skips with no asset/integrity impact
- “User can buy item” without underpay / over-fulfill / cross-account effect

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| Speculative races | No non-atomic path → theory, not finding |
| “Might be wrong logic” | No invariant, no scenario |
| LOW padding | Checklist noise without illegal end-state |
| Authz as logic | Missing owner check is `access-control` |
| Ignoring atomic guards | Filing double-spend when uniqueness holds |

## Submit checklist

- `write_evidence` first: invariant, steps, trust-of-client site
- `weakness_class: business-logic`
- **Good:** *“Checkout accepts `unit_price` from JSON (`orders.py:77`) instead of catalog; user sets 0.01 and fulfills.”*
- **Bad:** *“Business logic might be wrong.”*
- Or honest `submit_none`
