---
name: access-control
description: >-
  Hunts IDOR/BOLA, missing authentication on mutators, mass assignment, and
  broken object/function-level authorization. Use when handlers take resource
  ids (id/uuid/slug/user_id), role/tenant/owner checks, permit/deny lists,
  parallel REST vs GraphQL vs job vs import gates, or unauth mutators.
  Prefer evidence of missing checks at load sites over “should use RBAC.”
  Highest real-world payout — prefer over clever injection when both appear.
---

# Hunt class: access-control

## Principles

- **Prefer evidence over pre-training.** Cite the load site and (missing) authorize site you actually read.
- **Be certain.** If the check might live in middleware/policy, read those before filing absence.
- **Provide evidence.** file:line or path+symbol; concrete lower-priv request.
- **Correctness over completeness.** One solid IDOR beats “IDs are sequential.”
- Honest `submit_none` when enforcement is consistent.

## When to use

- Handlers take resource ids; role/tenant/owner checks; mass-assign of `role`/`owner_id`/`is_admin`
- Parallel paths: REST vs GraphQL vs job vs webhook vs CLI — **weakest gate wins**
- Horizontal (peer) and vertical (user→admin) privilege; multi-tenant filter missing
- Unauth/cross-user write that mutates others’ data, tenants, or global/admin state

## When not to use / Scope

- GraphQL-specific resolver/batching story is clearer as `graphql` (do not dual-file same resolver)
- Client-only hide of buttons when **server** enforces the same rule
- Public read of intentionally public resources; create-own with no cross-user access
- Related skills: `graphql` for resolver/batching BOLA; `business-logic` for invariant breaks with correct authz; `web-protocol-auth` for token/session machinery

## Decision tree

```
1. Map roles, tenants, ownership from routes/middleware/policies
2. List handlers with resource ids (id, uuid, slug, user_id)
3. For each sensitive read/write: ownership/role/tenant check present BEFORE use?
4. Compare UI-gated vs API/batch/webhook/CLI paths — weakest wins
5. Mass-assignment: full-body bind, permit vs deny lists, hidden fields
6. Consistent enforcement everywhere → submit_none
```

## Rules quick reference

| Rule | Summary |
|------|---------|
| Object-level | Load by id is not authorize; need owner/tenant/role check |
| Before use | Checks after mutation/return still leak or race |
| Weakest gate | UI gate without API gate is a finding on the API |
| Mass assign | Full-body bind of role/owner/admin fields is classic |
| BFLA | Function-level: can lower role call admin mutators? |
| Batch paths | Per-item ownership on export/import/bulk delete |
| Claim trust | JWT role claims need server re-check for privileged ops |
| Dual-file ban | Same resolver not under both `access-control` and `graphql` |
| Sequential IDs | Guessable ids alone ≠ finding without cross-user proof |
| Impact | Cross-user read/write/delete/grant or privilege escalation |

## Focus

- Object-level authz (IDOR/BOLA); function-level (BFLA)
- Missing authentication on critical mutators
- Horizontal and vertical privilege; multi-tenant filter missing
- Batch/export/import: per-item ownership?
- JWT/session role claims trusted without server re-check — only with clear impact

## Hunt workflow

1. **Inventory** — enumerate mutators and id-based loaders; map middleware/policies
2. **Trace** — find check site (or absence); note after-use checks and alternate paths
3. **Prove** — IDOR extras: create-then-access, swap tenant header, secondary resources, verb swap
4. **Evidence** — exact lower-priv request (method, path, params) and state change; `write_evidence`
5. **Submit or none** — `weakness_class: access-control`, or honest `submit_none`

## Stack cues

```
findById|get_object_or_404|Objects\.get\(|\.findOne\(|where\(.*id
user_id|owner_id|account_id|tenant_id|org_id|customer_id
requireAdmin|is_admin|hasRole|checkPermission|authorize|CanCan|Pundit|policy
@PreAuthorize|@RolesAllowed|login_required|Depends\(|AllowAnonymous|permitAll
params\.permit|allowlist|mass.?assign|bind\(|ModelAttr
skip_before_action|AUTH_NONE|authentication_classes\s*=\s*\[\]
```

## Required evidence

- Attacker role, victim resource, request shape, missing check site
- Impact: cross-user read/write/delete/grant or privilege escalation
- Citations on load and (missing) authorize

## False positives

- Create-own with no cross-user access and no privilege field writable
- Admin-only route correctly gated (including router-group middleware)
- “IDs in URLs” without a cross-user proof
- Client-side-only authz when server is responsible and enforces

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| “Should use RBAC” | No concrete bypass request |
| Dual-file GraphQL BOLA | Same resolver under two classes |
| Sequential IDs alone | Guessability ≠ authorization failure |
| UI-only analysis | Server is the authority |
| Missing middleware without reading it | False absence claims |
| Admin-as-bug | Designed admin behavior is not a finding |

## Submit checklist

- `write_evidence` first: attacker role, victim resource, request shape, missing check site
- `weakness_class: access-control`
- **Good:** *“User A `DELETE /api/docs/{id}` with B’s id; `docs.py:140` loads by id only — deletes B’s doc.”*
- **Bad:** *“Should use RBAC.”* / *“IDs are sequential.”*
- One clear boundary per finding; or honest `submit_none`
