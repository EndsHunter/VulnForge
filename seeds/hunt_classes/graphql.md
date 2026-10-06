---
name: graphql
description: >-
  Hunts GraphQL/BFF surfaces that break object-level authz, enable batch/alias
  abuse, or leak data via nested resolvers — not “introspection is on.” Use when
  reviewing schema/resolvers (Graphene, Strawberry, Apollo, Hasura, PostGraphile,
  graphql-js), node(id:) loads, field auth directives, mutations without per-object
  checks, or depth/cost vs expensive resolvers. Compare GraphQL vs REST — weakest
  gate wins. Do not dual-file the same resolver under access-control.
  Activation: surface-triggered via hunt_focus / planner when GraphQL inventory
  exists — not blanket collection-active under hybrid ship policy.
---

# Hunt class: graphql

## Principles

- **Prefer evidence over pre-training.** Cite schema, resolvers, and middleware you read.
- **Be certain.** Authz may live in directives/plugins — read them before claiming absence.
- **Provide evidence.** Operation + resolver path, missing object-level check, cross-user or privilege effect; batch/alias/cost only with concrete impact.
- **Correctness over completeness.** One BOLA mutation beats “GraphQL is enabled.”
- Honest `submit_none` when per-resolver authz + demand control hold.
- **Dual-file ban:** same resolver/path+symbol not under `graphql` + `access-control`.

## When to use

- GraphQL, Graphene, Strawberry, Apollo, Hasura, PostGraphile, graphql-js, Relay
- Federated gateways; JSON “query” RPCs that behave like GraphQL
- Mutations + sensitive queries with id/global ID loads; nested private fields
- Batching/aliasing vs rate limits; depth/breadth/cost amp with security impact

### Activation criteria (planner / hybrid policy)

**Include `graphql` in `hunt_focus` when ANY of:**

- Inventory or greps show GraphQL stack (Graphene, Strawberry, Apollo, Hasura, PostGraphile, graphql-js, Ariadne, async-graphql, …)
- `*.graphql` / `*.gql` schema files; resolver dirs; GraphiQL / Playground / Voyager exposed in tree
- Codemap modules named for schema/resolvers/federation gateway / BFF speaking GraphQL
- HTTP surface documents a GraphQL endpoint

**Do not** rely on active `access-control` alone for GraphQL object-level stories — dual-file ban means GraphQL BOLA/BFLA belongs here once.

**Collection flag:** keep `active: false`. Surface-triggered enqueue via `hunt_focus` when any criterion above is present. Not blanket collection-active.

## When not to use / Scope

- Classic REST IDOR without GraphQL → `access-control`
- Pure sink SQLi via GraphQL args with sink narrative → prefer `injection` once
- Introspection alone without sensitive exposure path; N+1 performance without security impact
- Related skills: `access-control` for non-GraphQL object authz; `injection` for interpreter sinks via args; `feature-abuse` for export-style operations; **dual-file ban on same resolver** with access-control

## Decision tree

```
1. Locate schema, resolvers, middleware, auth directives, complexity plugins
2. Mutations + sensitive queries: ownership/role check on OBJECT, not only “logged in”
3. Trace id / global ID → load → authorize → return (and nested fields)
4. List resolvers: per-item tenant/owner filters?
5. Batching/alias/depth/cost vs expensive resolvers — only with concrete impact
6. Compare GraphQL vs REST for same resource — WEAKEST gate wins
7. Solid per-resolver authz + demand control → submit_none
```

## Rules quick reference

| Rule | Summary |
|------|---------|
| Per resolver/field | Authz not only once per HTTP request |
| Object-level | Logged-in ≠ authorized for this id |
| Nested fields | Private nested data needs checks too |
| Global ID | node(id:) is a classic BOLA surface |
| Mutation BFLA | Lower roles calling admin mutations |
| Mass-assign | Input types binding role/owner fields |
| Batch/alias | Defeat rate limits with real impact only |
| Cost/depth | Expensive resolvers without limits + impact |
| Weakest gate | GraphQL vs REST for same resource |
| Dual-file ban | Same resolver not under graphql + access-control |
| Surface trigger | Planner includes this class when GraphQL inventory exists |

## Focus

- BOLA via `node(id:)`, nested private fields without per-object checks
- Field-level authz gaps; mutation BFLA / mass-assign via input types
- Batching/aliasing defeating rate limits with real impact
- Depth/breadth/cost amp with concrete expensive resolvers
- Nested authz skip; federation trust; cookie CSRF on mutations; subscription auth

## Hunt workflow

1. **Inventory** — schema, resolvers, auth directives, complexity plugins, federation; note REST twins
2. **Trace** — id → load → authorize for mutations and sensitive queries; nested fields
3. **Prove** — cross-user/privilege effect; batch/cost impact if claimed; weakest-gate if REST exists
4. **Evidence** — operation, resolver path, missing check, effect; `write_evidence`
5. **Submit or none** — `weakness_class: graphql`, or honest `submit_none`

## Stack cues

```
graphql|GraphQL|graphene|strawberry|apollo|gql`|type Query|type Mutation
resolver|@Query|@Mutation|ObjectType|Field\(|node\(id
global.?id|fromGlobalId|toGlobalId|Node\.interface
@auth|@authorized|@require|isAuthenticated|skip_auth|permissions
dataloader|complexity|depth.?limit|query.?cost|rate.?limit
federation|@key|@external|gateway
subscription|batch|aliases|persisted.?quer
```

## Required evidence

- **Operation** named (query/mutation/subscription + field), with citation on schema or resolver entry (`start_line` on the resolver/handler, not only the type definition)
- **Missing control named:** no per-object ownership/tenant/role check; directive skipped; middleware only “isAuthenticated”; mass-assignable input fields (role/owner) without server pin
- **Cross-user or privilege effect:** attacker role, victim resource id, observable read/write/delete/grant beyond caller’s scope
- **Weakest-gate note** when the same resource exists on REST: which path is weaker and why (file under `graphql` if the GraphQL resolver is the broken one)
- **Batch/alias/depth/cost** claims require: concrete expensive resolver or data amp, missing/insufficient limit, and security impact (DoS with resource exhaustion story or authz bypass via batch) — not “aliases exist”
- Payload / request narrative: GraphQL document shape → missing check → impact
- `write_evidence` before `submit_candidate`

## False positives

- Introspection alone; GraphiQL on in non-prod without sensitive exposure path
- Missing rate limit alone without amp/data/authz impact
- N+1 performance without security impact
- Client-side query construction when server enforces per-object authz
- “GraphQL enabled” / schema publicly readable without a broken resolver story
- Dual-filing the same resolver under `access-control` (merge: keep `graphql`)

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| “GraphQL is enabled” | Not a finding |
| “Introspection on” | Need sensitive exposure path |
| Dual-file access-control | Same resolver twice |
| Rate limit alone | No amp/data impact |
| Ignoring directives | False absence of authz |
| Batch theory without impact | Noise vs DoS/authz proof |
| Relying on B0 access-control for GraphQL BOLA | Class inactive under B0; planner must name graphql |

## Submit checklist

- `write_evidence` first: operation, resolver path + `start_line`, missing check, cross-user/privilege effect
- `weakness_class: graphql`
- **Good:** *“`Mutation.deleteDoc(id)` (`schema.py:120`) loads by id only; any auth user deletes peers’ docs (BOLA).”*
- **Good:** *“`Query.node(id:)` (`nodes.py:44`) returns private `invoice` fields with no owner check; user A reads B’s invoice.”*
- **Good:** *“`Mutation.adminPurge` callable by role=user (`mutations.py:88`); BFLA — no role gate on mutation.”*
- **Good:** *“Nested `user.ssn` resolver (`types.py:210`) skips tenant filter present on parent; cross-tenant PII.”*
- **Bad:** *“GraphQL is enabled.”* / *“Introspection is on.”* / *“Same BOLA also filed under access-control.”*
- Or honest `submit_none`
