---
name: graphql
description: >-
  Hunts GraphQL/BFF surfaces that break object-level authz, enable batch/alias
  abuse, or leak data via nested resolvers — not “introspection is on.” Use when
  reviewing schema/resolvers (Graphene, Strawberry, Apollo, Hasura, PostGraphile,
  graphql-js), node(id:) loads, field auth directives, mutations without per-object
  checks, or depth/cost vs expensive resolvers. Compare GraphQL vs REST — weakest
  gate wins. Do not dual-file the same resolver under access-control.
---

# Hunt class: graphql

## Principles

- **Prefer evidence over pre-training.** Cite schema, resolvers, and middleware you read.
- **Be certain.** Authz may live in directives/plugins — read them before claiming absence.
- **Provide evidence.** Operation, missing check site, cross-user or privilege effect.
- **Correctness over completeness.** One BOLA mutation beats “GraphQL is enabled.”
- Honest `submit_none` when per-resolver authz + demand control hold.

## When to use

- GraphQL, Graphene, Strawberry, Apollo, Hasura, PostGraphile, graphql-js, Relay
- Federated gateways; JSON “query” RPCs that behave like GraphQL
- Mutations + sensitive queries with id/global ID loads; nested private fields
- Batching/aliasing vs rate limits; depth/breadth/cost amp

## When not to use / Scope

- Classic REST IDOR without GraphQL → `access-control`
- Pure sink SQLi via GraphQL args with sink narrative → prefer `injection` once
- Introspection alone without sensitive exposure path; N+1 performance without security impact
- Related skills: `access-control` for non-GraphQL object authz; `injection` for interpreter sinks via args; `feature-abuse` for export-style operations; dual-file ban on same resolver

## Decision tree

```
1. Locate schema, resolvers, middleware, auth directives, complexity plugins
2. Mutations + sensitive queries: ownership/role check on OBJECT, not only “logged in”
3. Trace id / global ID → load → authorize → return (and nested fields)
4. List resolvers: per-item tenant/owner filters?
5. Batching/alias/depth/cost vs expensive resolvers
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

## Focus

- BOLA via `node(id:)`, nested private fields without per-object checks
- Field-level authz gaps; mutation BFLA / mass-assign via input types
- Batching/aliasing defeating rate limits with real impact
- Depth/breadth/cost amp with concrete expensive resolvers
- Nested authz skip; federation trust; cookie CSRF on mutations; subscription auth

## Hunt workflow

1. **Inventory** — schema, resolvers, auth directives, complexity plugins, federation
2. **Trace** — id → load → authorize for mutations and sensitive queries; nested fields
3. **Prove** — cross-user/privilege effect; batch/cost impact if claimed
4. **Evidence** — operation, missing check, effect; `write_evidence`
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

- Operation, missing check site, cross-user or privilege effect

## False positives

- Introspection alone; missing rate limit alone without amp/data impact
- N+1 performance without security impact
- Client-side query construction when server enforces authz

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| “GraphQL is enabled” | Not a finding |
| “Introspection on” | Need sensitive exposure path |
| Dual-file access-control | Same resolver twice |
| Rate limit alone | No amp/data impact |
| Ignoring directives | False absence of authz |

## Submit checklist

- `write_evidence` first: operation, missing check, effect
- `weakness_class: graphql`
- **Good:** *“`Mutation.deleteDoc(id)` (`schema.py:120`) loads by id only; any auth user deletes peers’ docs (BOLA).”*
- **Bad:** *“GraphQL is enabled.”*
- Or honest `submit_none`
