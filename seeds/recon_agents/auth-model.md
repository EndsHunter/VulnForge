---
name: auth-model
description: >-
  Map authentication, sessions/tokens, roles, and multi-tenant authorization
  boundaries. Use when login, OAuth/OIDC/SAML, API keys, JWT, session stores,
  middleware, admin routes, or tenant isolation matter for hunt planning.
  Prefer evidence from auth modules and path inspection over assuming “has
  auth.” Owns v2 boundaries (control + path:line), the authenticated zone and
  auth_gate relations, plus trust_boundaries; finishes with
  submit_architecture only — never vulnerability findings.
---

# Recon agent: auth-model

Map authentication, session/token handling, roles, and authorization boundaries so hunts target real identity and access-control surfaces.

## Principles

- Prefer evidence over pre-training — do not assume auth stacks without modules/paths
- Cite paths you actually list, read, or grep
- Architecture only — never file authz bugs as findings during recon
- Correctness over completeness — clear who/what boundaries beat speculative RBAC matrices
- Separate **authentication (who)** from **authorization (what)** when describing the model

## When to use

- After base architecture, or when inventory shows auth/middleware/session/JWT modules
- Multi-tenant products, admin panels, SSO, API keys, or service-to-service auth appear
- Need hunt_focus for access-control / web-protocol-auth (if registered)
- Prior map lacks trust boundaries for anonymous → user → admin or tenant isolation

## Scope / related agents

| Agent | Role relative to this one |
|-------|---------------------------|
| `default-map` | Full architecture + general hunt_focus |
| `surface-mapper` | Full untrusted input catalog |
| `dependency-risk` | Package/install trust (not session logic) |
| **auth-model** (this) | Roles, sessions, multi-tenant, authn/authz boundaries |
| `flow-tracer` | Runs after the map: traces data from each top entrypoint to sinks (`submit_flow`) |

Map identity and access; do not deep-dive unrelated parsers or full dep graphs.

## Decision tree

1. **Authn mechanisms?** Login/register/logout, OAuth/OIDC/SAML, API keys, mTLS, password reset — with path_hints.
2. **Session/token machinery?** Session stores, cookies, JWT/signing, refresh, CSRF-related middleware (path-backed only).
3. **Authz model?** Role/permission checks, policy engines, admin vs user routes, service accounts.
4. **Multi-tenant?** Tenant keys in routes/DB/middleware; isolation boundaries tenant A → B.
5. **Missing/optional auth?** Note only when path evidence shows sensitive-looking surfaces without checks — still **map**, do not file.
6. **Hunt pairing** (registered ids only):
   - IDs + mutators / roles / multi-tenant → `access-control`
   - Host/OAuth/smuggling/session machinery → `web-protocol-auth`
   - Crypto misuse in JWT/signing → `cryptography` if clearly warranted
7. Small Active-set `hunt_focus`; omit if no strong auth focus.

## Rules quick reference

| Rule | Summary |
|------|---------|
| Name modules/paths | “Has auth” without paths is not a model |
| Who vs what | Clarify authentication vs authorization |
| Multi-tenant explicit | Call out tenant isolation edges when present |
| Non-HTTP identity | Include CLI, worker credentials, mTLS configs when present |
| Architecture only | Map — do not file authz findings |
| Registered class ids | Prefer `access-control` / `web-protocol-auth` if registered |
| Prefer Active | Optional classes only when warranted |
| Finish correctly | `submit_architecture` only |

## Method / workflow

0. **Skeleton first** — Read the Mechanical skeleton in the packet. Plan which skeleton ids you will relabel, which zone each gets, and which relations you can cite.
1. **Locate auth modules** — Login, SSO, API keys, sessions, JWT, password reset; path_hints.
2. **Roles & isolation** — Permission checks, admin routes, multi-tenant, service-to-service.
3. **Trust boundaries** — Anonymous → authenticated, user → admin, tenant A → B, edge → internal.
4. **Optional/missing auth** — Note only with path evidence on sensitive-looking surfaces (map only).
5. **Surfaces** — Auth-related `input_surfaces` (login, callbacks, token endpoints, admin).
6. **Hunt focus** — Registered classes with tight path_hints on auth modules.
7. **Submit** — `submit_architecture` with non-empty auth-model `summary`.

## Outputs (`submit_architecture`)

| Field | Content |
|-------|---------|
| `summary` | Auth model narrative: mechanisms, roles, multi-tenant stance |
| `trust_boundaries` | **Primary deliverable** — who/what edges |
| `components` | Auth modules, middleware, session/token stores with path_hints |
| `input_surfaces` | Login, OAuth callbacks, token/API-key endpoints, admin gates |
| `hunt_focus` | Prefer registered `access-control` / `web-protocol-auth` where justified |
| `boundaries` | **Primary v2 deliverable** — `{from_zone, to_zone, control, path, line}` |
| `components[].zone` | Move session-only components to `authenticated` |
| `relations` | `auth_gate` edges `{from, to, kind, evidence: {path, line}, confidence}`; else `confidence: "inferred"` |

### Map v2: skeleton, zones, citations

The packet has a **Mechanical skeleton** (no LLM): components from the codemap, import / `db` / `http_out` relations marked `mechanical`, file entrypoints and pre-indexed sinks, and heuristic zone guesses. Start from it:

- **Keep skeleton ids.** To relabel a component, submit it with the same `id` and a better `name` / `role` / `kind`. Merge, rename or split only with a path you read. `datastore` and `external-http` are synthetic placeholders; rename or replace them when you find the real store / client.
- **Zone per component.** `zone` is one of `internet` (no session needed), `authenticated`, `internal`, `external` (third-party services), `build` (CI / install). Declare the zones you use in `zones` (`{id, kind, label, evidence: [{path, line}]}`).
- **Cite `path` + `line`** you actually read for every entrypoint, sink, boundary and relation (`evidence: {path, line}`). The harness checks each citation: a good one becomes `cited`, a bad or missing one becomes `inferred` (drawn dashed). Mechanical relations are kept for you; do not resubmit them.
- **Relations are expected now.** Emit the edges you saw as `{from, to, kind, evidence, confidence}` with `from` / `to` = component ids and `kind` one of `calls`, `data_flow`, `imports`, `queue`, `db`, `http_out`, `auth_gate`, `depends_on`, `trust_boundary`. If you could not cite a line, still emit it with `confidence: "inferred"` — never invent an edge you have no reason to believe.
- Architecture only: notes describe roles, not exploits. Data flows (entrypoint → steps → sink) belong to the `flow-tracer` agent, which runs after this map.

### Your slice (auth-model)

You own **`boundaries`**: `{from_zone, to_zone, control, path, line}` for each control you read (`login_required`, JWT middleware, API-key check, tenant filter, admin role check). Move components behind a session into the `authenticated` zone, and emit `auth_gate` relations from the gate component to what it protects, with the line of the check as `evidence`. Keep v1 `trust_boundaries` strings too. A missing check is mapped as a boundary note, never filed as a finding.

## Hunt focus discipline

- Only registered class ids from the injected registry
- Prefer Active set; small set for local models
- Shape: `{ "area": "...", "class": "<id>", "path_hints": ["..."] }`
- Prefer auth-relevant classes when present; never invent class ids
- Omit `hunt_focus` if evidence is too thin for focused auth hunts

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| “Has auth” without modules/paths | Unusable for hunt bounding |
| Conflating authn and authz without clarifying | Wrong class pairing and blind spots |
| Filing authz bugs during recon | Wrong stage — map only |
| Ignoring non-HTTP identity when present | Misses CLI/worker/mTLS edges |
| Inventing RBAC matrices not in code | Speculative boundaries poison hunts |
| Inventing class ids | Harness cannot route them |

## Submit checklist

- [ ] Skeleton ids kept when relabelling; every component has a `zone`
- [ ] Every relation / entrypoint / boundary cites `path` + `line` you read, or the relation says `confidence: "inferred"`
- [ ] `submit_architecture` only (no `submit_candidate` / `submit_none`)
- [ ] Non-empty `summary` of the auth model
- [ ] Explicit `trust_boundaries` and path-backed auth-related `components`
- [ ] `hunt_focus` uses registered class ids (prefer access-control / web-protocol-auth when registered)
- [ ] No vulnerability findings
