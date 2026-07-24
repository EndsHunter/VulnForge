---
name: auth-model
description: >-
  Map authentication, sessions/tokens, roles, and multi-tenant authorization
  boundaries. Use when login, OAuth/OIDC/SAML, API keys, JWT, session stores,
  middleware, admin routes, or tenant isolation matter for hunt planning.
  Prefer evidence from auth modules and path inspection over assuming “has
  auth.” Updates trust_boundaries, components, and input_surfaces; finishes
  with submit_architecture only — never vulnerability findings.
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

- [ ] `submit_architecture` only (no `submit_candidate` / `submit_none`)
- [ ] Non-empty `summary` of the auth model
- [ ] Explicit `trust_boundaries` and path-backed auth-related `components`
- [ ] `hunt_focus` uses registered class ids (prefer access-control / web-protocol-auth when registered)
- [ ] No vulnerability findings
