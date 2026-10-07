---
name: web-protocol-auth
description: >-
  Hunts HTTP framing, cache-key bugs, and identity-token machinery — JWT, OAuth,
  OIDC, SAML, sessions, password reset, Host/X-Forwarded trust. Use when reviewing
  proxies/gateways, custom parsers, token issue→verify→refresh, redirect_uri/PKCE,
  cache deception, or smuggling with dual-parser evidence in-repo. Prefer exact
  bytes/claims and victim effect over “JWTs are dangerous.”
  Activation: surface-triggered via hunt_focus when JWT/OAuth/session/Host/
  smuggling surfaces exist — inactive under B0 hybrid.
---

# Hunt class: web-protocol-auth

## Principles

- **Prefer evidence over pre-training.** Cite parsers, verify lines, and URL builders you read.
- **Be certain.** Smuggling needs dual-parser disagreement in-repo; deployment-only leads are notes.
- **Provide evidence.** Exact bytes/claims and victim effect (ATO, smuggled prefix, poisoned cache).
- **Correctness over completeness.** One Host-poisoned reset beats protocol style nits.
- Honest `submit_none` when alg/claims pin and Host is not trusted.
- **Known findings are per-path.** Skip re-file only when Known findings already lists **this** `path_hints` file. Another file with the same class (second open redirect, second Host builder) is a new candidate. Do not `submit_none` as a duplicate of a different path.
- **Planner:** include when JWT/OAuth/session/Host/smuggling inventory exists (inactive-ok).

## When to use

- Proxies/gateways, custom HTTP parsers, sessions/JWT/OAuth/OIDC/SAML
- Password reset; Host/`X-Forwarded-*` use for links and redirects
- Unallowlisted server 3xx (`header("Location:")`, `res.redirect`) of request data
- Cache poisoning / cache deception; CRLF in forwarded headers
- OAuth redirect_uri, state/PKCE, id_token checks, mix-up; SAML wrapping/XXE

### Activation criteria (planner)

**Include `web-protocol-auth` in `hunt_focus` when ANY of:**

- JWT/JOSE libraries with issue → store → transmit → verify → refresh → revoke paths (`jsonwebtoken`, `jose`, `PyJWT`, `jjwt`, …)
- OAuth/OIDC/SAML client or IdP wiring (`redirect_uri`, PKCE, `id_token`, Assertion consumers)
- Session create/regenerate/fixation surfaces; password-reset / magic-link URL builders
- Host / `X-Forwarded-*` / `X-Real-IP` used to build emails, redirects, or trust decisions
- In-repo reverse proxy / gateway / dual HTTP parsers (smuggling / desync candidates)
- Cache key / CDN surrogate logic with unkeyed attacker input
- Lab maps listing forged JWT, OAuth login bugs, CSRF-on-auth, 2FA storage, password reset ATO (Juice Shop family)

**Collection:** keep `active: false` under hybrid; surface-triggered via focus.

## When not to use / Scope

- Pure object-level authz without protocol story → `access-control`
- JWT secret hardcode without protocol angle may fit `cryptography` — file **once**
- Smuggling claims without dual-parser evidence in-repo
- Related skills: `cryptography` for material/verify strength; `access-control` for BOLA; `client-side` for browser sinks; `chains` for redirect+token theft multi-hop

## Decision tree

```
1. Establish role (proxy vs app; IdP vs RP client)
2. Tokens: issue → store → transmit → verify → refresh → revoke
3. Framing: name BOTH components and the divergent parse
4. Host/forwarded: URL builders for email links and redirects
5. Prove CROSS-USER impact (victim response, smuggled prefix, emailed link)
6. Verify paths pin alg/claims and Host is not trusted → submit_none
```

## Rules quick reference

| Rule | Summary |
|------|---------|
| Dual parsers | Smuggling lives in disagreement between two components |
| Verify not decode | Signature nobody verifies is decoration |
| Pin alg/claims | Allowlisted algorithms + aud/iss/exp as required |
| Host trust | Raw Host in reset/verify links enables ATO |
| OAuth redirect | Exact allowlist, not prefix; state/PKCE for CSRF |
| Per-path | `encodeURI` / `urlencode` is not an allowlist; each file’s Location/res.redirect is its own finding |
| Cache keys | Unkeyed attacker input in cached responses |
| Session fixation | Regenerate id on privilege change |
| Reset tokens | Entropy, single-use, binding to user/intent |
| Dual-file ban | Same JWT forge not under protocol + crypto |
| In-tree | Components not in tree → notes, not confirmed |
| Surface trigger | Planner includes class when JWT/OAuth/session/Host inventory exists |

## Focus

- Smuggling/desync (CL.TE / TE.CL / H2→H1); CRLF in forwarded headers
- Cache poisoning / cache deception
- Host/forwarded trust for reset/verify links
- JWT alg confusion/none; decode without verify; kid/jku/x5u
- OAuth/OIDC redirect_uri, state/PKCE, id_token checks, mix-up
- SAML wrapping/XXE; sessions fixation; password reset token flaws

## Hunt workflow

1. **Inventory** — proxies, token libraries, session store, Host/forwarded use, OAuth clients
2. **Trace** — issue→verify for tokens; dual parse for framing; URL builders for links
3. **Prove** — cross-user victim effect with exact bytes/claims
4. **Evidence** — citations on parse/verify/build sites; `write_evidence`
5. **Submit or none** — `weakness_class: web-protocol-auth`, or honest `submit_none`

## Stack cues

```
X-Forwarded|X-Real-IP|Forwarded|req\.host|getHost\(|Host header
Transfer-Encoding|Content-Length|absolute.?uri
Cache-Control|Vary:|CDN|surrogate|cache.?key
jwt|jsonwebtoken|jose|PyJWT|algorithms|verify_signature|kid|jku|x5u|none
oauth|OIDC|openid|redirect_uri|response_type|PKCE|code_verifier|id_token
SAML|Assertion|NotOnOrAfter|Audience|InResponseTo
session|Set-Cookie|SessionID|regenerate|fixation
password.?reset|reset_token|recover|forgot
Location:|header\(\s*[\"']Location|res\.redirect|HttpResponseRedirect
```

## Required evidence

- **Exact bytes/claims:** token fields, Host header value, Location target, or dual-parser inputs — cited at verify/build/parse sites with `start_line`
- **Missing control named:** no signature verify; alg not pinned; redirect prefix match; Host trusted for links; session not regenerated; reset token not bound/single-use
- **Victim effect:** ATO, session fixation, smuggled request prefix, poisoned cache serving victim, OAuth code/token theft — cross-user where applicable
- **Smuggling:** name **both** components in-repo and the divergent parse; deployment-only → note, not candidate
- **Dual-file:** same JWT forge story not also under `cryptography`
- `write_evidence` before `submit_candidate`

## False positives

- JWT library verify with allowlisted algorithms and audience
- Redirect allowlist exact match (not prefix bugs)
- SameSite/HttpOnly missing without sensitive cookie or CSRF path
- “OAuth implicit flow exists” without steal/misbind path
- Smuggling theory without dual-parser evidence in audit tree
- Cookie flag nits alone

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| “JWTs are dangerous” | No verify gap or forge path |
| “Duplicate of other file’s redirect” | Different path = different finding; Known findings skip same-path only |
| Confirmed out-of-tree | Components not in audit scope |
| Cookie flag nits alone | Need sensitive cookie or CSRF path |
| Smuggling theory | No dual-parser evidence |
| Dual-file crypto | Same forge under two classes |
| Leaving class off when JWT/OAuth surfaces clear | B0/A1 residual miss on Juice Shop–like labs |

## Submit checklist

- `write_evidence` first with exact bytes/claims and victim effect
- `weakness_class: web-protocol-auth`
- **Good:** *“Password reset builds link from raw Host (`reset.py:33`); attacker poisons Host → token to attacker; ATO.”*
- **Good:** *“`header('Location: '.$_GET['go'])` has no allowlist; victim 3xx to attacker origin.”*
- **Good:** *“`res.redirect(encodeURI(req.query.u))` — encodeURI is not an allowlist; file this path even if another file already has an open redirect.”*
- **Good:** *“JWT verify accepts `alg=none` / skips signature (`auth.js:90`); attacker forges `sub` → ATO.”*
- **Bad:** *“JWTs are dangerous.”* / *“Same class as a known finding on another file, none.”*
- Or honest `submit_none`
