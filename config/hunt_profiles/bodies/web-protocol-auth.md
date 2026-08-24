---
name: web-protocol-auth
description: >-
  Hunts HTTP framing, cache-key bugs, and identity-token machinery — JWT, OAuth,
  OIDC, SAML, sessions, password reset, Host/X-Forwarded trust. Use when reviewing
  proxies/gateways, custom parsers, token issue→verify→refresh, redirect_uri/PKCE,
  cache deception, or smuggling with dual-parser evidence in-repo. Prefer exact
  bytes/claims and victim effect over “JWTs are dangerous.”
---

# Hunt class: web-protocol-auth

## Principles

- **Prefer evidence over pre-training.** Cite parsers, verify lines, and URL builders you read.
- **Be certain.** Smuggling needs dual-parser disagreement in-repo; deployment-only leads are notes.
- **Provide evidence.** Exact bytes/claims and victim effect (ATO, smuggled prefix, poisoned cache).
- **Correctness over completeness.** One Host-poisoned reset beats protocol style nits.
- Honest `submit_none` when alg/claims pin and Host is not trusted.
- **Known findings are per-path.** Skip re-file only when Known findings already lists **this** `path_hints` file. Another file with the same class (second open redirect, second Host builder) is a new candidate. Do not `submit_none` as a duplicate of a different path.

## When to use

- Proxies/gateways, custom HTTP parsers, sessions/JWT/OAuth/OIDC/SAML
- Password reset; Host/`X-Forwarded-*` use for links and redirects
- Unallowlisted server 3xx (`header("Location:")`, `res.redirect`) of request data
- Cache poisoning / cache deception; CRLF in forwarded headers
- OAuth redirect_uri, state/PKCE, id_token checks, mix-up; SAML wrapping/XXE

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

- Exact bytes/claims and victim effect; dual-parser or missing verify citation

## False positives

- JWT library verify with allowlisted algorithms and audience
- Redirect allowlist exact match (not prefix bugs)
- SameSite/HttpOnly missing without sensitive cookie or CSRF path
- “OAuth implicit flow exists” without steal/misbind path

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| “JWTs are dangerous” | No verify gap or forge path |
| “Duplicate of other file’s redirect” | Different path = different finding; Known findings skip same-path only |
| Confirmed out-of-tree | Components not in audit scope |
| Cookie flag nits alone | Need sensitive cookie or CSRF path |
| Smuggling theory | No dual-parser evidence |
| Dual-file crypto | Same forge under two classes |

## Submit checklist

- `write_evidence` first with exact bytes/claims and victim effect
- `weakness_class: web-protocol-auth`
- **Good:** *“Password reset builds link from raw Host (`reset.py:33`); attacker poisons Host → token to attacker; ATO.”*
- **Good:** *“`header('Location: '.$_GET['go'])` has no allowlist; victim 3xx to attacker origin.”*
- **Good:** *“`res.redirect(encodeURI(req.query.u))` — encodeURI is not an allowlist; file this path even if another file already has an open redirect.”*
- **Bad:** *“JWTs are dangerous.” / “Same class as a known finding on another file, none.”*
- Or honest `submit_none`
