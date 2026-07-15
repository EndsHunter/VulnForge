---
name: obvious
description: >-
  Exhausts high-signal dumb checks others skip because they assume someone
  already looked — committed secrets, debug routes, open redirects, sensitive
  cookie flags, verbose prod errors. Use when grepping passwords/api keys/pem,
  /debug /admin /metrics /env, DEBUG=True, returnUrl/next redirects, or
  CORS * + credentials. Report only items with a concrete impact path; exhaust
  then stop.
---

# Hunt class: obvious

## Principles

- **Prefer evidence over pre-training.** Grep and inventory systematically; verify each hit.
- **Be certain.** Flag alone is not a finding — trace impact.
- **Provide evidence.** Citations; for secrets, material is real/default-usable.
- **Correctness over completeness.** Exhaust the list, then stop — not a creativity contest.
- Honest `submit_none` when checklist is clean.

## When to use

- First pass / residual sweep for secrets, debug endpoints, open redirects
- Cookie flags on sensitive cookies; verbose prod errors
- TODO/FIXME about auth matching a **real** missing check
- Debug/dev mode toggleable in prod; unprotected actuator-style routes

## When not to use / Scope

- Example secrets in docs never loaded
- Dependency CVE with no reachable use (codemap note, not candidate)
- Pure missing hardening without impact
- Related skills: `cryptography` for verify/forge crypto stories; `injection` for eval on user data with full sink narrative; `supply-chain` for install-time trust; `access-control` for real authz gaps beyond TODO

## Decision tree

```
1. Grep and inventory systematically — exhaust the list
2. For each hit, TRACE IMPACT — flag alone is not a finding
3. Confirm secrets are real material; debug routes mounted in main app
4. Cookie missing HttpOnly: is value security-sensitive?
5. Checklist clean → submit_none
```

## Rules quick reference

| Rule | Summary |
|------|---------|
| Exhaust then stop | Systematic coverage, not creativity contest |
| Impact gate | Every hit needs a path to data/auth/code effect |
| Real secrets | Default-usable material, not placeholders forced replace |
| Mounted debug | Route must be on prod app surface |
| Sensitive cookies | HttpOnly/Secure matter when value is session/token |
| Open redirect | Token/phishing impact, not every next= |
| TODO + missing check | TODO alone is noise without real gap |
| SCA reachability | Known-bad + reachable sink, else note only |
| Dual-file | Install script impact may fit `supply-chain` better |
| Severity | Committed cloud keys can be CRITICAL if valid path |

## Focus

- Hardcoded passwords/keys/tokens; secrets files (`.env*`, pem, credentials.json)
- TODO/FIXME about auth matching a **real** missing check
- Debug/dev mode toggleable in prod; unprotected `/debug` `/admin` `/metrics` `/env`
- `eval`/exec on user data (else file injection); CORS `*` + credentials patterns
- Open redirects; prod stack traces; AI-codegen smells (userId as auth)

## Hunt workflow

1. **Inventory** — exhaust greps for secrets, debug routes, redirects, cookie flags, verbose errors
2. **Trace** — each hit to impact (mounted route, loaded secret, reflected redirect)
3. **Prove** — real material / prod surface / sensitive value
4. **Evidence** — verified hits with citations; `write_evidence`
5. **Submit or none** — `weakness_class: obvious`, or honest `submit_none`

## Stack cues

```
password\s*=\s*['\"][^'\"]+['\"]|api[_-]?key|secret[_-]?key|BEGIN PRIVATE|AKIA|sk-
\.env|credentials\.json|\.pem|id_rsa
/admin|/debug|/test|/metrics|/env|/config|actuator|phpinfo
DEBUG\s*=\s*True|APP_ENV|development
eval\(|exec\(|child_process|os\.system|Function\(
redirect\(|returnUrl|next=|goto=|continue=
Access-Control-Allow-Origin.*\*|Allow-Credentials
traceback|stack.?trace|printStackTrace
TODO.*auth|FIXME.*validat|HACK.*security
```

## Required evidence

- Hits verified with impact; citations; for secrets, material is real/default-usable

## False positives

- Example secrets forced replace; debug under test packages only
- Missing HttpOnly on intentional CSRF cookie when session is HttpOnly
- Verbose errors only in gated debug builds

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| “Found TODO about security” | No missing check |
| Creativity contest | Pad after exhaust |
| Example secrets | Never loaded |
| CVE bingo | No reachable sink |
| Flag without impact | Hardening noise |

## Submit checklist

- `write_evidence` first listing hits verified with impact
- `weakness_class: obvious`
- **Good:** *“AWS key `AKIA…` in `deploy/settings.py:4` committed; full account access if valid.”*
- **Bad:** *“Found TODO about security.”*
- Or honest `submit_none`
