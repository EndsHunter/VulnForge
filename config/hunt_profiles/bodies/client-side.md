---
name: client-side
description: >-
  Hunts browser/webview trust bugs where a victim session or cross-origin data
  is hit via source→DOM sink. Use when grepping innerHTML/dangerouslySetInnerHTML/
  v-html, postMessage origin checks, CORS+credentials, WebSocket auth, open
  redirects, clickjacking of state-changing frames, or prototype pollution with
  a security gadget. Prefer victim impact over “no CSP header.”
---

# Hunt class: client-side

## Principles

- **Prefer evidence over pre-training.** Cite source and sink you actually traced in JS/HTML.
- **Be certain.** Framework auto-escape may neutralize — read the full path including opt-outs.
- **Provide evidence.** Source→sink citations; victim context; session/data impact.
- **Correctness over completeness.** One DOM XSS with session theft beats CSP checklist.
- Honest `submit_none` when sinks are safe end-to-end.

## When to use

- SPAs, extensions, webviews, DOM sinks, CORS with credentials, WebSockets
- postMessage weak origin; clickjacking surfaces; client open redirect
- Prototype pollution **with** security gadget; DOM clobbering into sinks

## When not to use / Scope

- Missing CSP/XFO alone without sensitive framable action or XSS sink
- Client-side “missing authz” (server is authority)
- Framework auto-escape with no opt-out on the path; attacker-only self-XSS without victim delivery
- Related skills: `injection` for server template/code sinks; `web-protocol-auth` for cookie/session protocol; `access-control` for server authz; `ai-llm` for agent tools

## Decision tree

```
1. Grep sinks first; walk args back to client sources
2. Name controllable SOURCE and executing SINK
3. Impact hits VICTIM SESSION or CROSS-ORIGIN data?
4. Framework escape hatches (dangerouslySetInnerHTML, v-html, bypassSecurityTrust*)?
5. postMessage/WS origin auth; CORS reflection + credentials
6. Sinks safe end-to-end → submit_none
```

## Rules quick reference

| Rule | Summary |
|------|---------|
| Victim required | Attacker’s own page only is not the finding |
| Source→sink | Both ends cited; transforms noted |
| Escape hatches | React/Vue/Angular unsafe APIs are prime |
| postMessage | Origin allowlist; no `*` with sensitive handlers |
| CORS+creds | Reflected origin or null + credentials is impact |
| CSWSH | Cookie auth on WS without origin checks |
| Pollution | Recursive write **and** reachable gadget |
| Clickjack | State-changing framable action, not “no XFO” alone |
| Redirect | Client open redirect with token/session impact |
| CSP alone | Missing CSP is hardening, not a finding |

## Focus

- DOM XSS (location/hash/search, postMessage, cookie → innerHTML/eval/…)
- DOM clobbering; postMessage weak origin; CSWSH
- CORS+credentials reflection/weak suffix/`null`
- Clickjacking on state-changing framable actions
- Client open redirect; prototype pollution with security gadget

## Hunt workflow

1. **Inventory** — grep DOM sinks, postMessage, CORS config, WS constructors
2. **Trace** — sink → source; framework escape hatches; origin checks
3. **Prove** — victim/cross-origin impact; pollution gadget if claimed
4. **Evidence** — source→sink + victim context; `write_evidence`
5. **Submit or none** — `weakness_class: client-side`, or honest `submit_none`

## Stack cues

```
innerHTML|outerHTML|document\.write|insertAdjacentHTML|eval\(|new Function
dangerouslySetInnerHTML|v-html|bypassSecurityTrust|domSanitizer|DOMPurify
postMessage|onmessage|event\.origin|targetOrigin
location\.hash|location\.search|document\.URL|window\.name
WebSocket|wss://
Access-Control-Allow-Origin|Allow-Credentials|cors\(
__proto__|prototype|merge\(|defaultsDeep
```

## Required evidence

- Source→sink citations; victim context; impact (session theft, CSRF-like action, data leak)

## False positives

- Framework auto-escape without opt-out
- Missing CSP/XFO alone; postMessage with strict origin allowlist
- Pollution without reachable gadget
- Tabnabbing/XS-Leaks without extreme confidence

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| “No CSP header” | Hardening, not a finding alone |
| Self-XSS only | No victim delivery path |
| Client authz | Server is authority |
| Pollution theory | No gadget = no impact |
| Ignoring sanitizers | False positives on cleaned paths |

## Submit checklist

- `write_evidence` first with source→sink and victim context
- `weakness_class: client-side`
- **Good:** *“`#` fragment → `innerHTML` in `app.js:210`; non-HttpOnly session cookie steals via victim link.”*
- **Bad:** *“No CSP header.”*
- Or honest `submit_none`
