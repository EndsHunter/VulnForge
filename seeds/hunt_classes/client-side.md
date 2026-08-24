---
name: client-side
description: >-
  Hunts XSS and other browser-victim bugs, including server-rendered HTML that
  reflects request data into the response, and DOM sinks. Use when grepping
  res.send/res.write/echo/print of query or body, innerHTML/dangerouslySetInnerHTML/
  v-html, postMessage origin checks, CORS+credentials, WebSocket auth, open
  redirects, clickjacking of state-changing frames, or prototype pollution with
  a security gadget. Prefer victim impact over “no CSP header.”
---

# Hunt class: client-side

## Principles

- **Prefer evidence over pre-training.** Cite source and sink you actually traced in JS/HTML.
- **Be certain.** Framework auto-escape may neutralize — read the full path including opt-outs.
- **Provide evidence.** Source→sink citations; victim context; session/data impact.
- **Correctness over completeness.** One reflected XSS with a victim browser beats CSP checklist.
- Honest `submit_none` when HTML/DOM sinks are encoded end-to-end.

## When to use

- Server HTML responses that concatenate `req.query` / `$_GET` / body into `res.send`, `res.write`, `echo`, `print`, `render` without context encoding
- SPAs, extensions, webviews, DOM sinks, CORS with credentials, WebSockets
- postMessage weak origin; clickjacking surfaces; client open redirect
- Prototype pollution **with** security gadget; DOM clobbering into sinks

## When not to use / Scope

- Missing CSP/XFO alone without a framable control. `X-Frame-Options: ALLOWALL` or `*` is not protection. A GET that renders a POST form (transfer, delete, grant) with ALLOWALL/missing XFO **is** a clickjacking candidate even when the POST body is HTML-escaped.
- Client-side “missing authz” (server is authority)
- Framework auto-escape with no opt-out on the path; attacker-only self-XSS without victim delivery
- Do **not** `submit_none` just because the HTML is built on the server. A victim browser still executes reflected markup.
- Related skills: `injection` for SQL/OS/eval/SSTI interpreters (not HTML XSS); `web-protocol-auth` for cookie/session protocol; `access-control` for server authz; `ai-llm` for agent tools

## Decision tree

```
1. Grep HTML/DOM sinks first (res.send/echo/innerHTML/render), walk args to request data
2. Name controllable SOURCE and executing SINK
3. Impact hits a VICTIM BROWSER (script in HTML), session, or cross-origin data?
4. Framework escape hatches (dangerouslySetInnerHTML, v-html, bypassSecurityTrust*)?
5. postMessage/WS origin auth; CORS reflection + credentials
6. Sinks encoded end-to-end → submit_none
```

## Rules quick reference

| Rule | Summary |
|------|---------|
| Victim required | Attacker’s own page only is not the finding |
| Server HTML XSS | `res.send('<h1>'+q)` / `echo $_GET[x]` is in-scope reflected XSS |
| Source→sink | Both ends cited; transforms noted |
| Escape hatches | React/Vue/Angular unsafe APIs are prime |
| postMessage | Origin allowlist; no `*` with sensitive handlers |
| CORS+creds | Reflected origin or null + credentials is impact |
| CSWSH | Cookie auth on WS without origin checks |
| Pollution | Recursive write **and** reachable gadget |
| Clickjack | Framable GET of a state-changing form. `ALLOWALL`/`*` counts as no XFO |
| Redirect | Client open redirect with token/session impact |
| CSP alone | Missing CSP is hardening, not a finding |

## Focus

- Reflected/stored XSS in server-built HTML (`res.send`, `echo`, unescaped `res.render`)
- DOM XSS (location/hash/search, postMessage, cookie → innerHTML/eval/…)
- DOM clobbering; postMessage weak origin; CSWSH
- CORS+credentials reflection/weak suffix/`null`
- Clickjacking on state-changing framable actions
- Client open redirect; prototype pollution with security gadget

## Hunt workflow

1. **Inventory** — grep HTML response sinks and DOM sinks, postMessage, CORS, WS
2. **Trace** — sink → source; framework escape hatches; origin checks
3. **Prove** — victim/cross-origin impact; pollution gadget if claimed
4. **Evidence** — source→sink + victim context; `write_evidence`
5. **Submit or none** — `weakness_class: client-side`, or honest `submit_none`

## Stack cues

```
res\.send\(|res\.write\(|res\.end\(|echo |print\(
innerHTML|outerHTML|document\.write|insertAdjacentHTML|eval\(|new Function
dangerouslySetInnerHTML|v-html|bypassSecurityTrust|domSanitizer|DOMPurify
postMessage|onmessage|event\.origin|targetOrigin
location\.hash|location\.search|document\.URL|window\.name
WebSocket|wss://
Access-Control-Allow-Origin|Allow-Credentials|cors\(
__proto__|prototype|merge\(|defaultsDeep
X-Frame-Options|ALLOWALL|frame-ancestors|Content-Security-Policy
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
| “Server-side, so not XSS” | Victim browser still runs reflected HTML |
| Self-XSS only | No victim delivery path |
| Client authz | Server is authority |
| Pollution theory | No gadget = no impact |
| Ignoring sanitizers | False positives on cleaned paths |

## Submit checklist

- `write_evidence` first with source→sink and victim context
- `weakness_class: client-side`
- **Good:** *“`req.query.name` concatenated into `res.send` HTML; victim browser executes markup.”*
- **Good:** *“`#` fragment → `innerHTML` in `app.js:210`; non-HttpOnly session cookie steals via victim link.”*
- **Bad:** *“No CSP header.” / “This is server-side so I submit_none.”*
- Or honest `submit_none`
