---
name: client-side
description: >-
  Hunts XSS and other browser-victim bugs, including server-rendered HTML that
  reflects request data into the response, and DOM sinks. Use when grepping
  res.send/res.write/echo/print of query or body, innerHTML/dangerouslySetInnerHTML/
  v-html, postMessage origin checks, CORS+credentials, WebSocket auth, open
  redirects, clickjacking of state-changing frames, or prototype pollution with
  a security gadget. Prefer victim impact over “no CSP header.”
  Activation: surface-triggered via hunt_focus when SPA/DOM/HTML-XSS/CORS/
  clickjack surfaces exist (e.g. Juice Shop–style) — inactive under B0 hybrid.
---

# Hunt class: client-side

## Principles

- **Prefer evidence over pre-training.** Cite source and sink you actually traced in JS/HTML.
- **Be certain.** Framework auto-escape may neutralize — read the full path including opt-outs.
- **Provide evidence.** Source→sink citations with `start_line` on the executing sink; victim context; session/data impact.
- **Correctness over completeness.** One reflected XSS with a victim browser beats CSP checklist.
- Honest `submit_none` when HTML/DOM sinks are encoded end-to-end.
- **Planner:** include this class when browser/HTML/DOM/CORS/clickjack surfaces exist (inactive-ok).

## When to use

- Server HTML responses that concatenate `req.query` / `$_GET` / body into `res.send`, `res.write`, `echo`, `print`, `render` without context encoding
- SPAs, extensions, webviews, DOM sinks, CORS with credentials, WebSockets
- postMessage weak origin; clickjacking surfaces; client open redirect
- Prototype pollution **with** security gadget; DOM clobbering into sinks

### Activation criteria (planner / Juice Shop–style)

**Include `client-side` in `hunt_focus` when ANY of:**

- Server templates or handlers reflecting request data into HTML (`res.send`/`echo`/`render`/`<%=` with query/body)
- SPA/DOM sinks: `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrust*`, `document.write`
- CORS middleware reflecting Origin / `null` **with** credentials
- postMessage handlers without strict origin allowlist touching sensitive state
- State-changing GET forms/pages framable under missing XFO / `ALLOWALL` / `*` / weak CSP `frame-ancestors`
- Lab/challenge maps listing XSS, DOM XSS, CSP bypass, video/header XSS (Juice Shop family)

**Collection:** keep `active: false` under hybrid; surface-triggered via focus (not blanket-on).

## When not to use / Scope

- Missing CSP/XFO alone without a framable control. `X-Frame-Options: ALLOWALL` or `*` is not protection. A GET that renders a POST form (transfer, delete, grant) with ALLOWALL/missing XFO **is** a clickjacking candidate even when the POST body is HTML-escaped.
- Client-side “missing authz” (server is authority)
- Framework auto-escape with no opt-out on the path; attacker-only self-XSS without victim delivery
- Do **not** `submit_none` just because the HTML is built on the server. A victim browser still executes reflected markup.
- Related skills: `injection` for SQL/OS/eval/SSTI interpreters (not HTML XSS); `web-protocol-auth` for cookie/session protocol; `access-control` for server authz; `ai-llm` for agent tools

## Decision tree

```
1. Grep HTML/DOM sinks first (res.send/echo/innerHTML/render), walk args to request data
2. Name controllable SOURCE and executing SINK (cite start_line on sink)
3. Impact hits a VICTIM BROWSER (script in HTML), session, or cross-origin data?
4. Framework escape hatches (dangerouslySetInnerHTML, v-html, bypassSecurityTrust*)?
5. postMessage/WS origin auth; CORS reflection + credentials
6. Clickjack: framable GET of state-changing UI (ALLOWALL/* = no deny)
7. Sinks encoded end-to-end → submit_none
```

## Rules quick reference

| Rule | Summary |
|------|---------|
| Victim required | Attacker’s own page only is not the finding |
| Server HTML XSS | `res.send('<h1>'+q)` / `echo $_GET[x]` is in-scope reflected XSS |
| Source→sink | Both ends cited; transforms noted; `start_line` on sink |
| Escape hatches | React/Vue/Angular unsafe APIs are prime |
| postMessage | Origin allowlist; no `*` with sensitive handlers |
| CORS+creds | Reflected origin or null + credentials is impact |
| CSWSH | Cookie auth on WS without origin checks |
| Pollution | Recursive write **and** reachable gadget |
| Clickjack | Framable GET of a state-changing form. `ALLOWALL`/`*` counts as no XFO |
| Redirect | Client open redirect with token/session impact |
| CSP alone | Missing CSP is hardening, not a finding |
| Surface trigger | Planner includes class when XSS/CORS/DOM/clickjack inventory exists |

## Focus

- Reflected/stored XSS in server-built HTML (`res.send`, `echo`, unescaped `res.render`)
- DOM XSS (location/hash/search, postMessage, cookie → innerHTML/eval/…)
- DOM clobbering; postMessage weak origin; CSWSH
- CORS+credentials reflection/weak suffix/`null`
- Clickjacking on state-changing framable actions
- Client open redirect; prototype pollution with security gadget

## Hunt workflow

1. **Inventory** — grep HTML response sinks and DOM sinks, postMessage, CORS, WS, frame headers
2. **Trace** — sink → source; framework escape hatches; origin checks
3. **Prove** — victim/cross-origin impact; pollution gadget if claimed; clickjack framability
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

- **Source and sink citations** with `start_line` on the executing sink (`innerHTML`/`res.send`/`echo`/…), not only a template string assignment
- **Victim context:** how a victim browser/session is reached (link, stored page, framed GET, cross-origin read)
- **Impact named:** session theft, CSRF-like state change, cross-origin data leak, account action — not “XSS exists”
- **Transforms noted:** encoding/sanitizer bypass or missing context encode
- For CORS: reflected/null Origin **and** credentials (or equivalent data impact)
- For clickjack: framability proof (missing/ALLOWALL/`*` / weak frame-ancestors) **and** state-changing UI
- For pollution: recursive write **and** reachable security gadget
- `write_evidence` before `submit_candidate`

## False positives

- Framework auto-escape without opt-out
- Missing CSP/XFO alone; postMessage with strict origin allowlist
- Pollution without reachable gadget
- Tabnabbing/XS-Leaks without extreme confidence
- Self-XSS without victim delivery path
- “XFO is set” when value is ALLOWALL/`*` (not a deny)

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| “No CSP header” | Hardening, not a finding alone |
| “Server-side, so not XSS” | Victim browser still runs reflected HTML |
| Self-XSS only | No victim delivery path |
| Client authz | Server is authority |
| Pollution theory | No gadget = no impact |
| Ignoring sanitizers | False positives on cleaned paths |
| Omitting class on Juice Shop–like XSS maps | B0 inactive miss; planner must name client-side |

## Submit checklist

- `write_evidence` first with source→sink and victim context
- `weakness_class: client-side`
- **Good:** *“`req.query.name` concatenated into `res.send` HTML; victim browser executes markup.”*
- **Good:** *“`#` fragment → `innerHTML` in `app.js:210`; non-HttpOnly session cookie steals via victim link.”*
- **Good:** *“GET form POSTs `to`/`n` and sets `X-Frame-Options: ALLOWALL`; victim can be framed into transferring funds.”*
- **Bad:** *“No CSP header.”* / *“This is server-side so I submit_none.”* / *“XFO is set so no clickjack”* (ALLOWALL/`*` is not a deny).
- Or honest `submit_none`
