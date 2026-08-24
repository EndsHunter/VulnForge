---
name: feature-abuse
description: >-
  Hunts abuse of legitimate features (export, search, webhooks, previews, import)
  for over-access, integrity break, or SSRF — design gaps, not only coding bugs.
  Use when reviewing backup/export, import/restore, search/filter order_by,
  webhook/callback/avatar URLs, share tokens, or report/print jobs. Prefer
  host/scheme control for SSRF and missing tenant scope for exfil over
  “export exists.”
---

# Hunt class: feature-abuse

## Principles

- **Prefer evidence over pre-training.** Cite feature entrypoints and scope checks you read.
- **Be certain.** SSRF needs host/scheme control; path-only is usually not enough.
- **Provide evidence.** Role + feature action + data/effect gained; file:line.
- **Correctness over completeness.** One over-scoped export beats missing rate-limit notes.
- Honest `submit_none` when features correctly scope data and outbound URLs.

## When to use

- Export/backup, import/restore, search/filter, webhooks/callbacks
- Preview/share tokens, report/print, notification/email content assembly
- URL/file params reaching HTTP clients or FS without allowlist

## When not to use / Scope

- User can export **their own** correctly scoped data
- SSRF claims where only path is user-controlled (host fixed)
- Missing rate limit alone without data leak or state change
- Related skills: `access-control` for pure IDOR on simple CRUD; `injection` for interpreter sinks; `web-protocol-auth` for Host/header framing; `supply-chain` for install-time trust

## Decision tree

```
1. From architecture, list powerful features
2. For each: what can a LOWER role force the system to fetch, emit, or overwrite?
3. Diff permission checks on UI vs API vs job/worker
4. Trace URL/file params to HTTP client or FS without allowlist
5. Features correctly scope data and outbound URLs → submit_none
```

## Rules quick reference

| Rule | Summary |
|------|---------|
| Feature as weapon | Legitimate API, illegitimate scope |
| Lower role | What can member/guest force vs admin intent |
| SSRF host/scheme | Path-only control is usually insufficient |
| Export scope | Tenant/owner filters on the query, not the UI |
| Import integrity | Privileged objects created without authz |
| Search oracle | Existence or secret-field order_by leaks |
| Share tokens | Over-broad or weak re-check on access |
| Job path | Async workers may skip request middleware |
| Allowlist | Webhook URLs fixed to vendor schemes/hosts |
| Impact | Exfil, SSRF, integrity overwrite, enumeration |
| Cite the sink | `citations[].symbol` is the function/const that performs the fetch or export |

## Focus

- Export/backup as exfil beyond role/tenant
- Import/restore creating privileged objects without authz
- Search as existence oracle or secret-field `order_by`
- Enumeration via reset/invite/register messages
- Preview/share tokens too broad; SSRF via webhook/avatar/callback URL
- Notification/email leaks; weak re-check on share links

## Hunt workflow

1. **Inventory** — powerful features from architecture and route names
2. **Trace** — permission diffs UI vs API vs worker; URL/file params to clients
3. **Prove** — lower role forces over-scope fetch/emit/overwrite
4. **Evidence** — entrypoint, missing scope, sequence, impact; `write_evidence`
5. **Submit or none** — `weakness_class: feature-abuse`, or honest `submit_none`

## Stack cues

```
export|download|backup|dump|csv|report|bulk
import|restore|upload|parse.*csv|zipfile
webhook|callback_url|notify_url|avatar_url|requests\.(get|post)|httpx\.
preview|draft|staging|share_token|public_link|signed_url
search|filter|order_by|sort=
```

## Required evidence

- Feature entrypoint, missing scope, abuse sequence, impact
- `citations[].path`, `start_line`, and `symbol` (the sink function or const name)
- `sink_path` and `sink_symbol` on the candidate matching that citation

## False positives

- Own-data export; webhook URLs fixed to vendor allowlist
- Search only over already-authorized sets
- Missing secondary control when primary permission already holds

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| “Export exists” | No over-scope proof |
| SSRF path-only | Host/scheme fixed → weak claim |
| Rate limit alone | No data/state impact |
| Ignoring workers | Job path may be the weak gate |
| Dual CRUD IDOR | Prefer `access-control` if pure object authz |

## Submit checklist

- `write_evidence` first: feature entrypoint, missing scope, sequence, impact
- `weakness_class: feature-abuse`
- Citations **must** include `symbol` for the sink (function or const that fetches, exports, or follows the URL)
- **Good:** *“Member `POST /export` omits `tenant_id` (`export.py:55`, symbol `export_csv`); CSV includes peer PII.”*
- **Good:** *“`callback_url` → `fetch_webhook` (`webhooks.js:40`); host and scheme are attacker-controlled.”*
- **Bad:** *“Export exists.” / citations with path but no `symbol`.*
- Or honest `submit_none`
