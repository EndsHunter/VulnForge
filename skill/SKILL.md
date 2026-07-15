---
name: vulnforge
description: >
  Local vulnerability discovery harness (Cloudflare-style audit discipline + durable state).
  Use when asked to security audit a codebase, find vulnerabilities, run vulnforge, pen-test
  source with LM Studio / local models, drive vf / Ralph / the dashboard, author or apply hunt
  skills, file candidates via apply-candidate, or interpret needs_human vs confirmed labels.
  Prefer the vf CLI protocol and PROTOCOL.md over free-form audit essays. Do not use for
  general app feature work unrelated to hunting, or for claiming exploit-proven findings
  without human accept.
---

# vulnforge skill

You are a client of the **vulnforge protocol** (`PROTOCOL.md` / `AGENT.md` in the harness repo).
Do not invent a second orchestrator. Prefer `vf` / Ralph / dashboard over free-form audit essays.

## Principles

- **Protocol over essays.** Durable truth lives in `harness.db`, `evidence/`, `inbox/`, and `events.jsonl` via `vf` — not chat-only reports.
- **Be certain.** Cite files you read; no speculative cloud / out-of-tree claims.
- **Labels are honest.** `needs_human` ≠ exploit proof; `confirmed` is human-only and still not production-ready proof.
- **One concrete action + effect.** Filing requires attacker does X → system does Y, with citations.
- **Honest none.** Prefer `submit_none` over inventing findings or dual-filing the same path+sink.
- **No target mutation.** Do not edit application source to make a PoC pass.

Follow `prompts/v1/PRINCIPLES.md` for the full exploitability bar, threat model, and exclusion gates (REACHABLE / UNMITIGATED / CONCRETE / IN SCOPE / CITED).

## Authority

| Authoritative | Not authoritative |
|---------------|-------------------|
| `harness.db` via `vf` commands | Free-written `REPORT.md` / chat essays |
| `evidence/` packs | Chat-only claims without citations |
| `inbox/*.json` applied via `vf apply-candidate` | Hunter self-grades |
| `events.jsonl` | Hand-edited `project/*` as "truth" |

## Labels (honesty)

- **`needs_human`** = passed **mechanical gates** (shape, citations, evidence pack or justified `no_poc`, threat model non-vacuous, manifest check). **Not** exploit proof.
- **`confirmed`** = a **human** accepted the finding after review. Automation never auto-confirms. Still **not** exploit proof.
- **`rejected_mech`** = failed mechanical gates.
- Optional `validate_llm` (default off) may demote to `rejected_llm` only — weak same-model signal, never auto-confirm.
- Prefer honest `submit_none` over inventing findings.

## Rules quick reference

### Surfaces & truth

| Rule | Summary |
|------|---------|
| Protocol CLI | Prefer `vf` / Ralph / dashboard over free-form audit markdown |
| Durable state | Truth is `harness.db` + evidence packs + events — not chat |
| project/ views | Regenerate with `vf project`; never hand-edit as truth |
| Config | LM Studio / models via `config/default.yaml` and/or dashboard Settings |

### Filing candidates

| Rule | Summary |
|------|---------|
| Citations | Real file:line (or path+symbol) you read in-tree |
| Evidence | `write_evidence` → `evidence_id`, or `no_poc` + ≥20-char justification on apply |
| Threat model | Non-vacuous who/boundary/impact on the candidate |
| One class | One path+sink → one `weakness_class` (most specific profile) |
| Class ids | Only registered hunt skill collection ids — do not invent |

### Labels & review

| Rule | Summary |
|------|---------|
| needs_human | Mechanical pass only — not exploit proof |
| confirmed | Human accept only — automation never auto-confirms |
| validate_llm | Optional demote only; never auto-confirm |
| submit_none | Required honesty when nothing solid after real work |

## Decision tree (which surface to use)

```
Need durable hunt state?
├─ Yes → vf init / run-once / ralph / dashboard  (PROTOCOL)
│        └─ Findings only via submit_candidate / apply-candidate → mech gates → human
└─ No, one-off advice?
   └─ Still follow PRINCIPLES.md exploitability bar; do not claim confirmed
```

```
Driving a run?
├─ New target → vf init --target <path>
├─ Drain queue → vf run-once | ralph | dashboard Start
├─ Operator hunt focus → Coverage / requeue with class + path_hints
├─ Custom hunt skill → Dev dashboard / generate skill (collection, not free-form essay)
└─ Stuck → vf status + events.jsonl (failed_task thrash vs failed_infra / deadletter)
```

```
Filing a candidate?
├─ Have source→sink (or single-site) citations you read?
│  ├─ Yes + write_evidence (or no_poc + justification) → submit_candidate / apply-candidate
│  └─ No → do not emit; gather proof or submit_none
└─ Dual-class temptation?
   └─ One path+sink → one weakness_class (most specific profile wins)
```

See **PROTOCOL.md** for CLI contracts and **AGENT.md** for operator/agent roles when present in the repo.

## Workflow

1. Ensure harness repo available; config points at LM Studio (`config/default.yaml` and/or dashboard Settings → `config/ui_settings.json`).
2. `vf init --target <path>` if no run exists (prints `runs/<target_id>/run-00N`).
3. Drive progress:
   - `vf run-once --run-dir <dir>` one task at a time, or
   - `python scripts/ralph.py --run-dir <dir> --task-timeout 900 --max-tasks 50`, or
   - `vf dashboard` → open run → **Start** (http://127.0.0.1:8787).
4. If drafting outside the model tool loop: write candidate JSON (see `fixtures/inbox_candidate.example.json`), then `vf apply-candidate --file <path> --run-dir <dir>`.
5. Regenerate human views with `vf project --run-dir <dir>` — do not hand-edit `project/` as truth.
6. Check `vf status --run-dir <dir>` and `events.jsonl` when stuck (`failed_task` thrash vs `failed_infra` / `deadletter`).

## Hunt skills

- Operator collection: `config/hunt_profiles/` (bodies + `collection.json` metadata; path kept for compatibility).
- Package seeds: `prompts/v1/hunt_classes/` (reseed replaces the collection).
- Each skill body (Cloudflare-aligned): trigger-rich description, Mission/Principles, Rules quick reference, Anti-patterns table, Hunt workflow/Method, Scope, Submit checklist (+ focus, stack cues, evidence rails).
- Metadata drives angles (`angle_ids`), sink routing (`sink_families`), and cross-class merge rank (`specificity`).
- **Active** skills bulk-enqueue when recon omits `hunt_focus`.
- Author prompt: `prompts/v1/generate_skill.md` (override: `config/prompts/generate_skill.md`).

## apply-candidate notes

- Body must include title, summary, weakness_class, threat_model, citations.
- For mech pass: provide `evidence_id` with a pack under `run_dir/evidence/<id>/` **or** `no_poc: true` + `no_poc_justification` (≥20 chars). The `no_poc` path is an intentional exception; prefer real evidence.
- Unlike hunt `submit_candidate`, apply does **not** require a same-session `write_evidence` (disk pack is enough for mech).

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| Long markdown “audit report” labeled confirmed | Skips mech gates + human accept; false certainty |
| Treating `confirmed` as exploit-proven | Label is human accept only — not production proof |
| Equating `needs_human` with `confirmed` | Mechanical pass ≠ human-reviewed |
| Editing app source to make a PoC pass | Target mutation; corrupts evidence |
| Skipping `submit_none` when nothing found | Invented findings / checklist spam |
| Dual-filing same path+sink under two classes | Noise, merge thrash, dishonest specificity |
| Expecting `validate_llm` / gapfill / dedup to prove exploit | Deferred stages are not exploit proof |
| Inventing class ids outside the collection | Broken routing; rejected or orphan findings |

## Scope

This skill covers **operating VulnForge** as a coding-agent client: init/run, filing candidates, labels, hunt skills, and protocol honesty.

Related surfaces (not separate inventable class ids):

- **PROTOCOL.md / AGENT.md** — CLI contracts and operator/agent roles
- **prompts/v1/PRINCIPLES.md** — exploitability bar shared by all hunters
- **Hunt skills** (`config/hunt_profiles/`, `prompts/v1/hunt_classes/`) — per-class Mission/Method; do not restate them here
- **Dev generate skill** — authors new profile bodies via `generate_skill.md`; still protocol-bound

Out of scope: general product feature development, mutating targets for demo PoCs, or claiming production-ready exploit proof without human review.

## Optional skill install

Copy or link this file into your agent skills directory when desired (e.g. project `skill/` is the source of truth in-repo). Wiring to global `~/.grok/skills` is optional operator setup, not required for CLI use.
