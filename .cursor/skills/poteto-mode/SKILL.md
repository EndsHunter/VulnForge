---
name: poteto-mode
description: >
  VulnForge-local poteto operator style: goal-and-proof, unslopped prose, and
  verified work on the cheap local path (vf CLI + verify-vulnforge). Use for
  /poteto-mode, poteto, potato mode, Forge boarding with rigor, or when an
  operator wants poteto non-negotiables without cloud agents or the full pstack
  plugin. Do not use for inventing exploits or claiming confirmed without human accept.
---

# Poteto mode (VulnForge)

Project-local slim of pstack **poteto-mode**. Same non-negotiables. Grounded in
**this** harness, not a second orchestrator.

For the full playbook library, principles leaves, swarm/arena, overnight, and
shipping stacks, install / invoke upstream pstack `poteto-mode`. This skill stays
short on purpose.

## When to use

- Operator wants `/poteto-mode` rigor on VulnForge work (docs, skills, cockpit proof, CLI).
- Cheap local path. Prefer `vf` + `.cursor/skills/verify-vulnforge` over cloud agents.
- Forge boarding or a PR that must prove claims without auto-merge theatre.

## When not to use

- Free-form audit essays that skip `PROTOCOL.md` / `vf`.
- Claiming `needs_human` or `confirmed` as exploit proof.
- Inventing PoCs, mutating the audit target, or auto-confirming findings.
- Duplicating hunt-class Mission/Method (those live in `config/hunt_profiles/`).

## Non-negotiables

Name the ones that changed a decision in your reply.

1. **Goal-and-proof.** State the goal, the done check that can pass or fail, and the proof surface. No done without evidence.
2. **Unslopped.** Short declarative sentences. No walls of text. PR bodies are briefings (Why / What changed / Scope / Verification).
3. **Verified.** Prove on the real surface. `vf status`, `harness.db`, verify-vulnforge doctor/drive artifacts, or absolute screenshot URLs. "It compiles" is not proof.
4. **Protocol over essays.** Durable truth is `harness.db`, `evidence/`, `inbox/`, `events.jsonl` via `vf`. Chat-only reports are not authority.
5. **Labels are honest.** `needs_human` ≠ exploit proof. `confirmed` is human-only and still not production exploit proof. Automation never auto-confirms.
6. **Cheap local first.** Prefer `.venv/bin/vf` and `.cursor/skills/verify-vulnforge`. Do not require cloud agents for ordinary operator proof.
7. **No target mutation.** Never edit application source to make a PoC pass. Evidence only under `evidence/`.
8. **Honest none.** Prefer `submit_none` / skip over inventing findings or dual-filing the same path+sink.

Cite only repo files and skills you actually read this session. Never fabricate links.

## Authority map

| Authoritative | Not authoritative |
|---------------|-------------------|
| `PROTOCOL.md`, `AGENTS.md`, `config/default.yaml` | Chat essays / free-written REPORT.md as truth |
| `harness.db` via `vf` | Hand-edited `project/*` |
| `evidence/` packs | Hunter self-grades |
| `.cursor/skills/verify-vulnforge` proof artifacts | HTTP GET of HTML alone as UI proof |
| Human HITL (`vf hitl respond` / Report Accept) | `validate_llm` / near-dup merge as confirm |

Related skills (call, do not rewrite):

- `skill/SKILL.md` (name `vulnforge`) — protocol client, filing, labels
- `.cursor/skills/verify-vulnforge` — cockpit + CLI operator proof
- Upstream pstack `poteto-mode` — full playbooks when this slim is not enough

## Harness today (do not invent stages)

Default pipeline (`AGENTS.md` / `PROTOCOL.md` / `config/default.yaml`):

```text
init → recon → hunt × N → validate_mech → validate_llm (default on)
     → idle project projection
     → [optional tool_gaps on idle if run.auto_tool_gaps]
```

| Stage / kind | What it is | Confirms? |
|--------------|------------|-----------|
| `recon` | Architecture map; enqueue hunts. Mechanical codemap is separate (`runs.codemap_json`) | No |
| `hunt` | Area × weakness class; `submit_candidate` or `submit_none` | No |
| `validate_mech` | Schema, citations, evidence or justified `no_poc`, threat model, manifest | No → `needs_human` or `rejected_mech` |
| `validate_llm` | Dual disprove (default **on**). Demote only → `rejected_llm` or stay `needs_human` | **Never** auto-confirm |
| HITL / Report | Human accept → `confirmed`; reject → `rejected_human` | Human only |
| `develop_poc` / `validate_poc` / `iterate_poc` | Operator PoC workshop / sandbox one-shot / iterate | **Never** confirm; sandbox opt-in (`poc_harness.sandbox_oneshot` default false) |

Finding states (honest):

```text
candidate → rejected_mech | needs_human
needs_human → [validate_llm] rejected_llm | needs_human
needs_human | rejected_* | confirmed  ↔  human review
```

## Tools and submit contracts (operator-facing)

`code_static` only. No shell on the default profile. Paths relative to the audit target (or evidence pack for `write_evidence`).

Hunt finishers:

- `submit_candidate` — title, summary, weakness_class, threat_model, citations, session `evidence_id` from `write_evidence`. Optional `preflight_candidate` first.
- `submit_none` — required honesty when nothing solid after real work.

Outside the tool loop:

```bash
vf apply-candidate --file inbox/x.json --run-dir <dir>
```

Shape: `fixtures/inbox_candidate.example.json`. Mech pass needs `evidence_id` with a pack under `run_dir/evidence/<id>/` **or** `no_poc: true` + `no_poc_justification` (≥20 chars). Prefer real evidence. Apply does not require same-session `write_evidence` (disk pack is enough).

Exploitability bar and exclusion gates: `seeds/system/PRINCIPLES.md` (REACHABLE / UNMITIGATED / CONCRETE / IN SCOPE / CITED). Do not restate the whole bar here.

## Cheap local operator loop

1. Work from the VulnForge repo root. Ensure `.venv` and `vf`.
2. For product/UI/CLI proof, use verify-vulnforge (isolated runs-root; never operator `runs/`):

```bash
.cursor/skills/verify-vulnforge/scripts/vf-verify launch
eval "$(.cursor/skills/verify-vulnforge/scripts/vf-verify env)"
.cursor/skills/verify-vulnforge/scripts/vf-verify doctor --write
# drive one mapped feature; capture artifacts
.cursor/skills/verify-vulnforge/scripts/vf-verify stop
```

3. For a real audit run (when the task is hunting, not cockpit verify):

```bash
.venv/bin/vf init --target <path>
.venv/bin/vf run-once --run-dir runs/<target_id>/<run_id>
# or: python scripts/ralph.py --run-dir ... --task-timeout 900 --max-tasks 50
# or: vf dashboard → http://127.0.0.1:8787
.venv/bin/vf status --run-dir ...
.venv/bin/vf hitl inbox --run-dir ...
```

4. Regenerate views with `vf project`. Never hand-edit `project/` as truth.
5. Stuck? `vf status` + `events.jsonl` (`failed_task` thrash vs `failed_infra` / `deadletter`).

Do **not** click Start / Resume / Hard stop / Delete / Save settings / Reseed during verify-vulnforge drives (see that skill). Sandbox PoC stays opt-in.

## Decision tree

```text
Need poteto rigor on VulnForge?
├─ Prove cockpit / CLI feature → verify-vulnforge playbook path
├─ Drive or interpret a hunt run → skill/SKILL.md + PROTOCOL.md via vf
├─ File a candidate outside the tool loop → apply-candidate + PRINCIPLES.md
├─ Open a docs/skill PR → playbooks/opening-a-pr.md (this skill)
└─ Full pstack playbook (babysit, shipping stack, overnight) → upstream poteto-mode
```

```text
About to claim "done"?
├─ Have a pass/fail done check + artifact? → report with evidence
└─ No → keep working or say what is blocked (not a fake green)
```

```text
About to talk about a finding label?
├─ needs_human → mechanical (+ optional disprove hold). Not exploit proof
├─ confirmed → human accepted. Still not exploit proof
└─ validate_llm / sandbox PoC / develop_poc → never treat as confirm
```

## Writing the reply (adapted)

- Short declarative sentences. One thought per sentence.
- Every claim carries its evidence or its label in the same sentence (measured, inferred, or guess).
- Frame impact for the operator and the next maintainer before implementation detail.
- Never invent exploits, CVEs, or PoC payloads for demo.
- PR link form when you open one: `https://github.com/EndsHunter/VulnForge/pull/<number>`.

## Playbooks (local)

Open a todolist whose first items are the matched playbook's steps. Skip with `skip: <reason>`.

| Playbook | When |
|----------|------|
| `playbooks/opening-a-pr.md` | End of code/docs/skill work that ships as a PR |
| `playbooks/verify-then-merge.md` | Before calling a change Ready / asking Ops to merge |

Need Investigation / Bug fix / Feature / Babysit / Shipping / Autopilot? Use upstream pstack poteto-mode playbooks. Keep VulnForge honesty rules when those cross this repo.

## Forge / Ops boarding notes

When preparing work for Forge (not when this skill alone runs a PR):

- **Grok build medium** for skill/docs boarding unless Ops says otherwise.
- **Do not merge** — leave open for Jonathan / Ops.
- **Gauge QA:** N/A for docs/skills-only unless Jonathan asks for a glance.
- Screenshots in PR body **and** a PR comment use **absolute** `raw.githubusercontent.com` URLs pinned to the PR head SHA. Never relative `docs/` paths alone in the PR description.

## Anti-patterns

| Anti-pattern | Why |
|--------------|-----|
| Treating this skill as a second harness | Protocol is `vf` / PROTOCOL.md |
| Equating `needs_human` with confirmed or exploit-proven | Label honesty |
| Requiring cloud agents for ordinary verify | Cheap local path |
| Vendoring entire upstream poteto | Drift + noise; link out |
| Long audit markdown labeled confirmed | Skips mech + human |
| Editing the target to pass a PoC | Corrupts evidence |
| Relative image paths only in PR descriptions | Standing EndsHunter bar |

## Scope

Covers **how** an operator/agent works on VulnForge with poteto rigor.

Out of scope: hunt-class bodies, toolgen integrate apply, mutating targets, claiming production exploit proof, merging without human/Ops.
