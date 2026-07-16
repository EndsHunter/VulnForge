# Plan: Operator Control Pack

**Date:** 2026-07-15  
**Repo:** VulnForge  
**Status:** Validated inventory (explore subagents) → implementation plan  

This plan covers run-scoped hunt skill modes, richer recon re-run, findings overlap tooling, attack-chain builder, coverage-queue cleanup, Dev default tools, seed/default skill provenance, architecture history/edit, and hunt architecture context.

---

## Validation matrix (what exists today)

| # | Request | Status | Evidence |
|---|---------|--------|----------|
| 1 | Start run with **default vs custom-only** hunt skills | **Missing** | `InitBody` / `vf init` have recon agents + `dynamic_skills` only; profile `source` is metadata; `active_class_ids()` is global and not source-filtered |
| 2 | Re-run Recon: pick recon agents + enable custom hunt skills | **Partial** | Mission **Operator re-run** already has agent multi-select, brief, focus paths, prior-arch, enqueue-hunts / arch-only (`app.js` `renderOperatorRerunCard`, `ops.requeue_recon`). **No** hunt-skill mode / custom-only picker |
| 3 | Report overlap checker + merge / 1A–1B | **Partial** | Auto `merge_near_duplicate` on hunt insert; `stable_key` upsert; unused `merge_findings`; Report near-dup badge only — no cluster UI or operator merge |
| 4 | Post-run **attack chain builder** (confirmed / + needs_human) | **Missing** | Per-finding PoC workshop + `develop_poc` exist; no multi-finding chain model/UI |
| 5 | Remove **~40 hunt cap** on Coverage | **Backend done / UI stale** | `ops.apply_coverage_mode` uses `run.max_tasks`; `coverage.js` still `Math.min(raw, 40)` + “capped at 40” copy |
| 6 | Dev **Tools**: control **default** tools | **Partial** | Per-hunt/per-recon allowlists exist; global defaults hardcoded in `profiles/code_static.py` + `packet.tool_schemas_for` |
| 7 | Modified skills know **defaults** | **Partial** | Edit of seed body → `source=custom`; live tool allowlist re-read on pack; no seed-diff / restore / “default body” UX |
| 8 | Recon **merge** quality | **Exists; improve** | `merge_architectures` multi-agent merge; batch finalize; salvage path for weak models |
| 9 | Architecture **history** + **manual edit** | **Missing** | Single `runs.architecture_json` overwrite via `set_architecture` |
| 10 | Architecture passed to hunts | **Exists** | `_architecture_slice` + `pack_hunt` “Architecture (area slice)” — improve, don’t invent |

Honesty constraints (do not violate):

- Target tree remains **read-only** for agents.
- Automation never sets `confirmed`.
- Evidence only under `evidence/`.
- Chains / PoCs are **operator research tools**, not exploit proof.

---

## Design principles

1. **Run-scoped policy over global toggles** — hunt skill mode lives on the run (`config_json` / recon payload), not by deactivating the whole Dev collection.
2. **Reuse existing primitives** — `source`, `active`, `merge_findings`, architecture merge, Coverage select, PoC workshop.
3. **Cap = `run.max_tasks`** everywhere (UI estimates must match backend).
4. **Provenance over mutation** — architecture history appends snapshots; merges never lose prior generations silently.
5. **Small PRs** — each phase shippable with tests; UI can lag API by one PR if needed.

---

## Core data model additions

### Run hunt policy (PR-B)

```yaml
# Stored on runs.config_json / recon task payload
hunt_skill_mode: all_active | seed_active | custom_only | explicit
# all_active     — today's active_class_ids() (default)
# seed_active    — active profiles with source == "seed" (package defaults still active)
# custom_only    — active profiles with source in {custom, generated, import}
# explicit       — only hunt_skill_ids list
hunt_skill_ids: []   # used when mode == explicit
```

Resolution helper (single source of truth):

```text
resolve_run_class_ids(db|cfg) -> list[str]
```

Consumers must use this instead of raw `active_class_ids()`:

- `plan_hunt_tasks` / `_fallback_hunt_tasks`
- `plan_file_by_file_hunts`
- Coverage `mode=all` (and default select set)
- Recon packet registry section (so model cannot `hunt_focus` disallowed ids)
- Optional: `request_hunt` mid-run (decide: hard reject vs warn — recommend hard reject outside allowlist)

### Architecture history (PR-F)

```text
architecture_revisions table (or JSON array on run):
  id, run_id, created_at, source (recon|merge|manual|import),
  agent_ids[], recon_generation, snapshot_json, note
```

- `set_architecture` always appends a revision before overwrite.
- API: `GET .../architecture`, `GET .../architecture/history`, `PUT .../architecture` (manual), `POST .../architecture/restore/{rev}`.

### Finding clusters / variants (PR-D)

Do **not** invent a second identity system. Build on:

- `stable_key` (exact)
- `merge_key` path|symbol (near-dup)
- Optional softer cluster: same path + overlapping line ranges / title Jaccard (report-time only)

Display model:

```text
cluster_id → primary finding (keeper)
  variants: 1A (primary), 1B, 1C (related / near-dup / superseded)
```

Operator actions: **Merge into primary** (wire `merge_findings`), **Keep separate**, **Open both**.

### Attack chain (PR-E)

```text
chains table or evidence/chains/<id>.json:
  id, title, finding_ids[], include_states (confirmed|needs_human),
  steps[{finding_id, role, notes, poc_path?}], created_at, updated_at
```

Launch options post-run:

- Scope: `confirmed` only | `confirmed` + `needs_human`
- Optional: enqueue `develop_poc` for steps missing PoC
- Never auto-confirm findings

### Default tools config (PR-G)

```text
config/default_tools.json  (or config/tools/defaults.json)
  recon: [list] | null  # null = built-in packet defaults
  hunt: [list] | null
  develop_poc: [list] | null
```

Dev Tools tab edits this; `tool_schemas_for` + profile allowlist resolve through it. Per-skill allowlists still **narrow** further.

### Seed provenance (PR-G/H)

On each profile:

- Keep `source`
- Add `seed_body_hash` or compare live to package `prompts/v1/hunt_classes/{id}.md`
- Dev UI: badge **seed / modified from seed / custom**, actions **Diff seed**, **Restore seed body**

---

## PR plan (DAG)

```text
PR-A  Coverage 40 UI cleanup ─────────────────────────────┐
PR-B  Run hunt skill mode (API + resolve helper) ─────────┼─► PR-C Recon re-run + init UI
PR-D  Findings cluster / merge UI ────────────────────────┼─► PR-E Attack chain builder
PR-F  Architecture history + manual edit ─────────────────┤
PR-G  Default tools + seed provenance in Dev ─────────────┘
PR-H  Recon merge hardening + richer hunt arch context (can parallel PR-F)
```

### PR-A — Coverage queue cap UI cleanup (quick win)

**Goal:** Remove stale “40” ceiling from Coverage estimates/copy; use `run.max_tasks`.

| | |
|--|--|
| **Files** | `ui/static/coverage.js`; optionally expose `max_tasks` on run snapshot in `ui/store.py` |
| **Deps** | None |
| **Accept** | No user-facing “capped at 40”; estimates use `max_tasks`; backend still sole enforcer; “All classes” can select full catalog |

Also tighten copy so operators understand:

- **Cover all areas** = active skills × areas (capped by `max_tasks`)
- **Custom** = any registered skill; residual matrix axes still reflect used/planned classes unless expanded

### PR-B — Run-scoped hunt skill mode (backend)

**Goal:** Runs can use `all_active` | `seed_active` | `custom_only` | `explicit`.

| | |
|--|--|
| **Files** | `hunt_profiles/store.py` (resolve helpers), `stages/recon.py` (`plan_hunt_tasks`), `strategies.py`, `control/ops.py` (coverage + requeue_recon payload), `cli.py`, `db` run config, tests |
| **Deps** | None |
| **Accept** | Unit tests: custom_only excludes seed ids; empty custom set fails clearly or falls back with event; recon packet lists only allowed classes; coverage-all respects mode |

### PR-C — Init + Operator re-run UI for hunt skills

**Goal:** Start run and re-run recon can select skill mode and optional explicit skills; re-run already has recon agents — add hunt skill controls.

| | |
|--|--|
| **Files** | `ui/templates/index.html`, `ui/static/app.js` (init + `renderOperatorRerunCard`), `ui/app.py` (`InitBody`, recon rerun body), wire to PR-B |
| **Deps** | PR-B |
| **Accept** | New audit: radio/select Default(active) / Seed-active / Custom only / Pick skills; re-run recon: same + existing agents/brief/paths; payload reaches recon finalize planning |

**Re-run Recon — current vs target**

| Control | Today | Target |
|---------|-------|--------|
| Recon agents | Yes | Yes (keep) |
| Brief / paths | Yes | Yes |
| Prior architecture | Yes | Yes |
| Enqueue hunts / arch-only | Yes | Yes |
| Hunt skill mode | No | Yes |
| Explicit skill multi-select | No | Yes (when mode=explicit or as “also queue these”) |
| Dynamic skills toggle | Init only | Init + optional re-run |

### PR-D — Report findings overlap checker

**Goal:** Surface overlaps; merge or view as variants (1A / 1B).

| | |
|--|--|
| **Files** | `stages/dedup.py` (cluster API), `control/ops.py` (merge endpoint), `ui/store.py`, `ui/static/report.js`, tests |
| **Deps** | None (uses existing merge) |
| **Accept** | Report: filter/group Near-dup; cluster drawer shows 1A/1B; **Merge into…** calls `merge_findings`; superseded linked; no auto-confirm |

Suggested API:

- `GET .../findings/clusters`
- `POST .../findings/merge` `{ keep_id, drop_ids }`
- Detail: list `near_dup_titles`, `merged_classes`, `superseded_by`

### PR-E — Attack chain builder (post-run)

**Goal:** After hunts exist, operator builds multi-finding attack chains from confirmed and/or needs_human.

| | |
|--|--|
| **Files** | new `vulnforge/chains/` or `stages/attack_chain.py`, DB or evidence JSON, Report/Mission UI tab or modal, ops launch |
| **Deps** | PR-D helpful (pick related findings); not hard-blocked |
| **Accept** | Create chain from selected findings; toggle scope confirmed vs confirmed+needs_human; steps reorderable; optional enqueue `develop_poc` per step; export markdown; honesty banner |

### PR-F — Architecture history + manual edit

**Goal:** Every recon merge/manual edit is recoverable; Mission can edit architecture.

| | |
|--|--|
| **Files** | `db.py`, `stages/recon.py` (`store_merged_architecture`), Mission UI in `app.js`, API routes |
| **Deps** | None |
| **Accept** | History list with timestamps/source; restore revision; JSON (or form) edit with validation; re-run still merges with prior when checkbox set |

### PR-G — Dev: default tools + default skill provenance

**Goal:** Operator controls global default tool lists; sees/restores seed skill bodies.

| | |
|--|--|
| **Files** | `toolgen/catalog.py`, `packet.py`, `profiles/code_static.py`, `config/…`, `ui/static/dev.js`, `templates/dev.html`, `hunt_profiles/store.py` |
| **Deps** | None |
| **Accept** | Tools tab: edit default recon/hunt/develop_poc sets; skill editor shows seed vs modified + restore; packing uses config defaults then skill allowlist |

### PR-H — Recon merge hardening + hunt architecture context

**Goal:** Improve merge quality; give hunts richer but still bounded architecture.

| | |
|--|--|
| **Files** | `stages/recon.py` (`merge_architectures`), `stages/hunt.py` (`_architecture_slice`), `packet.py` caps, tests |
| **Deps** | PR-F optional (history makes merges safer to iterate) |
| **Accept** | Documented merge rules (summary concat option, component path merge); hunt slice includes trust boundaries + path-matched components + optional hunt_focus for area; unit tests for multi-agent merge conflicts |

Improvements (concrete):

1. **Summary:** prefer concatenate short unique paragraphs over last-wins when agents cover different domains.
2. **Components:** merge by `name`/`path`; union tags/paths rather than full replace.
3. **Hunt slice:** include `recon_generation`, matched `hunt_focus` for area, slightly higher component cap when path_hints align.
4. **Empty arch:** recon re-run UX already prompts; ensure hunt logs event when architecture missing.

---

## Implementation order (operator value)

1. **PR-A** — minutes; fixes misleading Coverage UX (your 40Q issue).
2. **PR-B → PR-C** — custom-only runs + re-run recon skill controls (core ask).
3. **PR-F + PR-H** — architecture reliability for everything downstream.
4. **PR-D** — report hygiene before chains.
5. **PR-E** — attack chain builder on clean findings.
6. **PR-G** — Dev polish (default tools / seed provenance).

---

## Subagent validation checklist (per PR)

For each PR before merge:

| Check | How |
|-------|-----|
| Exists-vs-gap re-scan | explore agent on touched paths |
| Unit tests | `pytest` for resolve helpers, merge, clusters, arch history |
| UI smoke | Coverage estimates, init modal, re-run card, Report merge |
| Honesty | no confirmed automation; target RO; evidence paths |
| Cap consistency | UI cap == `run.max_tasks` |

---

## Out of scope / non-goals

- Executing attack chains or PoCs against live systems from the dashboard.
- Treating same-model validation as proof.
- Replacing human review for `confirmed`.
- Global deactivation of seed skills as the only way to get custom-only (must be run-scoped).

---

## Open decisions (resolve before PR-B/E)

1. **`custom_only` empty set:** error at init vs allow recon-only with zero hunts?
2. **`request_hunt` outside allowlist:** hard deny (recommended) vs allow with event?
3. **Chains storage:** SQLite table vs `evidence/chains/*.json` only?
4. **Seed-active definition:** only `source==seed` and active, or “package seed ids regardless of edit-to-custom”? Recommend: `source==seed` only; edited seeds are custom.
5. **Matrix columns:** should Coverage residual matrix expand to all allowed skills even unused? (nice-to-have after PR-A/B)

---

## Summary for operator

| You asked | Verdict | Plan |
|-----------|---------|------|
| Custom-only / default profiles at run start | Missing | PR-B + PR-C |
| Re-run recon with profiles + custom hunts | Agents yes; hunt skills no | PR-C on top of existing re-run card |
| Findings overlap merge / 1A–1B | Auto merge only | PR-D |
| Attack chain builder | Missing | PR-E |
| Remove 40Q limit | Backend yes, UI no | **PR-A first** |
| Default tools in Dev | Missing globally | PR-G |
| Default skills when modified | Partial | PR-G |
| Recon merge + arch history/edit | Merge yes; history/edit no | PR-F + PR-H |
| Arch → hunts | Already sliced | PR-H improve |
