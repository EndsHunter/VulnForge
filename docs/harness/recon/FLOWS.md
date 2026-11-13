# Recon v2: zones, data flows and the Atlas flow map

Status: **implemented (R0–R5); R6 hunt planning from flows pending** (ui-redesign follow-up). Source: the Atlas concept in the
"VulnForge Redesign Concepts" canvas. It showed the architecture split into trust
zones (Internet-facing / Authenticated / Internal) with arrows following data from
where it enters to where it lands.

## Why Atlas has no arrows today

| Gap | Where |
|-----|-------|
| `relations` is optional and the prompts say "omit if unsure", so most maps have none. Atlas draws edges only from `relations`. | `seeds/system/recon.md`, `seeds/recon_agents/*.md`, `pages/atlas.js edgePaths` |
| Zones don't exist in the schema. `trust_boundaries` is free text, so Atlas guesses a zone per area by text-matching it. | `submit_architecture.py`, `atlas.js assignZones` |
| Nothing records a data flow (entry point → steps → sink). No agent owns it. | recon agents: default-map, surface-mapper, dependency-risk, auth-model |
| All four recon agents each write a *whole* map in parallel, then an LLM merge reconciles them. Work overlaps and is lost in the merge, which is hard for 35B-class models. | `stages/recon.py` fan-out + `merge_architectures` |
| Mechanical facts are never shown on the map: codemap import edges (module → module, with the import line), codemap entrypoints, and the sink pre-index (kind, path, line). Only the agents see them, through `query_flows`. | `tools/codemap.py _build_import_edges`, `tools/sink_preindex.py` |

## Principles

1. **Mechanical first.** Build a skeleton without an LLM from facts we already
   compute, so Atlas has zones and arrows before any model runs. The LLM labels
   and corrects that skeleton. It does not invent topology from scratch.
2. **Every edge and step cites `path:line`.** A validator checks that each cited
   file exists and the line is in range. Anything uncited is marked `inferred`
   and drawn dashed.
3. **One job per agent.** Map, surfaces, flows and auth each own a part of the
   schema instead of rewriting the whole map.
4. **Flows steer hunts. They are not proof.** A flow is never evidence for a
   finding, and an empty zone or no flow never means safe (AGENTS.md honesty rules).
5. **Back-compatible.** v1 maps keep rendering (heuristic zones, `relations`
   edges). `schema: "vulnforge/architecture@2"` marks the new shape.

## Schema: `vulnforge/architecture@2`

All new fields are optional, and v1 fields stay.

```jsonc
{
  "schema": "vulnforge/architecture@2",
  "summary": "...",
  "zones": [
    { "id": "internet", "label": "Internet-facing", "kind": "internet",
      "description": "Public router, no session required",
      "evidence": [{ "path": "app.py", "line": 12 }] }
    // kind: internet | authenticated | internal | external | build
  ],
  "components": [
    { "id": "api-invoices", "name": "api/invoices", "kind": "http_router",
      "zone": "internet", "role": "Invoice CRUD and search",
      "path_hints": ["app.py"],
      "entrypoints": [{ "label": "GET /invoices/search", "path": "app.py", "line": 40 }],
      "sinks": [{ "kind": "sql", "path": "app.py", "line": 52 }],
      "origin": "mechanical|recon" }
  ],
  "boundaries": [
    { "from_zone": "internet", "to_zone": "authenticated", "control": "login_required",
      "path": "auth.py", "line": 18 }
  ],
  "relations": [
    { "from": "api-invoices", "to": "db", "kind": "calls|data_flow|imports|queue|db|http_out|auth_gate",
      "evidence": { "path": "app.py", "line": 52 },
      "confidence": "mechanical|cited|inferred" }
  ],
  "flows": [
    { "id": "f1", "title": "Invoice search query → SQL",
      "source": { "component": "api-invoices", "label": "GET /invoices/search?q", "path": "app.py", "line": 40 },
      "steps": [ { "component": "api-invoices", "path": "app.py", "line": 47, "note": "q concatenated into query" } ],
      "sink": { "component": "db", "kind": "sql", "path": "app.py", "line": 52 },
      "crosses": ["internet", "internal"],
      "classes": ["injection"],
      "confidence": "cited|inferred" }
  ],
  "trust_boundaries": ["(v1 free text, kept for old readers)"],
  "input_surfaces": [], "hunt_focus": []
}
```

## Recon pipeline v2

| Step | LLM? | Owns | Notes |
|------|------|------|-------|
| **R0 skeleton** (`recon_mech`, runs in init) | no | `components` (origin mechanical), `relations` (imports, confidence mechanical), `entrypoints`, `sinks`, zone *suggestions* | Codemap modules → components. Import edges are rolled up from module to component. Entrypoints come from the codemap. Sinks from the pre-index are attached to their component. Zone heuristics: route decorators or HTTP routers → internet; `login_required`/auth middleware → authenticated; workers, settings, db → internal; outbound HTTP clients → external. Stored with `origin: "mechanical"`. |
| **R1 map** (default-map, rewritten) | yes | component names/roles, `zones`, `boundaries`, zone per component | Starts from the skeleton (in its packet). It may merge, rename or split components, citing evidence. It no longer writes flows or hunt focus. |
| **R2 surfaces** (surface-mapper) | yes | `entrypoints` per component (`path:line`) | Validated mechanically. |
| **R3 flow tracer** (new agent, fan-out) | yes | `flows` | One task per top entry point (cap configurable; default 8). Uses `query_flows`, `find_symbol`, `read_file` and `query_sinks`. Finishes with a new `submit_flow` tool. Steps must cite lines. |
| **R4 auth / deps** (auth-model, dependency-risk) | yes | `boundaries` controls, external zone, `relations` kind `auth_gate` / `depends_on` | Scoped to their slice. |
| **R5 merge** | mostly no | the whole map | Deterministic merge by component id and flow id, then validation. Drop edges to unknown components. Set `cited` when the evidence line exists and `mechanical` when an import edge backs the relation. Only the `summary` paragraph goes through the LLM. |
| **R6 plan hunts** | no | `hunt_focus` | Built from flows (flow × class, path hints = the flow's files) plus component gaps. The hunt packet gets the flow slice. |

Ralph order: R0 → R1 → (R2 ‖ R4) → R3 fan-out → R5 → R6. `continue_recon`,
priorities and Atlas "Run recon with brief" keep working. A brief can
target a step (for example "trace flows from /admin").

## Atlas flow map (UI)

- **Zone bands** come from `zones` (ordered internet → authenticated → internal →
  external → build). Heuristic zones are the fallback for v1 maps, labelled "guessed".
- **Arrows** in three layers, toggled in the map toolbar:
  - **Flows** (default on): accent arrows with arrowheads, a numbered step badge
    and a zone-crossing marker where a flow crosses a band.
  - **Relations**: neutral solid arrows, dashed when `inferred`.
  - **Imports**: faint arrows, off by default.

  Lines route orthogonally around nodes. Hovering shows kind and evidence; clicking
  opens the code at that line.
- **Flows panel** (left column, under the tree, or as a tab next to Files): each
  flow shows `source → sink`, a crossing badge such as "Internet → Internal", the
  hunt state of its classes, and its confidence. Selecting one highlights its path,
  dims everything else and lists the steps with `path:line` links.
- **Inspector** adds "Flows through this area" and a **Hunt this flow** composer
  (classes preselected from `flow.classes`).
- Empty and partial states: before recon finishes, the map shows the mechanical
  skeleton with the label "Mechanical skeleton: recon has not labelled this yet."

## Work split (sub-agents, file ownership)

| Agent | Owns | Depends on |
|-------|------|------------|
| **Skeleton** | new `vulnforge/recon_skeleton.py`, schema normalizers/validators (`normalize_architecture_v2`, `validate_citations`), the R0 hook in init, snapshot fields (`architecture.skeleton`, v2 passthrough), tests on `fixtures/toy_sqli` + mono_synth | schema in this doc |
| **Recon prompts and tools** | `submit_architecture` v2 params, new `tools/agent/submit_flow.py`, new `seeds/recon_agents/flow-tracer.md`, rewrites of default-map/surface-mapper/auth-model/dependency-risk, `seeds/system/recon.md`, the deterministic merge in `stages/recon.py`, FakeLLM scripted tests, `docs/system/RECON.md` | Skeleton (normalizers) |
| **Atlas UI** | `pages/atlas.{js,css}` zones/edges/flows panel, node tests for layout and orthogonal routing | schema only (works from fixture JSON) |
| **Hunt planning** (phase 2) | R6 flow → hunt_focus, flow slice in the hunt packet | Recon prompts |

Skeleton and Atlas UI can run in parallel on the schema contract. Recon prompts
starts once the normalizers land. Hunt planning comes last.

## Verification

- Unit: skeleton on fixtures (expected components, import relations, zones), the
  citation validator (bad line → `inferred`), the merge (dedupe, unknown endpoints
  dropped), and Atlas routing/layout (node tests).
- FakeLLM end-to-end: init → R0 → scripted R1/R3 → merged v2 map with ≥1 cited
  flow, and Atlas renders arrows (snapshot test).
- Live (optional, `VF_LIVE=1`): recon on `fixtures/toy_sqli` must yield the
  search → SQL flow with cited lines.
- Honesty: no path from flows to `confirmed`. Flow text never appears as finding
  evidence.
