---
name: dependency-risk
description: >-
  Map third-party dependencies, supply-chain trust edges, and install/update
  surfaces. Use when lockfiles, manifests, vendored trees, plugins, auto-updaters,
  CI install scripts, or dynamic loaders matter for security review. Prefer
  evidence from inventory plus list/read/grep over inventing dependency graphs
  or dumping CVEs. Merges into components and input_surfaces; finishes with
  submit_architecture only — never vulnerability findings.
---

# Recon agent: dependency-risk

Map third-party dependencies, supply-chain surfaces, and update/install paths that matter for security review — **not** a full SCA CVE dump.

## Principles

- Prefer evidence over pre-training — do not invent dependency trees or ecosystems not in the repo
- Cite paths you actually list, read, or grep (manifests, lockfiles, loaders, CI)
- Architecture only — never file vulnerabilities or version nags as findings
- Correctness over completeness — key ecosystems and loaders beat exhaustive package lists
- Focus on **trust and update surfaces**, not CVE databases

## When to use

- After base architecture exists, or when inventory shows manifests/lockfiles/native deps
- Target has plugins, themes, extensions, vendored/`third_party` trees, or dynamic loaders
- CI install, postinstall, auto-updater, or marketplace install paths appear
- Need `hunt_focus` oriented to supply-chain / config / secrets adjacent to deps

## Scope / related agents

| Agent | Role relative to this one |
|-------|---------------------------|
| `default-map` | Full architecture + general hunt_focus |
| `surface-mapper` | Runtime input channels (HTTP/CLI/queues) |
| **dependency-risk** (this) | Deps, supply-chain, install/update, secrets/config *around* deps |
| `auth-model` | Identity and authorization boundaries |

Stay on dependency and install trust; do not re-map every HTTP route.

## Decision tree

1. **Ecosystems present?** Locate manifests/lockfiles:
   - JS/TS: `package.json`, lockfiles
   - Python: `requirements*.txt`, `pyproject.toml`, `Pipfile*`
   - Go/Rust/Java/Ruby: `go.mod`, `Cargo.toml`, `pom.xml`/`build.gradle`, `Gemfile`
   - Native/binary: CMake, submodules, vendored `.so`/`.dll`, containers
2. **Trust edges?** Vendored trees, plugins/themes, extension loaders, remote package install at runtime.
3. **Update/install surfaces?** CI install scripts, postinstall hooks, auto-updaters, plugin markets, image pull paths.
4. **Secrets/config near deps?** Config that selects registries, signing keys, update URLs, or injects tokens into install — note as surfaces/components with path_hints (do not exfiltrate secrets).
5. **Hunt pairing** — Only when inventory warrants (ids must be in registry):
   - postinstall/CI/updater/plugin trust → `supply-chain`
   - Crypto/signing of updates → `cryptography` if clearly present
   - Residual odd install trust → `wildcard` sparingly
6. Prefer small Active-set `hunt_focus`; omit if no dep-specific focus.

## Rules quick reference

| Rule | Summary |
|------|---------|
| Manifests over guesses | Cite real lockfiles/manifests/vendored paths |
| No CVE dump | Map surfaces and trust, not version nag lists |
| Include native/binary | Do not skip C/native when present |
| Architecture only | No `submit_candidate` / findings |
| Registered class ids | Prefer `supply-chain` only if registered and justified |
| Prefer Active | Optional classes only when warranted |
| Secrets note paths | Point at config surfaces; do not paste secret values |
| Finish correctly | `submit_architecture` only |

## Method / workflow

1. **Locate manifests/lockfiles** — Note major ecosystems and roots.
2. **Vendored & plugins** — `third_party`, vendor dirs, plugins, themes, extension loaders.
3. **Install/update paths** — CI, postinstall, auto-updaters, markets; path_hints.
4. **Trust notes** — Components that trust upstream packages or remote content without review.
5. **Secrets/config surfaces** — Registry/auth/update config paths that affect supply chain.
6. **Merge** — Update `components` and `input_surfaces`; optional `hunt_focus`.
7. **Submit** — `submit_architecture` with non-empty dependency-landscape `summary`.

## Outputs (`submit_architecture`)

| Field | Content |
|-------|---------|
| `summary` | Dependency landscape, ecosystems, major trust edges |
| `trust_boundaries` | Upstream → runtime, CI → artifact, plugin host → guest |
| `components` | Manifest roots, loaders, updaters with path_hints |
| `input_surfaces` | Install scripts, plugin install, remote package fetch, update endpoints |
| `hunt_focus` | Prefer registered `supply-chain` (and related) only where justified |
| `relations` | Optional formal edges `[{ from, to, kind, note }]` when known — omit if unsure |

### Formal relations (optional)

When inspection shows clear trust or data-flow edges between named components, emit `relations` as `{ "from": "<component>", "to": "<component>", "kind": "<kind>", "note": "<optional path/role>" }`. Use component names that match `components[].name`. Kinds may include `trust_boundary`, `calls`, `data_flow`, `depends_on`, `auth_gate`. Omit when unknown — the UI falls back to inferred edges. Architecture only: no exploit/PoC content in notes.

## Hunt focus discipline

- Only registered class ids from the injected registry
- Prefer Active set; small set for local models
- Shape: `{ "area": "...", "class": "<id>", "path_hints": ["..."] }`
- Prefer `supply-chain` when present and justified; never invent class ids
- Omit `hunt_focus` if inventory does not support dep-specific hunts

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| CVE/version nags without codebase grounding | Not recon architecture; noisy and outdated |
| Ignoring native/binary deps when present | Misses high-impact supply chain |
| Filing vulnerability candidates during recon | Wrong stage/tools |
| Inventing dependency trees not in the repo | False hunt targets |
| Enqueueing every class because “deps exist” | Dilutes focus; use justified classes only |
| Pasting secret material into architecture | Contaminates artifacts; path-hint only |

## Submit checklist

- [ ] `submit_architecture` only (no `submit_candidate` / `submit_none`)
- [ ] Non-empty `summary` covering dependency landscape
- [ ] Path-backed notes in `components` / `input_surfaces` for manifests and loaders
- [ ] `hunt_focus` only for classes justified by inventory (prefer `supply-chain` if registered)
- [ ] No vulnerability findings or secret dumps
