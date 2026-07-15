---
name: supply-chain
description: >-
  Hunts dependency, build, install, and update trust breaks with real attacker
  impact — install-time code exec, poisoned artifacts, CI secret exposure,
  dependency confusion, or unsigned updates that become runtime control. Use
  when reviewing package manifests/lockfiles, postinstall/prepare scripts,
  CI workflows (pull_request_target), Docker/build scripts, auto-updaters, or
  private registry resolve order. Prefer in-tree trust edges over NVD bingo.
---

# Hunt class: supply-chain

## Principles

- **Prefer evidence over pre-training.** Prefer **in-tree** trust edges over NVD bingo.
- **Be certain.** Version alone is not a finding — need reachability or install-time exec.
- **Provide evidence.** Remote content → install/build → secrets → effect; who can poison.
- **Correctness over completeness.** One confusion/postinstall RCE beats “should pin all deps.”
- Honest `submit_none` when clean pins + no lifecycle scripts + CI least-privilege.

## When to use

- Package managers + lockfiles, CI workflows, Docker/build scripts
- Auto-updaters, plugin marketplaces, private package feeds
- postinstall/preinstall/prepare; setup.py cmdclass; custom build targets
- Dependency confusion (extra-index-url, unscoped npm, misordered GOPROXY)

## When not to use / Scope

- Transitive CVE with no reachable use and no install-time exec
- Runtime SQLi/RCE from app code → `injection`
- Missing SBOM as a finding (process/hardening)
- Related skills: `obvious` for committed secrets without install path; `injection` for app sinks; `feature-abuse` for runtime SSRF; dual-file install script only if impacts truly differ

## Decision tree

```
1. Inventory manifests, lockfiles, CI configs, Docker/build scripts, updater/plugin loaders
2. Trace: remote content → install/build → secrets available → runtime/deploy
3. Dangerous scripts: who controls input? what identity runs it?
4. Internal package names: can public same-name win resolution?
5. Lockfile CVEs: import/call of vulnerable API? No site → note, don’t candidate
6. Clean pins + no lifecycle scripts + CI least-privilege → submit_none
```

## Rules quick reference

| Rule | Summary |
|------|---------|
| Trust edge | Remote → install/build → effect must be explicit |
| Poisoner | Who can publish/replace the artifact? |
| Lifecycle scripts | postinstall in CI with cloud keys is high impact |
| Confusion | Public same-name wins resolve order |
| Floating refs | `@latest` / `@main` actions are mutable trust |
| PR secrets | `pull_request_target` + untrusted checkout is classic |
| CVE reachability | Import/call of vulnerable API, not version alone |
| Unsigned update | Auto-update/plugin without integrity → runtime control |
| Dual-file ban | Same install impact not under supply-chain + obvious unless distinct |
| SBOM missing | Process gap, not a vulnerability finding |

## Focus

- postinstall/preinstall/prepare; setup.py cmdclass; custom build targets
- Dependency confusion (extra-index-url, unscoped npm, misordered GOPROXY)
- Floating ranges; missing integrity; mutable tags (`@latest`, `@main` actions)
- CI secrets × untrusted code (`pull_request_target` + PR checkout)
- curl|bash installers; unsigned auto-update/plugin load
- Workspace path deps pulling unreviewed code into prod images

## Hunt workflow

1. **Inventory** — manifests, lockfiles, CI, Docker, updaters, plugin loaders
2. **Trace** — remote → install/build → secrets → runtime/deploy
3. **Prove** — poisoner identity and effect (RCE, secret steal, runtime control)
4. **Evidence** — trust edge and poisoner; `write_evidence`
5. **Submit or none** — `weakness_class: supply-chain`, or honest `submit_none`

## Stack cues

```
postinstall|preinstall|prepare|install\.js|setup\.py|cmdclass
package-lock|yarn.lock|pnpm-lock|Pipfile.lock|poetry.lock|go.sum|Cargo.lock
extra-index-url|index-url|publishConfig|registry\.npmjs|GOPROXY|PIP_EXTRA
\.github/workflows|pull_request_target|secrets\.|GITHUB_TOKEN|permissions:
uses:.*@main|uses:.*@master|actions/checkout@
curl .*\| *(ba)?sh|wget .*\||ADD http|RUN curl
auto.?update|electron-updater|plugin.?install|integrity|cosign|sigstore
```

## Required evidence

- Trust edge (remote → install/build → effect), who can poison it

## False positives

- DevDependency scripts never run in prod CI/image
- “Should pin all deps” without floating path or known-bad pin + sink
- Theoretical registry takeover without resolve-order evidence

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| CVE bingo | No reachability or install-time impact |
| Dual-file with obvious | Same impact twice |
| Version alone | Not a finding without use |
| Missing SBOM | Process, not vuln |
| Dev-only scripts | No prod identity |

## Submit checklist

- `write_evidence` first: trust edge and poisoner
- `weakness_class: supply-chain`
- **Good:** *“Internal package `acme-utils` resolves via public PyPI first (`pip.conf` extra-index); attacker publishes same name — postinstall RCE in CI with cloud keys.”*
- **Bad:** *“Uses lodash; lodash had CVEs.”*
- Or honest `submit_none`
