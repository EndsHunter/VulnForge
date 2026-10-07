# Opening a PR (VulnForge poteto)

Invoked at the end of docs, skill, or small harness work that ships as a PR.
For full pstack opening-a-pr (worktrees, deslop, stacks), use upstream poteto-mode.

## Steps

1. **Branch.** Work from a clean branch off the agreed base (usually `main`). Prefer a fresh worktree when the main tree is dirty.
2. **Diff honesty.** Touch only the files the boarding brief (or task) named. No drive-by refactors. No invented exploits or hunt-class prose.
3. **Deslop.** Tighten commit and PR prose. Short declarative sentences. Conventional Commits title: `type(scope): subject` (e.g. `docs(skills): add project-local poteto-mode`).
4. **PR body sections** (drop empty ones):
   - `## Why`
   - `## What changed`
   - `## Scope` (covers / deliberately leaves out)
   - `## Verification` (real commands + outcomes)
5. **Screenshots.** If the change claims UI state, embed **absolute** head-SHA URLs in the PR body **and** a PR comment:
   ```text
   https://raw.githubusercontent.com/EndsHunter/VulnForge/<HEAD_SHA>/<path>.png
   ```
   Never relative `docs/` paths alone in the PR description.
6. **Forge flags.** Open ready (not draft) unless Ops asked for draft. Set Grok build **medium** when the boarding brief says so. **Do not merge.** Leave open for Jonathan / Ops.
7. **Gauge.** Docs/skills-only → Gauge N/A unless Jonathan asks for a glance.
8. **Post the URL.** Return `https://github.com/EndsHunter/VulnForge/pull/<number>`. Do not start babysit unless asked.

## Verification bullets (examples)

- Skill frontmatter parses (`name`, `description`).
- Paths match boarding: `.cursor/skills/poteto-mode/SKILL.md` (+ playbooks if added).
- No harness behavior change unless the brief explicitly allowed it.
