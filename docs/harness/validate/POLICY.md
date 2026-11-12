# Operator security policy (`vulnforge/security-policy@1`)

An operator-owned, versioned policy per run: trust boundaries, attacker-controlled
sources, scope, exclusions, and a severity rubric. It is stored in `harness.db`
(`security_policy_revisions`, append-only; current = newest revision, last 100 kept).
The target tree stays read-only — `SECURITY.md` can **seed** a draft, never the
other way round.

**Honesty:** the policy can only narrow scope and demote findings. It never
promotes a finding and never sets `confirmed`. Exclusions are always visible in
the Report (`policy_match` on the finding body, `REPORT.md` "Excluded by security
policy", export column `policy_rule`). Human review can reopen any excluded finding.

## Schema

```json
{
  "schema": "vulnforge/security-policy@1",
  "notes": "free prose (e.g. drafted from SECURITY.md) — LLM guidance only",
  "trust_boundaries":    [{"id": "tb-1", "name": "internet → api", "description": "...", "paths": ["src/api/**"]}],
  "attacker_controlled": [{"id": "src-1", "description": "HTTP params", "paths": ["src/api/**"]}],
  "trusted_inputs":      [{"id": "trust-1", "description": "deployer env vars", "paths": []}],
  "in_scope":     [{"id": "scope-1", "paths": ["src/**"], "note": "focus guidance"}],
  "out_of_scope": [{"id": "oos-1", "paths": ["tests/**"], "reason": "fixtures"}],
  "exclusions":   [{"id": "ex-1", "paths": ["vendor/**"], "weakness_class": "*", "reason": "vendored"}],
  "severity_rubric": [{"id": "sev-1", "max_severity": "MEDIUM", "weakness_class": "*",
                       "paths": ["src/admin/**"], "criteria": "admin-only surface"}]
}
```

Validation (`vulnforge/security_policy.py` `normalize_policy`) is strict: unknown
keys (top-level or inside a rule) are errors, ids must be unique across the policy
(missing ids are auto-assigned, e.g. `ex-1`), globs are relative with no `..`,
`exclusions` / `out_of_scope` / `in_scope` need at least one glob, and
`exclusions` / `out_of_scope` need a `reason`. An invalid save stores nothing.

Globs are case-sensitive and match the full relative path: `*` stays within one
segment, `**` crosses segments (may be empty), `?` is one character, and `[` is a
literal (no character classes, so `app/[id]` works). A trailing `/` or a glob with
no wildcard means the whole directory (`vendor` ≡ `vendor/**`). In `validate_mech`
citation paths are resolved under the target root the same way the citation gate
resolves them (`..` and symlinks: `lib/../vendor/a.py` → `vendor/a.py`), so the
policy judges the file the gate accepted.

`policy_match`, `severity_rubric` and `severity_claim_original` are harness-owned:
`validate_mech` drops any copy a candidate carried (listed in
`harness_keys_dropped`) before the gates, then recomputes them from the stored
policy. The Report ignores these fields on findings still in `candidate`.

## Where it is used

| Stage | Effect |
|-------|--------|
| recon | Policy block in every recon agent packet (graph + sequential) and in the LLM architecture merge: listed boundaries / attacker sources override conflicting inferences. The stored map records `security_policy_revision`. No mechanical rewrite of the map, no pruning of `hunt_focus`. |
| hunt | Area slice (rules whose globs overlap `path_hints`, plus rules without paths and the whole rubric), single and MoA hunts. Hunters are told **not** to skip `submit_candidate` because a rule might match — the harness records the exclusion. |
| validate_mech | `check_policy_exclusion` (last in `CHECKS`): an `exclusions` rule (class matches, or `*`) or an `out_of_scope` rule that covers **every** cited path → `rejected_mech` with `policy_excluded:<id>` / `policy_out_of_scope:<id>` and `policy_match` stored. A finding with one cite outside the rule is not excluded. After the gates, the tightest matching rubric rule with `max_severity` caps `severity_claim` (original kept as `severity_claim_original`, record in `severity_rubric`); it never raises severity, and it runs after `check_non_vacuous` so a cap cannot loosen that check. |
| validate_llm | Full policy block in the disprove packet. A disprover may add `POLICY_RULE=<id>`; known ids are stored as `policy_rules_cited` per verifier and on `validation_llm`. Citations never change the verdict or the all-reject aggregation. |

`in_scope` is packet guidance only — it is not a gate.

### Not re-gated

The policy applies to findings validated after it is saved. `validate_mech`
returns early for terminal findings and for `needs_human` findings whose mech
already passed; the rearm path (`rearm=true` / deadlettered) only requeues
`validate_llm`. A new exclusion therefore does not move an already-passed finding
to `rejected_mech`.

## Operator surfaces

- Dashboard: **Mission → Policy** — JSON editor, Save (server-validated), History
  (load into editor / restore), **Draft from SECURITY.md** (fills the editor; not saved).
- API: `GET|PUT /api/runs/{t}/{r}/security-policy`, `GET .../security-policy/history`,
  `GET .../security-policy/history/{rev}`, `POST .../security-policy/restore/{rev}`,
  `GET .../security-policy/draft/security-md`.
- CLI: `vf policy show|set|history|restore|draft-security-md` (see `PROTOCOL.md`).

A `SECURITY.md` draft copies prose into `notes` only; no mechanical rules are
invented. An LLM-drafted policy (`vf policy draft`) is not implemented.
