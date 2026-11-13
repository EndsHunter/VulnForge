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

## Promote from a human reject

Report → a finding in `rejected_human` → **Promote to policy** (`vulnforge/policy_promote.py`).
It covers the case where a human rejects a finding with a note like "this input is admin-only"
and the same false positive keeps coming back in later hunts.

1. **Draft** (`GET .../findings/{fid}/policy-draft?target_list=exclusions|out_of_scope`) is
   read-only. It requires the finding to be `rejected_human` **and** a stored HITL response
   `finding-N` / `finding-N-review` = `changes-requested`. The harness re-reads that response
   and never invents one. Pre-fill: `paths` = the finding's cited paths, resolved like the gate
   resolves them (exact files, the narrowest rule); `weakness_class` = the finding's class
   (exclusions only); `reason` = the note on that review response only. A stale
   `finding-N-notes` row from an earlier review is not used. The draft also lists the current
   `needs_human` findings the rule would match. That list is display only: nothing is re-gated
   (see "Not re-gated" above).
2. The operator edits the rule (id, globs, class, reason) and presses **Preview** (`dry_run`)
   and then **Save to policy** (`POST .../findings/{fid}/promote-to-policy`). Nothing is
   stored before Save. A blank or `*` class is refused unless the operator ticks
   **All weakness classes**, so a missing class never silently widens the rule.
3. Save appends the rule to the current policy as a new revision (`source=human_reject`,
   note naming the finding and HITL response). The write uses `BEGIN IMMEDIATE`, checks the
   draft's `base_revision` (a stale one gets `409 policy_changed`), and re-checks that the
   reject is still the current response. No finding state changes.

Only `exclusions` and `out_of_scope` are targets. Both demote through the visible
`check_policy_exclusion` gate. `trusted_inputs` and trust boundaries are prompt guidance with
no `policy_match` record, so they are not offered.

### Provenance

The saved rule carries a harness-stamped `provenance` object:

```json
{"kind": "human_reject", "finding_id": 12, "hitl_report_id": "finding-12",
 "hitl_block_id": "finding-12-review", "hitl_response_value": "changes-requested",
 "hitl_response_at": "<iso>", "hitl_note": "<reject note, ≤2000 chars>", "operator": "…",
 "promoted_at": "<iso>", "origin_paths": ["app.py"], "origin_weakness_class": "injection"}
```

Anything the client sends under `provenance` is dropped. The note, the response value and
the original paths and class are snapshotted, so the record survives a later reopen of the
finding (which deletes the live review response) and later edits to the rule's globs.

`provenance` is harness-owned. `Database.set_security_policy` refuses any provenance object
that is not already stored on the same list and rule id in some revision. The one exception
is the rule the promote path is adding. An Atlas policy JSON save or `vf policy set` can therefore
carry provenance forward unchanged (edits, History → Load → Save, restore), but cannot
fabricate it or paste it onto another rule. Provenance never reaches LLM packets.

Policy history (`GET .../security-policy/history`, Atlas → Security policy → History) adds
`promoted_rules` to each revision. It lists the rules whose provenance first appears in that
revision (finding id, HITL response, operator), so the record stays visible even after a
restore rewrites the revision note.

## Operator surfaces

- Dashboard: **Atlas → Security policy** fold — JSON editor, Save (server-validated), History
  (load into editor / restore), **Draft from SECURITY.md** (fills the editor; not saved).
- API: `GET|PUT /api/runs/{t}/{r}/security-policy`, `GET .../security-policy/history`,
  `GET .../findings/{fid}/policy-draft`, `POST .../findings/{fid}/promote-to-policy`,
  `GET .../security-policy/history/{rev}`, `POST .../security-policy/restore/{rev}`,
  `GET .../security-policy/draft/security-md`.
- CLI: `vf policy show|set|history|restore|draft-security-md` (see `PROTOCOL.md`).

A `SECURITY.md` draft copies prose into `notes` only; no mechanical rules are
invented. An LLM-drafted policy (`vf policy draft`) is not implemented.
