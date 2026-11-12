# SARIF 2.1.0 export

`sarif` is a format in the findings export registry (`vulnforge/export_findings.py` → `vulnforge/sarif_export.py`). It feeds GitHub code scanning (`github/codeql-action/upload-sarif`), IDE SARIF viewers, and other consumers.

| Surface | How |
|---------|-----|
| CLI | `vf export --run-dir RUN --format sarif [--out FILE\|-] [--include-needs-human] [--include-rejected] [--state STATE ...]` |
| Report | **Export** modal → **SARIF 2.1.0 (.sarif)**, with *include needs_human* / *include rejected* toggles |
| HTTP | `GET .../export?format=sarif[&sarif_include_needs_human=true][&sarif_include_rejected=true]` (media `application/sarif+json`) |
| Campaign | `GET .../campaign/findings?format=sarif` → `{count, states, skipped_no_location, sarif}` |

## State filter

| Default | Opt-in |
|---------|--------|
| `confirmed` | `needs_human` (`--include-needs-human`), `rejected_*` + `superseded` (`--include-rejected`) |

An explicit state list (repeatable `--state`, or a single campaign `state=`) replaces the default and the flags. `candidate` (not yet through `validate_mech`) is only exported when named that way. Exporting never changes finding state.

## Mapping

- **Rules**: one per weakness class (hunt skill). `ruleId` = class slug after the static hunt-skill aliases (`sqli` → `injection`, `xss` → `client-side`; `unclassified` when empty), tags `security`, `vulnforge`, slug. The campaign `class` filter uses the same mapping. No rule `security-severity`: one score per class would mislabel mixed-severity findings, so severity is carried by the result `level`.
- **Results**: one per finding. `level` from `severity_claim`: CRITICAL/HIGH → `error`, MEDIUM or missing → `warning`, LOW/INFORMATIONAL → `note`. `message.text` starts with the state for anything not `confirmed` (`needs_human: <title>. Mechanical gates passed; not a confirmed vulnerability.`), since code scanning uses the first sentence as the alert title (a title containing `.`, such as `os.system`, is cut there by GitHub). Related locations are linked from the message as `[path:line](id)`, because code scanning shows only linked ones.
- **Fingerprints**: `partialFingerprints` carries `stable_key` as `vulnforge/stableKey/v1` and as `primaryLocationLineHash`. `stable_key` hashes profile, sink path and symbol, class and attacker (see `vulnforge/findings/identity.py`), not line numbers, so alerts follow the finding across runs and line moves. Changing one of those fields gives a new alert.
- **Properties**: `vulnforge/state`, `vulnforge/finding_id`, `vulnforge/confirmed`, `vulnforge/weakness_class`, `vulnforge/severity_claim`, `vulnforge/evidence_id`, `vulnforge/stable_key`, `vulnforge/human_review_action`, `vulnforge/policy_rule` (security policy effect, when any). Run properties carry the run id, included states, and the disclaimer.
- **Locations**: the primary location is a citation with a path and start line in `sink_path`, preferring the one naming `sink_symbol`, else the first such citation; other cited lines go in `relatedLocations`. URIs are relative to the run's target root with no `uriBaseId` and no absolute local paths. For GitHub upload, the audited target must be the repository root, or alerts won't land on the committed files.
- **No location**: a finding with no target-relative path and start line is not emitted as a result. It is listed in `invocations[0].toolExecutionNotifications` (`vulnforge/no-location`).

GitHub upload limits: 10 MB gzipped and 25,000 results per run (5,000 shown). No `automationDetails` is written; set `category` on the upload step.

Honesty: `needs_human` means mechanical gates passed, and `confirmed` means a human accepted it. Neither is exploit proof, and SARIF export never sets `confirmed`.

Tests: `tests/test_export_sarif.py` validates output against the vendored OASIS schema (`tests/fixtures/sarif/sarif-schema-2.1.0.json`, offline).
