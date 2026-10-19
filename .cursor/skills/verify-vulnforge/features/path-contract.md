# Path contract

A candidate that passes mechanical validation carries an ordered source-to-sink path. Each node is a file and a line that exists in the target, and the order agrees with `query_flows`. A disprove that breaks the path names the branch or the sanitizer. A false source drops the sibling nodes that depend on it.

## Sub-features

- `path-ordered` requires an ordered list of source-to-sink nodes, each with a file and a line.
- `path-exists` rejects the candidate when any node file is missing or the line is outside that file.
- `path-flows` rejects the candidate when the node order does not agree with `query_flows` for that source and sink.
- `disprove-break` requires a rejecting disprove to name the breaking branch or the sanitizer.
- `false-source-prunes` drops sibling nodes that share a source disprove marked false.

## How to get to it (user POV)

- Submit a candidate with `vf apply-candidate` and run one `vf run-once` for mechanical validation.
- Read the finding on `GET /api/runs/{target_id}/{run_id}`.
- Read reachability with the hunt tool `query_flows` (`mode=calls` or `mode=both`, `path` and `symbol` set). Its result is stored with the finding or the task transcript.
- Read disprove on `body.validation_llm` after a scripted disprove run.

## Driving it with vf-verify

Preconditions:

- `vf-verify doctor` reports `ok: true`.
- The run exists under `$VF_VERIFY_RUNS_ROOT` and the target file in the candidate is inside `fixtures/toy_sqli` or another fixture this run initialized.
- `stages.validate_llm` stays on. Do not call a live model. Disprove bullets apply when a scripted disprove client is already configured; otherwise report those bullets unmet and do not skip them by accepting unordered citations.

- **Candidate.** `vf apply-candidate` a body whose path is an ordered array of `{path, line}` nodes from source to sink. Then `$VF_VERIFY_VF run-once --run-dir <run-dir>` once.
- **Ordered nodes.** On `GET $VF_VERIFY_URL/api/runs/<target_id>/<run_id>`, the finding body lists those nodes in source-to-sink order. Each node has a file path and a line number. A body that only has an unordered `citations` array fails `path-ordered`.
- **Exists.** Every node file exists under the run's target and the line number is between 1 and the file length. A missing file or an out-of-range line leaves the finding `rejected_mech`.
- **Agrees with flows.** The stored `query_flows` result for the source symbol and the sink symbol contains those files in the same order. A path `query_flows` does not support leaves the finding `rejected_mech`.
- **Breaking disprove.** When disprove rejects, `validation_llm` names `breaking_branch` or `sanitizer` with a non-empty value. A reject that names neither fails `disprove-break` and does not clear `pending_llm`.
- **False source.** When disprove marks a source false, sibling nodes that begin at that source are absent from the stored path. Leftover siblings fail `false-source-prunes`.
- **Accept still blocked.** While `pending_llm` is true, Accept follows [gate chain](./gate-chain.md). Zero parsed disprove verdicts, errors, or timeouts stay inconclusive and do not clear the flag.
- **Proof.** Save the candidate JSON, the run snapshot, the `query_flows` payload, and any `validation_llm` object. Record feature id `path-contract`.

## Gotchas

- `query_flows` is reachability, not a proof the candidate is exploitable. The contract is agreement between the claimed order and that tool's edges.
- Citations that resolve on disk are not a substitute for ordered source-to-sink nodes.
- A disprove `VERDICT=reject` without a branch or sanitizer name fails this feature.
- Do not delete sibling nodes by hand to make pruning look done. The harness result has to drop them.
- Reporting this feature passed because mechanical citation checks passed is a skipped path, not a pass.
