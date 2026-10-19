# Canary evidence

A harness signal is a fresh per-run canary the PoC cannot know in advance. Only the target's own stdout can show it, a neutralized control run must not show it, and the process exit is 0 on every repeat. The harness code sets `signal_observed`. The model does not.

## Sub-features

- `canary-planted` plants a new secret for this run and does not write it into the PoC source, argv, or environment the PoC can read ahead of the trigger.
- `canary-target-stdout` counts the secret only when the target process prints it on stdout.
- `canary-control` runs the same PoC again with the trigger neutralized and requires the secret to be absent.
- `canary-repeat` runs the pair k times with k at least 2, and requires exit 0 on every triggered run.
- `canary-code-decides` sets `signal_observed` only from those checks. A model referee cannot set it.

## How to get to it (user POV)

- Put a runnable PoC in the finding evidence pack.
- Run `vf validate-poc --finding-id <id> --run-dir <run-dir> --execute`.
- Read `evidence/<pack>/poc_run.json`.

## Driving it with vf-verify

Preconditions:

- `vf-verify doctor` reports `ok: true`.
- The finding's evidence pack contains PoC code the harness can launch inside microVM or gVisor isolation.
- The PoC does not contain a hardcoded success marker.
- `--referee` is absent.

- **Execute.** Run `$VF_VERIFY_VF validate-poc --run-dir <run-dir> --finding-id <id> --execute`. Exit code `0` only when every triggered run exited 0. Save stdout JSON.
- **Planted secret.** `poc_run.json` records a per-run canary value that does not appear in the PoC source, the harness argv, or the PoC environment captured for the run. The value is a fresh UUID (or the file records that a sanitizer fired instead).
- **Target stdout.** `signal_observed` is present only when that canary appears on the target process stdout. The same bytes on the PoC's own stdout, stderr-only, or a `success_regex` copied from the PoC hub do not count.
- **Control.** The file records a differential replay with the trigger neutralized. That replay's target stdout does not contain the canary. If it does, `verdict` is `inconclusive` or `poc_broken`.
- **Leak in the PoC.** If the canary string appears in the PoC source or in argv, `verdict` is `poc_broken` or `inconclusive`, and `signal_observed` is absent.
- **Repeat.** The file shows k triggered runs with k at least 2, each with `exit_code` 0, before `verdict` can be `signal_observed`. A single run is not enough.
- **Code decides.** `signal_observed` is set by the harness fields above. A referee `VERDICT=` line is not `signal_observed` and does not change `verdict`.
- **Finding untouched.** The run snapshot `state` is not `confirmed`.
- **Proof.** Save `poc_run.json`, the PoC source, and the finding state. Record feature id `canary-evidence`.

## Gotchas

- A hub `success_regex` that the PoC prints itself is self-certification. Matching it is a failed canary drive.
- Exit 0 without the canary is `inconclusive`, not `signal_observed`.
- Sandbox missing yields `sandbox_unavailable`. Report that precondition. Do not switch the runner to host execution.
- k equals 1 in the output fails `canary-repeat`.
- Do not copy the canary into the PoC to make the marker appear.
