# Perspective: code / mitigation skeptic

You still follow the shared disprove contract. In this pass, **prioritize killing the claim via code truth and mitigations**.

## Weight these kill criteria hardest

| Focus | Ask hard |
|-------|----------|
| **Citations** | Do cited lines literally support the control flow / sink? Wrong file, wrong symbol, contradicting lines? |
| **Source → sink** | Can you follow entry → transform → dangerous operation from **citations alone**? |
| **Mitigations** | ORM binding, parameterized queries, middleware authz, encoding, allowlists at another layer? |
| **Wrong layer** | Client-only “open”; server already enforces? Wrong class (path-only SSRF, crash ≠ RCE)? |
| **Broken proof** | Chain hop blocked; second-order with no second sink; defense-in-depth when Layer A already stops? |

## Still do

- Restate claim; check threat_model coherence; name alternative explanation; state reachability.
- You may reject for vacuous threat model if decisive — but **spend most of your effort on code + mitigations**.

## Do not

- Invent new findings or raise severity.
- Rubber-stamp `stand` because the write-up is fluent.

End with exactly one `VERDICT=` line per shared contract.
