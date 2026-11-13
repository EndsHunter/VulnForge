# Settings auto-tune on Flint

Measured on 13 Nov 2026 against `http://10.0.0.146:11501/v1`, model `flint`. Nothing was saved.

## Before

The morning probe took 48 seconds. It recommended a 32k context, 5,461 max output tokens, 20 tool rounds, a 180 second timeout, and 2 workers.

- Flint puts thinking in `reasoning`. That probe only read `reasoning_content`, so a 16 token request spent the budget on thinking and returned no answer. It never marked Flint as a reasoning model.
- Latency was the average of those cut-off calls, about 0.58 seconds. That is how the timeout landed at 180 seconds.
- The context ladder opened at about 256k tokens, used the whole 45 second budget on that one request, and fell back to a guessed 32k.
- Hand checks the same morning: about 43k tokens finished in 14 seconds, about 87k in 33 seconds, and about 173k was still running at 180 seconds. The chars/4 estimate ran about 30% under `usage.prompt_tokens`.
- It recommended 2 workers without sending two requests.
- The tool check was a single `ping`.

## After

The same endpoint, the new probe, 17.8 seconds. `apply` was off.

| Step | Result |
| --- | --- |
| Models | `flint` only. No context field on the card. 0.6s. |
| Resolve | HTTP 200 in 0.3s. The 32 token call came back with `reasoning` and an empty answer. |
| Tools | Called `ping`, then answered `pong` on the next turn. |
| Generation | A finished answer, 28 completion tokens in 0.2s. |
| Concurrency | One request 0.12s, two together 0.09s. The short calls overlapped. |
| Context | 4,096 tokens in 1.2s, 8,192 in 1.7s, aimed 32,768 in 12.6s. The server counted that last accept as 43,177 tokens, about 1.30× the local estimate. The next rung is 131,072, and the probe stopped there because the 32k accept had already taken 12.6s. |

Recommended values:

| Knob | Before | After | Confidence |
| --- | --- | --- | --- |
| Context window | 32,768 guessed | 38,859 (90% of 43,177) | medium |
| Max output | 5,461 | 9,714 | high |
| HTTP timeout | 180s | 900s | medium |
| Concurrent agents | 2, unmeasured | 1 | high |
| Tool rounds | 20 | 20 | medium |
| Max context fraction | (not what that run was judged on) | 0.30 | low |

The 900 second timeout is the reasoning-model floor. The 0.2 second sample would only support about three minutes, and it does not show a full thinking turn. The UI reason now says that. The run above still had the older sentence, which credited the short sample for the 900 seconds.

Concurrent agents stay at 1 because Flint thinks before it answers. The two short requests did overlap, so this run does not show that the server is strictly one-at-a-time. A long prefill can still block the next call. That was the 173k hand check.

`/v1/messages` returned HTTP 200. The probe keeps `chat_completions`, which is what the tool loop used.
