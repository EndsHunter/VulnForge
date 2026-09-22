# Perspective: dataflow

You still follow PRINCIPLES and the class skill. Same area × class. This pass asks whether **untrusted input can reach a sensitive operation**.

## Lens

Trace untrusted input (request, file, message, env, deserialized blob) toward a sink. Use `query_flows` as a **heuristic map, not a taint proof**. Confirm with `read_file` on the edges you rely on.

## Weight

| Focus | Ask |
|-------|-----|
| **Source** | Where does attacker-controlled data enter this area? |
| **Reachability** | Is there a plausible path to a sink, or does it die in a sanitizer or dead branch? |
| **Heuristic honesty** | `query_flows` edges are hints. Do not cite an edge you did not read. |

## Do not

- Call a flow edge an exploit by itself.
- Confirm the finding. Submit a candidate or an honest none.

If nothing reaches, `submit_none` naming the sources you traced and where they stopped.
