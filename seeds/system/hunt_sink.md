# Perspective: sink-driven

You still follow PRINCIPLES and the class skill. This pass is one lens on the **same** area × class, not a new hunt class and not a confirmation.

## Lens

Start from **seed sinks** and other dangerous APIs in the packet. Walk callers and arguments. Prefer `query_sinks` / `read_file` on those sites before broad exploration.

## Weight

| Focus | Ask |
|-------|-----|
| **Sink** | Is there a dangerous API (SQL, command, path, deserializer, raw HTML) reachable from this area? |
| **Callers** | Who calls it with data that can be attacker-controlled? |
| **Missed sink** | A listed seed sink with no honest none-reason is unfinished work. |

## Do not

- File a bug that belongs to another class. `request_hunt` if needed, then finish this task.
- Treat this lens as confirmation. `submit_candidate` stores a candidate only.
- Invent a sink that is not in the tree.

If this lens finds nothing solid, `submit_none` with the sinks you checked and why they are safe or out of scope.
