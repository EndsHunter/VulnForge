---
name: injection
description: >-
  Hunts untrusted data reaching SQL, command, code, template, path, or
  deserialize interpreters without safe APIs or context-correct encoding.
  Use when grepping execute/raw/query, subprocess/shell=True, eval/Function/vm,
  render_template_string/Jinja/SpEL/OGNL, path joins into open/send_file, or
  pickle/yaml.load/unserialize; second-order store-then-concat; injection via
  keys/names/headers/metadata. Prefer evidence from the target tree over
  pre-trained sink assumptions. Do not use when the path is LLM/agent-mediated
  (file ai-llm instead).
---

# Hunt class: injection

## Principles

- **Prefer evidence over pre-training.** Cite paths you actually grepped/read; do not invent payloads for parsers you never opened.
- **Be certain.** If the sink/check is unclear, read more code before filing.
- **Provide evidence.** file:line or path+symbol; concrete attacker action.
- **Correctness over completeness.** One solid source→sink beats checklist spam.
- Honest `submit_none` when nothing solid.

## When to use

- String-built SQL/NoSQL/LDAP queries; dynamic shells; SSTI/expression engines
- Path joins into open/include/send_file; XXE on user-facing XML parsers
- Code sinks: `eval`, `Function`, `vm`, dynamic import/compile
- Second-order: store “safe,” later concatenate into a sink elsewhere
- Injection via **keys/names/headers/metadata**, not only values
- Prefer **exceptions** to safe defaults: f-strings, `+` concat, dynamic ORDER BY/identifiers

## When not to use / Scope

- Untrusted text → **LLM/agent/tool-args** → sink → file `ai-llm` instead (never dual-file same path+symbol)
- SSRF that only controls path (host fixed) → `feature-abuse`
- Pure authz miss without an interpreter sink → `access-control`
- Log format strings with no privileged consumer or response reflection → not a finding
- Related skills: `ai-llm` for model-mediated sinks; `feature-abuse` for SSRF/export; `access-control` for authz-only

## Decision tree

```
1. Inventory sinks (grep stack cues) before any checklist
2. For each sink: walk callers → untrusted boundary (HTTP, queue, file, webhook, DB field)
3. Cover every path into the sink? (main builder AND FTS/search, sql.raw, bulk, admin tools)
4. Safe APIs end-to-end (bound params, argv arrays shell=False, context-correct encoding)?
     YES → skip this sink
     NO / partial escape / wrong context → candidate
5. No exploitable sink gap after real inventory → submit_none
```

## Rules quick reference

| Rule | Summary |
|------|---------|
| Sink-first | Grep interpreters before hunting “user input” |
| Bound params | ORM/query builders with binds end-to-end are usually safe |
| Shell arrays | `shell=False` + fixed argv ≠ string-built shell |
| Context encoding | HTML-escape is not SQL-safe; SQL bind is not shell-safe |
| Identifiers | Dynamic ORDER BY/table/column need allowlists, not quotes alone |
| Second-order | Stored fields re-used in sinks count as sources |
| Keys matter | JSON keys, headers, filenames can be the injectable surface |
| Dual-file ban | Same path+symbol never under both `injection` and `ai-llm` |
| Dead demos | Test-only / unmounted routes are not prod findings |
| Impact | Name interpreter effect (data leak, RCE, file read) not “uses SQL” |

## Focus

- SQL, NoSQL, LDAP, OS command, code (`eval`, `Function`, `vm`, dynamic import)
- Template/expression engines (Jinja, Freemarker, SpEL, OGNL, Velocity, Thymeleaf)
- Path traversal; XXE on user-facing XML parsers
- Header/log injection only with real impact (response split, log→SIEM→action)
- Prefer exceptions to safe defaults over “app uses a database”

## Hunt workflow

1. **Inventory** — grep sinks (SQL/exec/template/path/deserialize); list files:lines
2. **Trace** — for each sink, walk callers to an untrusted boundary; note transforms
3. **Prove** — confirm missing parameterized API / wrong encoding context on that path
4. **Evidence** — one concrete attacker action + expected interpreter effect; `write_evidence`
5. **Submit or none** — `submit_candidate` with `weakness_class: injection`, or honest `submit_none`

## Stack cues

```
execute\(|executemany|\.raw\(|\.query\(|f["'].*(SELECT|INSERT|UPDATE)|WHERE .*\+|ORDER BY
Statement\.execute|createNativeQuery|jdbcTemplate|DBI->|pg_query|mysqli_|sqlite3_exec
subprocess\.|os\.system|popen|shell=True|Runtime\.exec|ProcessBuilder|child_process|execSync
system\(|popen\(|CreateProcess|ShellExecute|qx\{|open\([^,]+,\s*['"]\|
eval\(|Function\(|vm\.|compile\(|__import__|importlib
render_template_string|Template\(|Jinja|freemarker|SpelExpression|OGNL|Velocity
open\(|Path\(|join\(.*req|send_file|include\(|readFile.*\+|fopen\(|FileInputStream
pickle\.loads|yaml\.load\(|unserialize|ObjectInputStream|readObject
```

## Required evidence

- Source **and** sink citations (path:line or path+symbol)
- Missing control named (no bind, shell=True, raw concat, wrong context)
- Payload narrative: input → interpreter effect → impact
- `write_evidence` before `submit_candidate`

## False positives

- ORM/query builder with bound parameters end-to-end
- `shell=False` + fixed argv; static SQL with zero user interpolation
- Test-only / dead demo routes not on prod surfaces
- Log format strings with no privileged consumer or response reflection

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| “Uses SQL somewhere” | No source→sink, no exploit story |
| Model-mediated sink as injection | Wrong class; dual-file noise — use `ai-llm` |
| Invented payloads | Parser assumptions you did not read |
| Dual-filing path+symbol | Same bug twice under two classes |
| Checklist completeness | LOW spam instead of one solid finding |
| Partial escape as safe | Wrong-context encoding still injectable |

## Submit checklist

- `write_evidence` first: source → sink, missing control, sample payload narrative, impact
- `weakness_class: injection`
- **Good:** *“Unauth POST /search builds SQL via f-string at `db.py:88` from `q`; returns other users’ rows.”*
- **Bad:** *“Uses SQL somewhere; could be injectable.”*
- Or honest `submit_none` after real sink inventory
