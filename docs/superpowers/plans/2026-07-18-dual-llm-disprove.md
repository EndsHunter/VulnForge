# Dual LLM Disprove Implementation Plan

> **For agentic workers:** Implement task-by-task. Steps use checkbox syntax.

**Goal:** Run two perspective-based adversarial disprove LLMs per finding and show `N/2 llm verified` on Report.

**Architecture:** One `validate_llm` task runs sequential dual chats (threat + code prompts). Aggregate: both `reject` → `rejected_llm`; else `needs_human`. Report reads `body.validation_llm`.

**Tech Stack:** Python (validate_llm, packet), prompt markdown, vanilla JS report UI, pytest FakeLLM.

---

### Task 1: Prompts + pack_disprove

**Files:**
- Create: `prompts/v1/disprove_threat.md`, `prompts/v1/disprove_code.md`
- Modify: `prompts/v1/disprove.md` (shared contract; keep kill criteria)
- Modify: `vulnforge/packet.py` — `pack_disprove(..., perspective: str | None = None)`
- Modify: `config/default.yaml` — `llm.disprove_verifiers`

### Task 2: Dual validate_llm

**Files:**
- Modify: `vulnforge/stages/validate_llm.py`
- Defaults for two verifiers; sequential chat; aggregate; body shape with `verifiers[]`, `stood`, `total`, `label`

### Task 3: Report UI

**Files:**
- Modify: `vulnforge/ui/static/report.js` — table badge + detail section
- Modify: `vulnforge/ui/static/styles.css` — badge colors

### Task 4: Tests

**Files:**
- Modify: `tests/test_validate_llm_safety.py` — two responses per dual path; new mixed cases

### Task 5: Verify + commit

- `pytest tests/test_validate_llm_safety.py -v`
- Commit implementation

---

**Execution:** inline in this session (user requested implement plan).
