"""
Pipeline stages.

Default path: recon → hunt → validate_mech → [optional validate_llm] → render.
Operator / idle extras: develop_poc (Report workshop), tool_gaps (CLI or auto),
generate_skill (custom hunt profile from brief),
generate_run_skills (N target-specific skills after recon when dynamic_skills).
Deferred (enqueue fails as progress): gapfill, dedup.run, feedback.
"""
