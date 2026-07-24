"""
Pipeline stages.

Default path: recon → hunt → validate_mech → [optional validate_llm] → render.
Operator / idle extras: develop_poc (Report workshop), tool_gaps (CLI or auto),
generate_skill (custom hunt profile from brief),
generate_run_skills (N target-specific skills after recon when dynamic_skills).

Near-duplicate merge helpers live in ``stages.dedup`` (not a leased task kind).
"""
