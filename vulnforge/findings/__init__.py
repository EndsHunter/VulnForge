"""Finding identity and near-dup merge (not leased stages)."""

from vulnforge.findings.identity import compute_stable_key
from vulnforge.findings.merge import merge_near_duplicate

__all__ = ["compute_stable_key", "merge_near_duplicate"]
