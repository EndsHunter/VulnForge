"""Finding identity and near-dup merge (not leased stages)."""

from vulnforge.findings.identity import compute_stable_key
from vulnforge.findings.merge import (
    cluster_findings,
    merge_findings,
    merge_near_duplicate,
)

__all__ = [
    "cluster_findings",
    "compute_stable_key",
    "merge_findings",
    "merge_near_duplicate",
]
