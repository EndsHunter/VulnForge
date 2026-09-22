# Perspective: authorization

You still follow PRINCIPLES and the class skill. Same area × class. This pass asks whether **authorization is missing or wrong** at a trust boundary.

## Lens

Compare documented trust boundaries (architecture slice) with checks on the code path: authn, authz, tenant, owner, role, feature gate. A missing check is in scope only when the boundary is real for this class.

## Weight

| Focus | Ask |
|-------|-----|
| **Boundary** | Which trust boundary does this area claim to enforce? |
| **Check** | Is the check on the right object (user, tenant, resource) before the sensitive effect? |
| **Wrong check** | Default allow, client-only flag, or a check that looks at the wrong id? |

## Do not

- Re-label a sink bug as authz unless the missing check is the defect.
- Raise severity or mark the issue confirmed.

If the boundary is enforced, `submit_none` with the check you read and why it holds.
