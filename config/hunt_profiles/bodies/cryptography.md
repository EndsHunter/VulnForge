---
name: cryptography
description: >-
  Hunts secret and crypto misuse that forges tokens, decrypts data, or breaks
  integrity/auth — not algorithm fashion. Use when grepping hardcoded
  keys/tokens, weak password hashing (MD5/SHA alone), JWT verify gaps
  (alg=none, verify=False, weak HS secrets, kid/jku/x5u), InsecureSkipVerify,
  static IV/ECB/homebrew, or predictable tokens. Prefer evidence of forge/decrypt
  path over “use AES-GCM someday.”
---

# Hunt class: cryptography

## Principles

- **Prefer evidence over pre-training.** Cite material and acceptance/verify sites you read.
- **Be certain.** If prod loads secrets from vault, confirm the path before filing hardcoded defaults.
- **Provide evidence.** What the attacker forges/decrypts/reads; file:line.
- **Correctness over completeness.** One forge path beats crypto style nits.
- Honest `submit_none` when vault + solid verify hold.

## When to use

- Hardcoded private keys, HMAC secrets, API tokens, passwords in tree
- Weak password storage: MD5/SHA1/SHA256 alone, unsalted, reversible encrypt-as-hash
- JWT: alg=none/confusion, verify skipped, weak HS secret, kid/jku/x5u abuse
- ECB/homebrew; empty/static IV+key; disabled TLS verify on sensitive channels
- Predictable tokens; encryption without integrity; fail-open crypto errors

## When not to use / Scope

- Protocol framing / OAuth redirect story clearer as `web-protocol-auth` (file **once**, best class)
- Dev secrets clearly never loaded in prod paths
- “Use AES-GCM someday” without forge/decrypt path; KDF cost style nits alone
- Related skills: `web-protocol-auth` for OAuth/session/Host framing; `obvious` for committed secrets with deploy impact; `access-control` for authz without crypto break

## Decision tree

```
1. Grep crypto APIs, secret material, JWT libraries, TLS clients
2. Trace key/token: generate → store → verify → rotate
3. Name what attacker FORGES / DECRYPTS / READS
4. Prefer broken verification or secret exposure over style nits
5. Vault + solid verify + decent entropy → submit_none
```

## Rules quick reference

| Rule | Summary |
|------|---------|
| Impact first | Name forge/decrypt/auth bypass, not algorithm preference |
| Material + accept | Hardcoded secret needs a consumer that trusts it |
| Password storage | Fast hashes alone; reversible “encryption as hash” |
| JWT verify | Pin alg; never trust header alone; check claims |
| TLS verify | Skip only when no secret/auth transport — still cite path |
| Token entropy | Math.random / sequential for auth tokens is a break |
| Integrity | Encrypt-only without MAC/AEAD enables tamper |
| Fail-open | Crypto errors that default to “valid” are critical |
| Dual-file ban | Same JWT forge path not under crypto + web-protocol-auth |
| Dev gates | Confirm prod config actually loads the weak material |

## Focus

- Hardcoded private keys, HMAC secrets, API tokens, passwords in tree
- Password storage and comparison (timing-safe where relevant)
- JWT verification gaps and key confusion
- Weak primitives with practical break path; disabled TLS on sensitive channels
- Predictable session/reset/API tokens; fail-open verify

## Hunt workflow

1. **Inventory** — secrets, crypto APIs, JWT/TLS verify sites
2. **Trace** — generate → store → verify → rotate for each material
3. **Prove** — attacker capability and concrete forge/decrypt/auth effect
4. **Evidence** — material site + acceptance path; `write_evidence`
5. **Submit or none** — `weakness_class: cryptography`, or honest `submit_none`

## Stack cues

```
password\s*=\s*['\"]|secret\s*=\s*['\"]|api[_-]?key|BEGIN (RSA |OPENSSH |EC )?PRIVATE
md5\(|sha1\(|hashlib\.md5|DigestUtils\.md5
bcrypt|scrypt|argon2|pbkdf2|CompareHashAndPassword
jwt\.|jsonwebtoken|jose\.|PyJWT|algorithm.*none|verify\s*=\s*False
InsecureSkipVerify|rejectUnauthorized:\s*false
Math\.random|random\.randint|hmac\.|sign\(|verify\(
```

## Required evidence

- Secret/algorithm site, attacker capability, concrete forge/decrypt/auth bypass
- Citations on material and acceptance/verify path

## False positives

- Dev/test secrets gated out of prod config
- Legacy crypto on non-sensitive telemetry with documented acceptance
- KDF cost style nits without practical break
- TLS verify off only for local docker healthchecks with no secret transport

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| Algorithm fashion | No impact without forge/decrypt path |
| Dual-file JWT | Same path under crypto + protocol classes |
| “Weak crypto” alone | Missing acceptance/use evidence |
| Ignoring vault | Filing dead defaults never loaded |
| Timing nits only | Without sensitive compare context |

## Submit checklist

- `write_evidence` first: secret/algorithm site + forge/decrypt path
- `weakness_class: cryptography`
- **Good:** *“HS256 secret is `dev-secret` in `config.py:12`; forges admin JWT accepted at `auth.py:90`.”*
- **Bad:** *“Use AES-GCM someday.”*
- Or honest `submit_none`
