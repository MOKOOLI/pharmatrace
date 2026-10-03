# Threat Model (STRIDE)

| Threat | Asset | Attack | Control | Test |
|---|---|---|---|---|
| **S**poofing | user identity | token forgery / role escalation | HMAC-SHA256 signature, constant-time compare, role whitelist | `TestBrokenAuthentication` |
| **T**ampering | audit history | DB admin edits/deletes custody rows | SHA-256 hash chain, `/ledger/verify`, hourly n8n check | `TestLedgerTamperEvidence` |
| **R**epudiation | custody events | "we never received that box" | every event signed into chain with actor id | `test_full_chain_of_custody` |
| **I**nfo disclosure | user list | username enumeration on login | identical error for unknown user / wrong password | manual |
| **D**oS | `/verify` | mass scanning | input length cap; rate limit on roadmap | roadmap |
| **E**levation | units | IDOR: transfer/dispense someone else's units | ownership check on every mutation | `TestBrokenObjectLevelAuth` |
| Injection | DB | SQLi via uid | 100% parameterized queries | `TestInjection` |
| Supply chain | deps | vulnerable packages | `pip-audit` + `bandit` in CI | CI |

## Known limitations (honest pentest notes)
- Demo user store is in-memory; production needs a users table + account lockout.
- No token revocation list yet (short TTL mitigates).
- Ledger proves *integrity*, not *availability*: an attacker who drops the whole table is detected only by the n8n check (row count = 0) — anchor Merkle roots externally.
