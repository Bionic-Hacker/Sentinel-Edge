# ADR-0005: Tamper-evident audit log

- **Status:** Accepted (implementation in Phase 2, archive in Phase 4)
- **Date:** 2026-10-06
- **Phase:** 2, 4

## Context
Spec §29 requires audit logs to be tamper-resistant. An attacker or insider with application
database access could otherwise alter or delete records of their actions (repudiation, T-AUD-01).

## Decision
1. **Hash chain:** each audit record stores `prev_hash` and
   `record_hash = SHA-256(canonical_json(record) || prev_hash)`. A verification tool walks the
   chain and reports the first break.
2. **Database grants:** the application's DB role has `INSERT` and `SELECT` on `audit_log`, and no
   `UPDATE`, `DELETE`, or `TRUNCATE`. Migrations run under a separate role.
3. **Off-host archive:** periodic export to an S3 bucket with **Object Lock** (governance mode,
   retention period) and SSE-KMS, so records survive database compromise.
4. Every record carries user, timestamp, action, resource, result, source IP, and correlation ID.

## Security impact
Tampering becomes detectable (chain), constrained (grants), and recoverable (archive).
Controls C-AUD-01..03.

## Alternatives considered
Amazon QLDB (deprecated by AWS); CloudWatch Logs only (no integrity proof on its own).

## Consequences
Audit writes are serialized per chain; acceptable at expected volume.
