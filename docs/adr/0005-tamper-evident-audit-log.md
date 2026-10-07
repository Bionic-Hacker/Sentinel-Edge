# ADR-0005: Tamper-evident audit log

- **Status:** Accepted — chain, grants and triggers implemented in Phase 2; archive in Phase 4
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

## Addendum: as implemented (Phase 2)

- **A fourth layer was added: triggers.** `UPDATE`, `DELETE` and `TRUNCATE` on `audit_log` raise an
  error for every role, including the table owner. Bypassing them requires `ALTER TABLE ...
  DISABLE TRIGGER`, which only the owner can do and which is itself DDL.
- **Concurrency:** writers take `pg_advisory_xact_lock` before reading the chain head, so
  concurrent requests extend the chain one at a time (tested with eight concurrent writers).
- **Canonical form:** `record_hash = SHA-256(prev_hash || "\n" || canonical JSON)` with sorted keys
  and UTC microsecond timestamps; details are redacted and size-bounded *before* hashing.
- **Verification:** `make verify-audit`, `GET /api/v1/audit-logs/verify` (itself audited), and the
  UI's "Verify integrity" button. Each reports the first broken record.

### Limitation: deleting the newest records
A hash chain proves that what remains is unaltered, but it cannot by itself prove that nothing
was removed from the **end**. Deleting the last N records leaves a shorter chain that still
verifies. Detecting that needs the current head hash anchored somewhere the attacker can't reach.
Phase 4 provides it: periodic export of the head hash and records to S3 with Object Lock. Until
then, the verify output prints the head hash so it can be recorded elsewhere, and triggers plus
grants make this attack require table-owner rights.
