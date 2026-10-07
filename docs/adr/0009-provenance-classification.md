# ADR-0009: Provenance classification for every capability and record

- **Status:** Accepted — implemented in Phase 1
- **Date:** 2026-10-06
- **Phase:** 1 onward

## Context
Spec §43 requires that simulated functionality is never misrepresented as real AWS
functionality. Documentation alone drifts; it needs enforcement.

## Decision
- A `Provenance` enum — `REAL_AWS`, `LOCAL`, `SIMULATED`, `DEMO` — in `app/core/provenance.py`.
- A **capability register** (`app/core/capabilities.py`) served at
  `GET /api/v1/platform/capabilities` and rendered on every UI module page with badges.
- **Tests enforce the rules:** nothing may be marked implemented REAL_AWS before an AWS phase
  ships it; simulator and demo entries can never be REAL_AWS; implemented entries cannot come
  from future phases.
- From Phase 2, every telemetry table has a non-null `provenance` column.

## Security impact
Integrity of the platform's own claims. An analyst can always tell whether a "blocked request"
was blocked by AWS WAF or by the simulator.

## Consequences
Each phase must update the register and its guard test deliberately.
