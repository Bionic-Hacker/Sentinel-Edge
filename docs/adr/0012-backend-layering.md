# ADR-0012: Backend layering and explicit response models

- **Status:** Accepted
- **Date:** 2026-10-06

## Decision
`api` (routers, auth dependencies) → `services` (business rules) → `repositories` (data access)
→ `models` (ORM). Routers return **Pydantic response models**, never ORM objects. Request models
use `extra="forbid"`.

## Security impact
- Excessive data exposure (OWASP API3) is prevented structurally: a field is returned only if it
  is declared on the response model.
- Mass assignment is blocked by `extra="forbid"` (tested in Phase 1 with a synthetic model).
- Authorization lives in one place (router dependencies plus service-level object checks).
