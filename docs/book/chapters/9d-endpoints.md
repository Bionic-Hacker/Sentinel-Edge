# API Endpoint Inventory

All 23 endpoints at v0.3.0, generated from the endpoint policy registry. *Public¹* means same-origin only (allowed `Origin` plus the `X-SentinelEdge-CSRF` header). *Setup* means any signed-in user, even before forced setup is complete. *Own²* means non-admins may read only their own record; others get 404 and the attempt is audited.

| Endpoint | Access | Risk | Rate limit | OWASP |
|---|---|---|---|---|
| `GET /health` | Public | low | 120 / min per IP | API8 |
| `GET /ready` | Public | low | 120 / min per IP | API4, API8 |
| `POST /auth/login` | Public¹ | critical | 20 / 2 min per IP | API2, API4, API6 |
| `POST /auth/mfa/verify` | Public¹ | critical | 20 / 2 min per IP | API2, API4 |
| `POST /auth/refresh` | Public¹ (cookie) | high | 30 / min per IP | API2 |
| `POST /auth/password/forgot` | Public¹ | high | 5 / 15 min per IP | API2, API4, API6 |
| `POST /auth/password/reset` | Public¹ | critical | 5 / 15 min per IP | API2, API6 |
| `POST /auth/logout` | Setup | low | 60 / min per user | API2 |
| `GET /auth/me` | Setup | low | 60 / min per user | API3 |
| `POST /auth/mfa/enroll` | Setup | high | 10 / 5 min per user | API2 |
| `POST /auth/mfa/enroll/confirm` | Setup | high | 10 / 5 min per user | API2, API4 |
| `POST /auth/password/change` | Setup | high | 10 / 5 min per user | API2 |
| `GET /platform/capabilities` | All roles | low | 120 / min per user | API9 |
| `GET /users` | ADMIN | medium | 120 / min per user | API3, API5 |
| `POST /users` (invite) | ADMIN | high | 30 / min per user | API3, API5, API6 |
| `GET /users/{id}` | ADMIN any; others own² | medium | 120 / min per user | API1, API3 |
| `PATCH /users/{id}` | ADMIN | critical | 30 / min per user | API1, API3, API5 |
| `POST /users/{id}/mfa/reset` | ADMIN | critical | 30 / min per user | API1, API5 |
| `DELETE /users/{id}` | ADMIN | critical | 30 / min per user | API1, API5 |
| `GET /audit-logs` | ADMIN, SEC_ENG | medium | 120 / min per user | API3, API5 |
| `GET /audit-logs/verify` | ADMIN, SEC_ENG | medium | 6 / min per user | API4, API5 |
| `GET /api-security/inventory` | ADMIN, SEC_ENG, DEVELOPER | medium | 120 / min per user | API5, API9 |
| `GET /api-security/owasp` | ADMIN, SEC_ENG, DEVELOPER | low | 120 / min per user | API5, API9 |

All paths are under `/api/v1`. Every route is also subject to the global ceiling of 600 requests per minute per IP. Admins cannot demote, deactivate, delete or reset MFA on themselves, and the last active admin cannot be removed.
