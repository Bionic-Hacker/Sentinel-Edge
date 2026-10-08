# API Endpoint Inventory

All 56 endpoints at v0.5.0, generated from the endpoint policy registry and the authorization matrix. *Public¹* means same-origin only (allowed `Origin` plus the `X-SentinelEdge-CSRF` header). *Setup* means any signed-in user, even before forced setup is complete. *Own²* means non-admins may read only their own record; others get 404 and the attempt is audited.

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
| `GET /security-events` | ADMIN, SEC_ENG, ANALYST, VIEWER | medium | 120 / min per user | API3, API5 |
| `GET /security-events/{id}` | ADMIN, SEC_ENG, ANALYST, VIEWER | medium | 120 / min per user | API3, API5 |
| `GET /incidents` | ADMIN, SEC_ENG, ANALYST, VIEWER | medium | 120 / min per user | API3, API5 |
| `POST /incidents` | ADMIN, SEC_ENG, ANALYST³ | medium | 60 / min per user | API3, API5, API6 |
| `GET /incidents/assignees` | ADMIN, SEC_ENG, ANALYST | low | 120 / min per user | API3, API5 |
| `GET /incidents/{id}` | ADMIN, SEC_ENG, ANALYST, VIEWER | medium | 120 / min per user | API3, API5 |
| `PATCH /incidents/{id}` | ADMIN, SEC_ENG, ANALYST³ | high | 60 / min per user | API1, API3, API5 |
| `POST /incidents/{id}/transitions` | ADMIN, SEC_ENG, ANALYST³ | high | 60 / min per user | API1, API5, API6 |
| `POST /incidents/{id}/assignment` | ADMIN, SEC_ENG, ANALYST³ | medium | 60 / min per user | API1, API5 |
| `POST /incidents/{id}/notes` | ADMIN, SEC_ENG, ANALYST | low | 60 / min per user | API3, API4 |
| `POST /incidents/{id}/events` | ADMIN, SEC_ENG, ANALYST³ | medium | 60 / min per user | API1, API3 |
| `GET /security/overview` | ADMIN, SEC_ENG, ANALYST, VIEWER | medium | 120 / min per user | API3, API5 |
| `GET /applications` | All roles³ | medium | 120 / min per user | API1, API3 |
| `POST /applications` | ADMIN, SEC_ENG³ | medium | 30 / min per user | API3, API5 |
| `GET /applications/owners` | ADMIN, SEC_ENG | low | 120 / min per user | API3, API5 |
| `GET /applications/{id}` | All roles³ | medium | 120 / min per user | API1, API3 |
| `PATCH /applications/{id}` | ADMIN, SEC_ENG³ | medium | 30 / min per user | API1, API3, API5 |
| `GET /simulator/scenarios` | ADMIN, SEC_ENG, ANALYST | low | 120 / min per user | API5 |
| `GET /simulator/runs` | ADMIN, SEC_ENG, ANALYST | low | 120 / min per user | API5 |
| `POST /simulator/runs` | ADMIN, SEC_ENG | medium | 6 / min per user | API4, API5, API6 |
| `GET /simulator/waf-rules` | ADMIN, SEC_ENG, ANALYST | low | 120 / min per user | API5 |
| `PUT /simulator/waf-rules/{rule_id}` | ADMIN, SEC_ENG | medium | 30 / min per user | API5 |
| `GET /vulnerabilities` | All roles³ | medium | 120 / min per user | API1, API3, API4 |
| `GET /vulnerabilities/overview` | All roles³ | low | 120 / min per user | API1, API3 |
| `GET /vulnerabilities/{id}` | All roles³ | medium | 120 / min per user | API1, API3 |
| `POST /vulnerabilities/{id}/status` | ADMIN, SEC_ENG, DEVELOPER³ | high | 60 / min per user | API1, API5, API6 |
| `POST /vulnerabilities/{id}/acceptances` | ADMIN, SEC_ENG³ | high | 30 / min per user | API1, API5, API6 |
| `POST /vulnerabilities/{id}/acceptances/{acceptance_id}/revoke` | ADMIN, SEC_ENG³ | medium | 30 / min per user | API1, API5 |
| `GET /scans` | All roles³ | low | 120 / min per user | API1, API3 |
| `GET /scans/{id}` | All roles³ | low | 120 / min per user | API1, API3 |
| `GET /sboms` | All roles³ | low | 120 / min per user | API1, API3 |
| `GET /sboms/{id}` | All roles³ | low | 120 / min per user | API1, API3, API4 |
| `GET /sboms/{id}/document` | All roles³ | low | 6 / min per user | API1, API4 |

All paths are under `/api/v1`. Every route is also subject to the global ceiling of 600 requests per minute per IP. Admins cannot demote, deactivate, delete or reset MFA on themselves, and the last active admin cannot be removed. ³ An object-level rule applies on top of the role: analysts change only incidents they own (closing, reopening, re-rating and assigning others are lead-only), developers see only applications they own (and only those applications' findings, scans and SBOMs), and SentinelEdge itself cannot be retired. Marking a false positive and accepting or revoking a risk are lead-only. Incident work uses the `investigation` limit (60 per minute per user). The CycloneDX download allows 6 per minute per user, because each is a complete document.
