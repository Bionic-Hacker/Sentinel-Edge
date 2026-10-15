# NIST SP 800-53 Rev. 5 crosswalk

How SentinelEdge's control catalogue (`docs/security-controls.md`, generated into
`backend/app/governance/catalogue.json`) maps to NIST SP 800-53 Rev. 5. It is written for an
assessor (an ISSO or an auditor) who works in 800-53 terms.

**What this is.** A mapping of where each 800-53 control is implemented in this system, citing the
SentinelEdge control IDs that carry the evidence. It is not an authorization package: there is no
system security plan, no categorisation under FIPS 199, no selected baseline and no assessment by
an independent party. The system holds synthetic data only and runs in short deploy windows.

**How it is kept honest.** `test_nist_crosswalk` checks on every build that every SentinelEdge
control ID cited here exists in the catalogue, and that every implemented control is cited at
least once, so the mapping cannot drift from what is built.

**Coverage terms.**

| Term | Meaning |
|---|---|
| Implemented | The system implements the control's intent; the cited controls carry evidence |
| Partial | Some of the control is implemented; the gap is named |
| Inherited | Provided by AWS under the shared-responsibility model |
| Organisational | A policy, personnel or procedural control outside a one-person portfolio system |

## Access control (AC)

| 800-53 | Control | SentinelEdge controls | Coverage |
|---|---|---|---|
| AC-2 | Account management | C-ID-07, C-ID-08 | Implemented: administrators create accounts (no self-registration, no email path); generated temporary passwords; forced change and MFA enrollment |
| AC-3 | Access enforcement | C-API-01, C-API-02, C-API-11, C-SO-05 | Implemented: every route declares one access class, enforced on the server and swept as every role |
| AC-4 | Information flow enforcement | C-EDGE-02, C-NET-01, C-NET-02, C-API-12 | Implemented: private origin, security-group chain, egress only through NAT, outbound allow-list |
| AC-5 | Separation of duties | C-GOV-03, C-GOV-04, C-VM-03, C-AI-05 | Implemented: a second lead approves one's own proposals; exceptions and risk acceptances need a lead |
| AC-6 | Least privilege | C-IAM-01, C-IAM-03, C-DB-01, C-AI-07, C-SEC-03 | Implemented: one IAM role per function, per-table database grants, one Bedrock permission |
| AC-7 | Unsuccessful logon attempts | C-ID-05, C-WAF-03 | Implemented: lockout shared by password and MFA failures; WAF sign-in rate rule |
| AC-12 | Session termination | C-ID-02, C-ID-03 | Implemented: 15-minute access tokens checked against a live session; refresh rotation |
| AC-17 | Remote access | C-EDGE-01, C-IAM-02 | Implemented: TLS-only access through the edge; AWS reached only from the owner's signed-in machine |

## Awareness and training (AT)

Organisational. The runbooks (`docs/runbooks/`) and `INTERVIEW_DEMO.md` are the closest material.

## Audit and accountability (AU)

| 800-53 | Control | SentinelEdge controls | Coverage |
|---|---|---|---|
| AU-2 | Event logging | C-SO-01, C-LOG-01, C-LOG-04, C-DNS-02, C-NET-04 | Implemented: security events, structured logs, CloudTrail, DNS query and VPC flow logs |
| AU-3 | Content of audit records | C-AUD-01, C-LOG-01 | Implemented: actor, action, target, time and correlation ID |
| AU-6 | Audit review, analysis and reporting | C-SO-04, C-EDGE-05, C-GOV-10 | Implemented: correlation rules, WAF read-back, explainable posture |
| AU-9 | Protection of audit information | C-AUD-02, C-AUD-03, C-LOG-02 | Implemented: append-only grants and triggers, hourly anchors in S3 Object Lock, redaction |
| AU-10 | Non-repudiation | C-AUD-01, C-SO-06, C-GOV-08 | Implemented: hash chain; timeline entries committed to it; decisions final |
| AU-11 | Audit record retention | C-LOG-04, C-NET-04, C-DNS-02, C-WAF-02 | Implemented: one year for trail, flow and query logs; WAF logs 30 days |
| AU-12 | Audit record generation | C-SO-01, C-SO-02 | Implemented |

## Assessment, authorization and monitoring (CA)

| 800-53 | Control | SentinelEdge controls | Coverage |
|---|---|---|---|
| CA-2 | Control assessments | C-GOV-05, C-GOV-06 | Partial: self-assessment (`SECURITY_ASSESSMENT.md`) with evidence checked on every build; no independent assessor |
| CA-5 | Plan of action and milestones | C-GOV-04, C-VM-02 | Partial: exceptions and remediation SLAs serve the purpose; no formal POA&M |
| CA-7 | Continuous monitoring | C-GOV-10, C-MON-01, C-MON-02, C-CICD-06 | Implemented: posture snapshots, alarms, the scan pipeline on every commit |
| CA-8 | Penetration testing | C-CICD-11, C-CICD-12 | Partial: authenticated DAST in CI; the live-edge ZAP scan is planned for the Phase 12 window |

## Configuration management (CM)

| 800-53 | Control | SentinelEdge controls | Coverage |
|---|---|---|---|
| CM-2 | Baseline configuration | C-IAC-01, C-IAC-04 | Implemented: all infrastructure in Terraform, tested and scanned |
| CM-3 | Configuration change control | C-IAC-03, C-GOV-02, C-GOV-03, C-WAF-04 | Implemented: saved plans applied after review; code-owner review; WAF only through Terraform |
| CM-6 | Configuration settings | C-CNT-01, C-WEB-01, C-WEB-02, C-API-08 | Implemented: hardened containers, security headers, API docs off when deployed |
| CM-7 | Least functionality | C-CNT-01, C-API-08, C-NET-00 | Implemented |
| CM-8 | System component inventory | C-API-10, C-VM-06 | Implemented: API inventory, SBOMs per artifact |

## Contingency planning (CP)

| 800-53 | Control | SentinelEdge controls | Coverage |
|---|---|---|---|
| CP-9 | System backup | C-DB-04, C-IAC-02 | Partial: automated backups (one day in dev); versioned state; synthetic data only |
| CP-10 | System recovery and reconstitution | C-IAC-01 | Implemented: the whole environment is rebuilt from code; RTO and RPO in `docs/disaster-recovery.md` |

## Identification and authentication (IA)

| 800-53 | Control | SentinelEdge controls | Coverage |
|---|---|---|---|
| IA-2 | Identification and authentication | C-ID-01, C-ID-02 | Implemented |
| IA-2(1), IA-2(2) | MFA for privileged and non-privileged accounts | C-ID-04, C-ID-08 | Partial: TOTP required for ADMIN and SECURITY_ENGINEER; optional for other roles |
| IA-2(8) | Replay-resistant authentication | C-ID-04, C-ID-03 | Implemented: TOTP time-step stored once; refresh-token reuse revokes the session |
| IA-5 | Authenticator management | C-ID-01, C-ID-07, C-SEC-04 | Implemented: Argon2id, generated temporary passwords, signing-key rotation with key IDs |
| IA-8 | Non-organisational users | C-API-02 | Implemented: no anonymous access beyond health and sign-in |
| IA-11 | Re-authentication | C-ID-02, C-ID-09 | Implemented: 15-minute tokens; token held in memory only |

## Incident response (IR)

| 800-53 | Control | SentinelEdge controls | Coverage |
|---|---|---|---|
| IR-4 | Incident handling | C-SO-04, C-SO-05, C-SO-07 | Implemented: detection to closure with server-enforced workflow |
| IR-5 | Incident monitoring | C-SO-06, C-SO-01 | Implemented: tamper-evident timeline |
| IR-6 | Incident reporting | C-SO-05 | Partial: reporting inside the platform; no external notification path |
| IR-8 | Incident response plan | C-GOV-03 | Partial: runbooks per scenario (`docs/runbooks/`), `docs/incident-response.md` |

## Maintenance (MA), media protection (MP), physical and environmental (PE)

Inherited from AWS for the hosting layer. No physical media or premises belong to this system.

## Planning (PL), program management (PM), personnel security (PS)

Organisational. The architecture decisions (`docs/adr/`) and the threat model are the nearest
planning artefacts.

## PII processing and transparency (PT)

Not applicable: the system processes synthetic data only. C-AI-04 pseudonymises client addresses
and accounts before any data reaches a model.

## Risk assessment (RA)

| 800-53 | Control | SentinelEdge controls | Coverage |
|---|---|---|---|
| RA-3 | Risk assessment | C-GOV-06, C-GOV-07 | Implemented: STRIDE threat model maintained as code; application threat models |
| RA-5 | Vulnerability monitoring and scanning | C-CICD-01, C-CICD-02, C-CICD-06, C-VM-01, C-VM-05 | Implemented |
| RA-7 | Risk response | C-VM-03, C-GOV-04, C-GOV-09 | Implemented: time-limited, justified acceptances with compensating controls |

## System and services acquisition (SA)

| 800-53 | Control | SentinelEdge controls | Coverage |
|---|---|---|---|
| SA-8 | Security and privacy engineering principles | C-GOV-01, C-API-13 | Implemented: provenance register; enumerations kept consistent across tiers |
| SA-10 | Developer configuration management | C-CICD-05, C-GOV-02 | Implemented |
| SA-11 | Developer testing and evaluation | C-CICD-04, C-CICD-07, C-CICD-08, C-CICD-11, C-IAC-04 | Implemented: 90% coverage floor, project Semgrep rules, scan gate, DAST |
| SA-15 | Development process, standards and tools | C-CICD-06, C-CICD-09, C-WEB-03 | Implemented |

## System and communications protection (SC)

| 800-53 | Control | SentinelEdge controls | Coverage |
|---|---|---|---|
| SC-5 | Denial-of-service protection | C-WAF-01, C-WAF-03, C-API-03, C-COST-01 | Partial: WAF and application rate limits, spend ceiling; no AWS Shield Advanced or Bot Control |
| SC-7 | Boundary protection | C-EDGE-02, C-LB-01, C-NET-01, C-NET-02, C-WAF-01, C-WAF-02 | Implemented |
| SC-8 | Transmission confidentiality and integrity | C-EDGE-01, C-LB-01, C-DB-03 | Implemented: TLS at the edge, to the origin and to the database |
| SC-12 | Cryptographic key establishment and management | C-SEC-04, C-IAM-03 | Implemented: KMS keys with documented policies; secrets generated into Secrets Manager |
| SC-13 | Cryptographic protection | C-ID-01, C-ID-04, C-DB-02 | Implemented |
| SC-18 | Mobile code | C-WEB-02, C-WEB-04 | Implemented: strict CSP, cross-origin isolation |
| SC-23 | Session authenticity | C-ID-03, C-ID-06 | Implemented: `__Host-` SameSite=Strict cookies, CSRF Origin checks |
| SC-28 | Protection of information at rest | C-DB-02, C-AWS-01, C-IAC-02 | Implemented: KMS encryption for the database, EBS and state |
| SC-39 | Process isolation | C-CNT-01 | Implemented: one non-root, read-only container per task |

## System and information integrity (SI)

| 800-53 | Control | SentinelEdge controls | Coverage |
|---|---|---|---|
| SI-2 | Flaw remediation | C-VM-02, C-CICD-10 | Implemented: remediation SLAs; OS fixes at image build |
| SI-3 | Malicious code protection | C-CICD-06 | Partial: image and dependency scanning; no runtime anti-malware |
| SI-4 | System monitoring | C-SO-02, C-SO-04, C-EDGE-05, C-EDGE-06, C-MON-01, C-MON-02 | Implemented |
| SI-5 | Security alerts and advisories | C-VM-05 | Implemented: new critical and high findings become security events |
| SI-7 | Software and information integrity | C-CICD-03, C-AUD-01 | Implemented: SHA-pinned actions, images by digest, hash-chained records |
| SI-10 | Information input validation | C-API-04, C-API-07, C-SO-03, C-AI-01, C-VM-04 | Implemented |
| SI-11 | Error handling | C-API-06, C-LOG-03 | Implemented |
| SI-15 | Information output filtering | C-AI-02, C-AI-03, C-SO-09 | Implemented: AI output contract; attacker text rendered as text only |

## Supply chain risk management (SR)

| 800-53 | Control | SentinelEdge controls | Coverage |
|---|---|---|---|
| SR-3 | Supply chain controls and processes | C-CICD-03, C-CICD-09 | Implemented: pinned actions and scanner images |
| SR-4 | Provenance | C-VM-06, C-GOV-01 | Implemented: SBOMs with SHA-256 per artifact |
| SR-11 | Component authenticity | C-CICD-02 | Implemented: hash-pinned Python dependencies |

## AI-specific controls

800-53 has no AI family. These map to NIST AI RMF and the OWASP Top 10 for LLM Applications
instead; listed here so every catalogue control is cited.

| Concern | SentinelEdge controls |
|---|---|
| Prompt injection and untrusted data (LLM01) | C-AI-01, C-AI-04 |
| Output handling (LLM05) | C-AI-02, C-AI-03 |
| Excessive agency (LLM06) | C-AI-05 |
| Unbounded consumption (LLM10) | C-AI-06 |
| Model access least privilege | C-AI-07 |

## Platform and governance controls cited elsewhere

Controls that support the mappings above without being a primary implementation of one 800-53
control: C-DNS-01 (DNS as code, CM-2), C-API-05 (same-origin API client, SC-7), C-API-09 (endpoint
policy registry, AC-3), C-NET-03 (trusted client IP, AU-3), C-SEC-01 and C-SEC-02 (secret
scanning and no secrets in the repository, IA-5), C-EDGE-03 and C-EDGE-04 (edge headers and the
private SPA bucket, SC-7), C-SO-08 (attack simulator safe by construction, SA-8).
