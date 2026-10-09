# Threat Register

Condensed from `docs/threat-model.md` (version 0.6). L×I is likelihood × impact, each from 1 to 3.

| ID | STRIDE | Threat | L×I | Status |
|---|---|---|---|---|
| T-EDGE-01 | D | Volumetric / L7 flood | 2×2 | Planned (P5) |
| T-EDGE-02 | T/I | TLS downgrade, weak ciphers | 1×3 | HSTS in app; edge P5 |
| T-EDGE-03 | E | Origin bypass around CloudFront/WAF | 2×3 | Planned (P4–5) |
| T-EDGE-04 | T | Cache poisoning / deception | 1×3 | Partly mitigated; edge P5 |
| T-EDGE-05 | S | Host header injection | 2×2 | **Mitigated (P1)** |
| T-EDGE-06 | T | Clickjacking, sniffing, XSS via missing headers | 2×2 | **Mitigated (P1)** |
| T-ORG-01 | I | Plaintext edge → origin | 1×2 | Planned (P4) |
| T-ORG-02 | S | Spoofed `X-Forwarded-For` | 2×2 | **Mitigated locally (P6)** |
| T-ORG-03 | T | Request smuggling / desync | 1×3 | Planned (P4) |
| T-ID-01 | S | Credential stuffing / brute force | 3×3 | **Mitigated (P2, P6), detected (P7)**; WAF P5 |
| T-ID-02 | S | Access-token theft via XSS | 2×3 | **Mitigated (P2)** |
| T-ID-03 | S | Refresh-token replay | 2×3 | **Mitigated (P2)**; opens an incident (P7) |
| T-ID-04 | T | CSRF on cookie-authenticated refresh | 2×2 | **Mitigated (P2)** |
| T-ID-05 | I | Account enumeration | 3×1 | **Mitigated (P2)** |
| T-ID-06 | D | Concurrent tab refresh trips reuse detection | 2×1 | **Mitigated (P2)** |
| T-ID-07 | S | TOTP replay within window | 2×3 | **Mitigated (P2)** |
| T-ID-08 | I | Database dump yields working second factors | 1×3 | **Mitigated (P2)** |
| T-ID-09 | E | Default or shared bootstrap credentials | 2×3 | **Mitigated (P2)** |
| T-ID-10 | D | Deliberate lockout of a known account | 2×1 | Accepted; bounded per IP (P6) |
| T-API-01 | E | BOLA | 3×3 | **Mitigated (P2, P7)**; probing detected |
| T-API-02 | E | BFLA | 2×3 | **Mitigated (P2)** |
| T-API-03 | T | Mass assignment | 2×3 | **Mitigated (P2, P6 sweep)** |
| T-API-04 | D | Unrestricted resource consumption | 3×2 | **Mitigated in app (P6)**; WAF P5 |
| T-API-05 | I | Excessive data exposure | 2×3 | **Mitigated (P2, P6 sweep)** |
| T-API-07 | T | Injection (SQL, command) | 2×3 | **Mitigated in app (P2), detected (P7)**; WAF P5 |
| T-API-08 | I | SSRF via user-supplied URLs | 1×3 | Not exposed; guard ready (P6) |
| T-API-09 | I | Error messages leak internals | 2×2 | **Mitigated (P1)** |
| T-API-10 | R | Requests untraceable | 2×2 | **Mitigated (P1)** |
| T-API-11 | T | Log injection / forging | 2×2 | **Mitigated (P1)** |
| T-API-12 | I | Undocumented or debug endpoints | 2×2 | **Mitigated (P1, P6)** |
| T-API-13 | D | Throttled flood fills the audit log | 2×2 | **Mitigated (P6)** |
| T-DB-01 | I | Database exposed to the internet | 1×3 | Local analogue mitigated; AWS P3–4 |
| T-DB-02 | I | Database credential theft | 2×3 | Scoped locally (P2); Secrets Manager P4 |
| T-DB-03 | E | Over-privileged app database role | 2×3 | **Mitigated (P2)** |
| T-DB-04 | I | Unencrypted data at rest / in transit | 1×3 | Planned (P4) |
| T-AI-01..06 | LLM01/02/05/06/10 | Prompt injection (direct, indirect), insecure output, data leakage, excessive agency, unbounded cost | — | Planned (P9) |
| T-CICD-01 | E | Stolen long-lived cloud keys from CI | 2×3 | Planned (P11); no keys exist |
| T-CICD-02 | T | Hijacked third-party action | 1×3 | **Mitigated (P1)** |
| T-SC-01 | T | Vulnerable or malicious dependency | 2×3 | **Mitigated (P1, P8)**: Trivy, SBOMs, OS fixes at build |
| T-SEC-01 | I | Secret committed to git | 2×3 | **Mitigated (P1)** |
| T-IAC-01/02 | T/I | Cross-environment change; state disclosure | 1×3 | Planned (P3) |
| T-WAF-01/02 | T/E | WAF weakened without review or via the app | — | Planned (P5) |
| T-AUD-01 | R | Audit records altered or deleted | 2×3 | **Mitigated (P2)** except tail deletion (P4) |
| T-CNT-01 | E | Container breakout / privilege escalation | 1×3 | **Mitigated (P1)** |
| T-INP-01 | D | Non-ASCII digits crash a comparison | 2×1 | **Mitigated (P2)**; found by tests |
| T-AZ-01 | E | Role compared by identity, failing open or closed | 2×3 | **Mitigated (P2)**; found by tests |
| T-SO-01 | T/R | Incident evidence or timeline altered | 2×3 | **Mitigated (P7)** |
| T-SO-02 | T | Simulated activity mixed with real | 2×3 | **Mitigated (P7)** |
| T-SO-03 | D | Event flooding buries detections | 2×2 | **Mitigated (P7)**; retention P12 |
| T-SO-04 | D | ReDoS in detection patterns | 2×2 | **Mitigated (P7)** |
| T-SO-05 | T | Stored XSS through evidence | 2×3 | **Mitigated (P7)** |
| T-SO-06 | E | Incident workflow bypass | 2×2 | **Mitigated (P7)** |
| T-SO-07 | T | Lost update between responders | 2×1 | **Mitigated (P7)** |
| T-SO-08 | E | Simulator abused against another system | 1×3 | **Mitigated (P7)** |
| T-SO-09 | I | Secrets captured in evidence | 2×3 | **Mitigated (P7)** |
| T-VM-01 | T | Scanner output carries markup or escapes into the UI | 2×2 | **Mitigated (P8)** |
| T-VM-02 | R | Risk acceptance silences a finding indefinitely or is rewritten | 2×3 | **Mitigated (P8)** |
| T-VM-03 | T | Finding marked fixed without a fix | 2×3 | **Mitigated (P8)** |
| T-VM-04 | E | Gate passes because a scanner crashed | 2×3 | **Mitigated (P8)** |
| T-VM-05 | T | Compromised or swapped scanner image | 1×3 | **Mitigated (P8)** |
| T-VM-06 | T | Authenticated DAST changes platform data | 2×2 | **Mitigated (P8)** |
| T-VM-07 | I | Developers read other teams' findings | 2×2 | **Mitigated (P8)** |
| T-VM-08 | D | Hostile import exhausts the API or floods events | 1×2 | **Mitigated (P8)** |
| T-GOV-01 | E/R | Requester approves their own exception or change | 2×3 | **Mitigated (P10)** |
| T-GOV-02 | T/R | Decision rewritten, or a closed request revived | 2×3 | **Mitigated (P10)** |
| T-GOV-03 | R | Accepted risk outlives its justification | 2×2 | **Mitigated (P10)** |
| T-GOV-04 | T | In-app catalogue drifts from the reviewed documents | 2×2 | **Mitigated (P10)** |
| T-GOV-05 | T | Posture score unexplainable or counting planned controls | 2×2 | **Mitigated (P10)** |
| T-GOV-06 | I | Developers read other teams' models and exceptions | 2×2 | **Mitigated (P10)** |
| T-GOV-07 | T/R | Threat model deleted to hide threats, or by the wrong role | 2×2 | **Mitigated (P10)** |
| T-GOV-08 | E | Change request used to change the real WAF | 1×3 | **Mitigated (P10)**: simulated WAF only |
| T-GOV-09 | T | Stored XSS through governance text | 2×3 | **Mitigated (P10)** |
