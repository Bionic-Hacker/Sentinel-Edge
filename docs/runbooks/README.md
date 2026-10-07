# Runbooks

Runbooks are first-class artifacts (spec §52). Each one follows [TEMPLATE.md](TEMPLATE.md) and is
written in the phase that introduces its failure mode, then exercised in a demo scenario.

| Runbook | Phase |
|---|---|
| [Compromised credential](compromised-credential.md) | 2 ✓ |
| Application outage | 4 |
| Origin connectivity issue | 5 |
| TLS failure | 5 |
| Certificate expiration | 5 |
| WAF false positive | 5 |
| SQL injection event | 7 |
| API abuse | 7 |
| Credential stuffing | 7 |
| Bot traffic | 7 |
| Vulnerability remediation | 8 |
| AI prompt injection | 9 |
