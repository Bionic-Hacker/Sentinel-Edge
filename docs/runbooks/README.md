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
| [SQL injection event](sql-injection-event.md) | 7 ✓ |
| [API abuse](api-abuse.md) | 7 ✓ |
| [Credential stuffing](credential-stuffing.md) | 7 ✓ |
| [Bot traffic and scanning](bot-traffic.md) | 7 ✓ |
| Vulnerability remediation | 8 |
| AI prompt injection | 9 |
