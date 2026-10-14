# Runbooks

Runbooks are first-class artifacts (spec §52). Each one follows [TEMPLATE.md](TEMPLATE.md) and is
written in the phase that introduces its failure mode, then exercised in a demo scenario.

| Runbook | Phase |
|---|---|
| [Compromised credential](compromised-credential.md) | 2 ✓ |
| [Application outage](application-outage.md) | 12 ✓ |
| [Origin connectivity issue](origin-connectivity.md) | 12 ✓ |
| [TLS failure](tls-failure.md) | 12 ✓ |
| [Certificate expiration](certificate-expiration.md) | 12 ✓ |
| [WAF false positive](waf-false-positive.md) | 12 ✓ |
| [SQL injection event](sql-injection-event.md) | 7 ✓ |
| [API abuse](api-abuse.md) | 7 ✓ |
| [Credential stuffing](credential-stuffing.md) | 7 ✓ |
| [Bot traffic and scanning](bot-traffic.md) | 7 ✓ |
| [Vulnerability remediation](vulnerability-remediation.md) | 8 ✓ |
| [Governance: exceptions, changes, threat model review](governance.md) | 10 ✓ |
| [AI prompt injection](ai-prompt-injection.md) | 9 ✓ |
