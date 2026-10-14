# Interview demo

A 15-minute walk through SentinelEdge, locally (`make dev`) or in a deploy window. Every attack
here is the built-in simulator's: it sends nothing over the network, only to SentinelEdge's own
detection, and its data is labelled Simulated everywhere (ADR-0019). Sign in as an ADMIN.

## The main story (5 minutes)

1. **Dashboard**, Live view: the status line explains itself; switch to **Simulated**.
2. **Automation → Attack simulator**: run **SQL injection**.
3. **Threats** (Simulated): the events, each with its HTTP analysis and verbatim evidence.
4. **Incidents**: correlation opened one (COR-003). Assign it to yourself and move it to
   *Investigating*; every step lands in its timeline and the audit chain.
5. **AI Security**: analyse the incident. The answer quotes evidence verbatim or is rejected,
   and it can only *propose* tightening actions.
6. Approve the proposal as a lead (a second lead if you raised it): the simulated WAF rule goes
   to **Block**.
7. Run the scenario again: the requests are now blocked at the edge; the **Dashboard** shows
   them as stopped.
8. In AWS: **WAF** and **Certificates** show the real edge, labelled Real AWS.

## Five scenarios

Each follows attack → detection → control → evidence → investigation → remediation →
validation. The runbook is the procedure a responder would follow.

| Scenario | Attack (simulator) | Detection | Control and evidence | Remediation | Runbook |
|---|---|---|---|---|---|
| SQL injection | SQL injection | HTTP analysis SQLI rules; COR-003 | Simulated WAF block; in AWS, `make edge-check` shows AWS WAF blocking it | AI proposal to block, approved by a lead | [sql-injection-event](docs/runbooks/sql-injection-event.md) |
| Credential stuffing | Credential stuffing | Failed sign-ins; COR-001, COR-002 | Lockout, per-IP limits, MFA; in AWS the WAF sign-in rate rule | Contain the source; reset affected accounts | [credential-stuffing](docs/runbooks/credential-stuffing.md) |
| API abuse | API abuse | Rate-limit trips, BOLA probing | Token buckets per IP and account; 404 for others' records, audited | Throttle or block the client | [api-abuse](docs/runbooks/api-abuse.md) |
| Prompt injection | Any scenario, then analyse an event whose payload tries to steer the model | Prompt-risk score on the input; the model never sees it as instructions | Delimited, pseudonymised input; verbatim-evidence contract; tighten-only proposals | The answer is rejected or marked; nothing is applied without a lead | [ai-prompt-injection](docs/runbooks/ai-prompt-injection.md) |
| Certificate expiration | Certificate expiry | A `certificate` event 30 days ahead (high at 14) | In AWS: both ACM certificates read live (`make report KIND=certificates`) | Restore the validation record or CAA through Terraform | [certificate-expiration](docs/runbooks/certificate-expiration.md) |

## Questions worth being ready for

- *Why can't the AI change the WAF?* It has no permission to (ADR-0008); proposals only tighten,
  and a human approves in the simulated WAF; real WAF changes are Terraform pull requests.
- *Why is CI not deploying?* The account forbids OIDC and a stored key is the thing to avoid;
  CI gates, and the deploy refuses anything not green (ADR-0030).
- *How do you know the audit log is complete?* Hash chain, insert-only grants, triggers, and
  hourly anchors in S3 Object Lock that catch deletion of the newest records (ADR-0005).
