# Runbook: Application outage (the API is down or failing)

- **Severity guidance:** SEV1 if no one can sign in; SEV2 if errors are partial
- **Owner role:** ADMIN
- **Related threats / controls:** T-API-13, T-COST-01; C-MON-01
- **Last exercised:** not yet (Phase 12)

## 1. Detection
The `no healthy API task` or server-error alarm fires (security-alerts topic); `make edge-check` fails at "the API is ready"; users see 502 or 503.

## 2. Triage (first 15 minutes)
Which layer? `curl -sI https://<domain>/api/v1/health` (edge), ALB target health in the console, `aws logs tail /ecs/sentineledge-dev/api --since 30m`. Locally: `docker compose ps`, `make logs`.

## 3. Investigation
Common causes, from the windows so far: the task refuses its settings in a deployed environment (log says which); the database is unreachable or refuses TLS (`/api/v1/ready` 503); an image older than a fix (health checks 400); a stopped Spot task the service is replacing.

## 4. Containment
Keep the edge up: CloudFront and WAF stay in front, so nothing is exposed while the API is down. Do not open security groups or disable the Host allow-list to get it back.

## 5. Remediation
Fix the cause, then redeploy through the pipeline: `make deploy-check`, `make deploy`, read the plan, `make deploy-finish`. For a bad release, deploy the previous tag the same way.

## 6. Validation
`make deploy-verify`: all 21 edge checks pass and the audit chain matches its anchor; the alarm returns to OK.

## 7. Rollback
Redeploy the last good tag: `git switch --detach vX.Y.Z` is not deployable (the gate wants main), so revert on main with a pull request and deploy that.

## 8. Post-incident
Record what happened in the incident's timeline, and update this runbook if a step was wrong.
