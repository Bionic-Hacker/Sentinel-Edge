# Certificates

SentinelEdge's TLS certificates, from issue to expiry (Phases 3 and 5). Code:
`terraform/modules/certificate` (issue), `app/services/aws_edge.py` (monitoring,
[ADR-0029](adr/0029-the-edge-read-back.md)).

## The two certificates

| Certificate | Region | Used by | Why there |
|---|---|---|---|
| `sentineledge.bionichacker.dev` | us-east-1 | CloudFront (viewer TLS) | CloudFront accepts certificates only from us-east-1 |
| `sentineledge.bionichacker.dev` | us-east-2 | The internal ALB (CloudFront to origin) | A load balancer uses certificates from its own Region |

Both are public ACM certificates for the exact name, no wildcard, RSA-2048, with certificate
transparency logging. They exist between windows (free), so a window never waits for issuance.

## Issue and validation

- **DNS validation.** ACM asks for one CNAME record; Terraform publishes it in the platform's own
  Route 53 zone, which is delegated from the owner's domain (ADR-0025). Both certificates share
  the record, since it is the same name.
- **CAA.** The zone allows only Amazon to issue for the name, and nobody to issue a wildcard
  (`0 issue "amazon.com"`, `0 issuewild ";"`). A certificate requested elsewhere is refused.
- **Trust chain.** Amazon Trust Services roots, trusted by every current browser and OS.

## Renewal and expiry

Public certificates are now valid for about 200 days. ACM renews DNS-validated certificates on
its own, about 60 days before expiry, as long as the validation record still resolves and the
certificate is in use; a renewed certificate is deployed to CloudFront and the ALB without any
change. Do not delete the validation record.

**Monitoring.** In a deploy window the API reads both certificates from ACM every five minutes
and shows them on the **Certificates** page: status, expiry and days left, renewal eligibility
and status, what uses them. It raises a certificate event on the Threats page:

| Condition | Severity |
|---|---|
| Expired, revoked, failed or validation timed out | Critical |
| Renewal failed | High |
| 14 days or less left | High |
| 30 days or less left | Medium |

Once per certificate, condition and day. The API's role may list and describe certificates,
never read a private key (ACM does not release them for public certificates anyway).

## If something goes wrong

- **Renewal failed:** check that the validation CNAME still exists in the zone
  (`make tf-plan STACK=dev` shows it as a change if it was removed) and that the delegation at the
  registrar still points at the zone's four name servers (`dig NS sentineledge.bionichacker.dev`).
- **Revocation** (a compromised name, not a compromised key: ACM keeps the key): request a new
  certificate by replacing the resource (`terraform apply -replace=...` from a reviewed plan);
  `create_before_destroy` keeps the old one serving until the new one is issued.
- **Expired:** the edge and the ALB stop serving TLS; treat as an outage and follow the renewal
  check above.
