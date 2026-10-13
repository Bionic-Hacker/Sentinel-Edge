# The platform's own public DNS zone, delegated from the owner's domain (ADR-0025).
#
# The owner's domain (for example bionichacker.dev) stays at its registrar's DNS; only this one
# name (sentineledge.bionichacker.dev) is handed to Route 53, with four NS records added at the
# registrar. Tearing SentinelEdge down then removes only its own zone, and other projects get
# their own names the same way.

resource "aws_route53_zone" "this" {
  # checkov:skip=CKV2_AWS_38: DNSSEC needs a DS record in the parent zone, and the registrar's DNS (Porkbun) cannot hold DS records for a delegated name. Recorded as a residual risk in ADR-0025.
  # checkov:skip=CKV2_AWS_39: Query logging is configured in modules/dns-query-logs (us-east-1, attached by the dev stack); Checkov's graph does not follow the zone ID across modules.
  name          = var.zone_name
  comment       = "SentinelEdge platform zone, delegated from the parent domain (ADR-0025)."
  force_destroy = false

  # Deleting the zone while the registrar still delegates to its name servers leaves a dangling
  # delegation that someone else can claim by creating zones until Route 53 hands them the same
  # servers. Remove the NS records at the registrar first, then this line (runbook in
  # docs/aws-setup.md).
  lifecycle {
    prevent_destroy = true
  }
}

# Only Amazon may issue certificates for the zone and every name in it, and nobody may issue a
# wildcard certificate.
resource "aws_route53_record" "caa" {
  zone_id = aws_route53_zone.this.zone_id
  name    = var.zone_name
  type    = "CAA"
  ttl     = 3600
  records = concat(
    [for ca in var.caa_issuers : "0 issue \"${ca}\""],
    ["0 issuewild \";\""],
    var.caa_iodef == "" ? [] : ["0 iodef \"${var.caa_iodef}\""],
  )
}
