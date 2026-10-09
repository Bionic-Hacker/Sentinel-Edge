# A public ACM certificate for one exact host name, validated by DNS. Public certificates are free
# and renew themselves while the validation record stays in DNS.
#
# The validation record is the same for every certificate this account requests for this name,
# in any Region and after any re-creation, so it is published once (an is-a.dev pull request for
# SentinelEdge) and never changes. Terraform does not wait for validation here: the certificate
# is issued whenever the record appears, and Phase 5 waits for ISSUED before CloudFront uses it.

resource "aws_acm_certificate" "this" {
  domain_name       = var.domain_name
  validation_method = "DNS"
  key_algorithm     = "RSA_2048"

  options {
    certificate_transparency_logging_preference = "ENABLED"
  }

  lifecycle {
    create_before_destroy = true
  }
}
