# A public ACM certificate for one exact host name, validated by DNS. Public certificates are free
# and renew themselves while the validation record stays in DNS.
#
# The validation record is the same for every certificate this account requests for this name,
# in any Region and after any re-creation. So exactly one certificate module per name publishes it
# (publish_validation_record), and the other only waits on it.
#
# Waiting for ISSUED (wait_for_issued) is off until the zone is delegated: before that, nothing can
# resolve the record and the wait would only time out. Phase 5 depends on the waited ARN.

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

resource "aws_route53_record" "validation" {
  for_each = var.publish_validation_record ? {
    for o in aws_acm_certificate.this.domain_validation_options : o.domain_name => o
  } : {}

  zone_id         = var.zone_id
  name            = each.value.resource_record_name
  type            = each.value.resource_record_type
  ttl             = 300
  records         = [each.value.resource_record_value]
  allow_overwrite = false
}

resource "aws_acm_certificate_validation" "this" {
  count = var.wait_for_issued ? 1 : 0

  certificate_arn = aws_acm_certificate.this.arn
  validation_record_fqdns = [
    for o in aws_acm_certificate.this.domain_validation_options : trimsuffix(o.resource_record_name, ".")
  ]

  timeouts {
    create = "30m"
  }

  depends_on = [aws_route53_record.validation]
}
