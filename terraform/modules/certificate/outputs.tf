output "certificate_arn" {
  description = "Certificate ARN (may still be PENDING_VALIDATION; use issued_certificate_arn to depend on issuance)."
  value       = aws_acm_certificate.this.arn
}

output "issued_certificate_arn" {
  description = "The ARN once ACM has issued it, or null while wait_for_issued is false. What CloudFront and the ALB use."
  value       = one(aws_acm_certificate_validation.this[*].certificate_arn)
}

output "status" {
  description = "PENDING_VALIDATION until the DNS record resolves, then ISSUED (as of the last refresh)."
  value       = aws_acm_certificate.this.status
}

output "validation_records" {
  description = "The DNS records that prove control of the name."
  value = [
    for o in aws_acm_certificate.this.domain_validation_options : {
      name  = o.resource_record_name
      type  = o.resource_record_type
      value = o.resource_record_value
    }
  ]
}
