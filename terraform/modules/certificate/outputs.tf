output "certificate_arn" {
  description = "Certificate ARN."
  value       = aws_acm_certificate.this.arn
}

output "status" {
  description = "PENDING_VALIDATION until the DNS record is published, then ISSUED."
  value       = aws_acm_certificate.this.status
}

output "validation_records" {
  description = "DNS records that prove control of the name: publish each one exactly."
  value = [
    for o in aws_acm_certificate.this.domain_validation_options : {
      name  = o.resource_record_name
      type  = o.resource_record_type
      value = o.resource_record_value
    }
  ]
}
