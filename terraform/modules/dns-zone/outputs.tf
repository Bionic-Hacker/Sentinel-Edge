output "zone_id" {
  description = "Route 53 hosted zone ID."
  value       = aws_route53_zone.this.zone_id
}

output "name_servers" {
  description = "The zone's four name servers: add each as an NS record for this name at the parent domain's DNS."
  value       = aws_route53_zone.this.name_servers
}

output "caa_records" {
  description = "The CAA values published at the zone apex."
  value       = aws_route53_record.caa.records
}
