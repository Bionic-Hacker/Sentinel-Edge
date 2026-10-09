output "vpc_id" {
  description = "VPC ID."
  value       = module.network.vpc_id
}

output "app_subnet_ids" {
  description = "App subnets (ECS tasks, internal ALB)."
  value       = module.network.app_subnet_ids
}

output "data_subnet_ids" {
  description = "Isolated data subnets (RDS)."
  value       = module.network.data_subnet_ids
}

output "security_group_ids" {
  description = "The ALB, app and database security groups."
  value = {
    alb = module.security_groups.alb_security_group_id
    app = module.security_groups.app_security_group_id
    db  = module.security_groups.db_security_group_id
  }
}

output "nat_mode" {
  description = "App-tier egress in effect."
  value       = module.network.nat_mode
}

output "ecr_api_repository_url" {
  description = "Where the API image is pushed (Phase 4)."
  value       = module.ecr_api.repository_url
}

output "certificate_status" {
  description = "Both certificates: PENDING_VALIDATION until the DNS record is published."
  value = {
    edge_us_east_1 = module.certificate_edge.status
    origin         = module.certificate_origin.status
  }
}

output "certificate_validation_records" {
  description = "Publish these in DNS (is-a.dev pull request). Both certificates use the same record."
  value       = distinct(concat(module.certificate_edge.validation_records, module.certificate_origin.validation_records))
}
