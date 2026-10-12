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
  description = "Both certificates: PENDING_VALIDATION until the zone is delegated, then ISSUED (empty while app_domain is empty)."
  value = {
    edge_us_east_1 = one(module.certificate_edge[*].status)
    origin         = one(module.certificate_origin[*].status)
  }
}

output "dns_delegation" {
  description = "Add these NS records at the parent domain's DNS (the registrar) to hand the platform's name to Route 53."
  value = var.app_domain == "" ? null : {
    parent_domain = join(".", slice(split(".", var.app_domain), 1, length(split(".", var.app_domain))))
    host          = split(".", var.app_domain)[0]
    type          = "NS"
    values        = module.dns_zone[0].name_servers
  }
}
