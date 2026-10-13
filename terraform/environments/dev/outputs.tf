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

output "ecr_dbadmin_repository_url" {
  description = "Where the role-bootstrap image is pushed."
  value       = module.ecr_dbadmin.repository_url
}

output "audit_anchor_bucket" {
  description = "Where the audit chain's head is anchored (S3 Object Lock)."
  value       = module.audit_anchors.bucket
}

output "workload" {
  description = "What make ecs-task needs during a deploy window (null between windows)."
  value = var.workload ? {
    region           = var.region
    cluster          = module.ecs[0].cluster_name
    service          = module.ecs[0].service_name
    task_definitions = module.ecs[0].task_definitions
    log_groups       = module.ecs[0].log_groups
    subnets          = module.network.app_subnet_ids
    security_group   = module.security_groups.app_security_group_id
    alb_dns_name     = module.alb[0].dns_name
    alb_arn          = module.alb[0].arn
    db_host          = module.database[0].address
    distribution_id  = module.edge[0].distribution_id
    spa_bucket       = module.edge[0].spa_bucket
    waf_log_group    = module.waf[0].log_group
    url              = "https://${var.app_domain}"
  } : null
}
