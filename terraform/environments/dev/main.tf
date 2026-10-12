# The dev environment's foundation (Phase 3). Almost everything here is free while idle: the VPC,
# subnets, route tables, gateway endpoint, security groups, an empty registry and two
# certificates. The platform's DNS zone costs $0.50 a month. The only hourly item is NAT, and it is
# off (nat_mode = "none") between deploy windows. Phase 4 adds the workload; Phase 5 the edge.

locals {
  name = "${var.project}-${var.environment}"
}

# The platform key from the account stack, found by alias so the stacks share no state.
data "aws_kms_alias" "platform" {
  name = "alias/${var.project}-platform"
}

module "network" {
  source = "../../modules/network"

  name                  = local.name
  cidr_block            = var.vpc_cidr
  availability_zone_ids = var.availability_zone_ids
  nat_mode              = var.nat_mode
  kms_key_arn           = data.aws_kms_alias.platform.target_key_arn
}

module "security_groups" {
  source = "../../modules/security-groups"

  name   = local.name
  vpc_id = module.network.vpc_id
}

module "ecr_api" {
  source = "../../modules/ecr"

  repository_name = "${var.project}/api"
  kms_key_arn     = data.aws_kms_alias.platform.target_key_arn
}

# The platform's own zone, delegated from the owner's domain (ADR-0025). Created with the first
# apply; its four name servers are then added as NS records at the registrar (dns_delegation).
module "dns_zone" {
  source = "../../modules/dns-zone"
  count  = var.app_domain == "" ? 0 : 1

  zone_name = var.app_domain
  caa_iodef = var.caa_iodef
}

# CloudFront only accepts certificates from us-east-1 (Phase 5). It publishes the validation
# record, which the home-Region certificate shares.
module "certificate_edge" {
  source    = "../../modules/certificate"
  count     = var.app_domain == "" ? 0 : 1
  providers = { aws = aws.us_east_1 }

  domain_name               = var.app_domain
  zone_id                   = module.dns_zone[0].zone_id
  publish_validation_record = true
  wait_for_issued           = var.dns_delegated
}

# The internal ALB's certificate, in the home Region (Phase 4). CloudFront forwards the viewer's
# Host header, so the CloudFront-to-ALB hop is verified against the same name.
module "certificate_origin" {
  source = "../../modules/certificate"
  count  = var.app_domain == "" ? 0 : 1

  domain_name     = var.app_domain
  wait_for_issued = var.dns_delegated

  # Its validation record is the edge certificate's; wait until that exists.
  depends_on = [module.certificate_edge]
}

# The migrations-and-roles image (Phase 4): postgres client, the role-bootstrap script and the
# RDS certificate bundle. Repositories cost nothing while empty, so both stay between windows.
module "ecr_dbadmin" {
  source = "../../modules/ecr"

  repository_name = "${var.project}/dbadmin"
  kms_key_arn     = data.aws_kms_alias.platform.target_key_arn
}

# Anchors of the audit chain's head (ADR-0005): S3 with Object Lock. Kept between windows (a few
# cents a month at most) so anchors outlive the database they vouch for.
module "audit_anchors" {
  source = "../../modules/audit-anchors"

  name        = local.name
  kms_key_arn = data.aws_kms_alias.platform.target_key_arn
}

# ---------------------------------------------------------------------------------------------
# The workload (Phase 4), only while `workload = true` during a deploy window (ADR-0026).
# Between windows none of it exists and nothing here is billed.
# ---------------------------------------------------------------------------------------------

locals {
  workload = var.workload ? 1 : 0
}

module "database" {
  source = "../../modules/database"
  count  = local.workload

  name              = local.name
  data_subnet_ids   = module.network.data_subnet_ids
  security_group_id = module.security_groups.db_security_group_id
  kms_key_arn       = data.aws_kms_alias.platform.target_key_arn
}

module "app_secrets" {
  source = "../../modules/app-secrets"
  count  = local.workload

  name        = local.name
  kms_key_arn = data.aws_kms_alias.platform.target_key_arn
}

module "app_secret_values" {
  source = "../../modules/app-secret-values"
  count  = local.workload

  secret_arns = module.app_secrets[0].secret_arns
  generation  = var.app_secrets_generation
}

module "alb" {
  source = "../../modules/alb"
  count  = local.workload

  name              = local.name
  account_id        = var.account_id
  vpc_id            = module.network.vpc_id
  subnet_ids        = module.network.app_subnet_ids
  security_group_id = module.security_groups.alb_security_group_id
  certificate_arn   = module.certificate_origin[0].issued_certificate_arn
  host_name         = var.app_domain
}

module "ecs" {
  source = "../../modules/ecs"
  count  = local.workload

  name                   = local.name
  account_id             = var.account_id
  region                 = var.region
  kms_key_arn            = data.aws_kms_alias.platform.target_key_arn
  subnet_ids             = module.network.app_subnet_ids
  security_group_id      = module.security_groups.app_security_group_id
  target_group_arn       = module.alb[0].target_group_arn
  host_name              = var.app_domain
  trusted_proxy_cidrs    = module.network.app_subnet_cidr_blocks
  api_image              = var.api_image
  dbadmin_image          = var.dbadmin_image
  api_repository_arn     = module.ecr_api.repository_arn
  dbadmin_repository_arn = module.ecr_dbadmin.repository_arn
  db_host                = module.database[0].address
  db_port                = module.database[0].port
  db_name                = module.database[0].db_name
  secret_arns            = module.app_secrets[0].secret_arns
  master_secret_arn      = module.database[0].master_user_secret_arn
  api_desired_count      = var.api_desired_count
  use_spot               = var.use_spot
  ai_provider            = var.ai_provider
  audit_anchor_bucket    = module.audit_anchors.bucket

  # The values must be in Secrets Manager before any task reads them.
  depends_on = [module.app_secret_values]
}
