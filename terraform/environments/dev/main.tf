# The dev environment's foundation (Phase 3). Everything here is free while idle: the VPC,
# subnets, route tables, gateway endpoint, security groups, an empty registry and two
# certificates. The only hourly item is NAT, and it is off (nat_mode = "none") between deploy
# windows. Phase 4 adds the workload; Phase 5 the edge.

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

# CloudFront only accepts certificates from us-east-1 (Phase 5).
module "certificate_edge" {
  source    = "../../modules/certificate"
  providers = { aws = aws.us_east_1 }

  domain_name = var.app_domain
}

# The internal ALB's certificate, in the home Region (Phase 4). CloudFront forwards the viewer's
# Host header, so the CloudFront-to-ALB hop is verified against the same name.
module "certificate_origin" {
  source = "../../modules/certificate"

  domain_name = var.app_domain
}
