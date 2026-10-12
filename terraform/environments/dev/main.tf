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
