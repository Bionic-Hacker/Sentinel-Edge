# Three subnet tiers per Availability Zone (ADR-0001):
#   public  internet gateway route; only the NAT lives here (the ALB is internal, Phase 4)
#   app     ECS tasks and the internal ALB; internet egress only through NAT, when NAT is on
#   data    RDS; no route out of the VPC at all
# A free S3 gateway endpoint serves the app and data tiers (ECR image layers live in S3).

# Pinned by zone ID, so a zone AWS adds later never changes the layout.
data "aws_availability_zones" "selected" {
  state = "available"

  filter {
    name   = "zone-id"
    values = var.availability_zone_ids
  }
}

data "aws_region" "current" {}

locals {
  # Names in the order the IDs were given, so subnet numbering is stable.
  zone_name_by_id = zipmap(data.aws_availability_zones.selected.zone_ids, data.aws_availability_zones.selected.names)
  azs             = [for id in var.availability_zone_ids : local.zone_name_by_id[id]]
  az_count        = length(var.availability_zone_ids)
}

resource "aws_vpc" "this" {
  cidr_block           = var.cidr_block
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = var.name }
}

# The default security group exists in every VPC; with no rules it allows nothing, so a
# resource launched without a group is isolated rather than open.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-default-deny" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = var.name }
}

resource "aws_subnet" "public" {
  count = local.az_count

  vpc_id                  = aws_vpc.this.id
  availability_zone       = local.azs[count.index]
  cidr_block              = cidrsubnet(var.cidr_block, 8, count.index)
  map_public_ip_on_launch = false

  tags = { Name = "${var.name}-public-${local.azs[count.index]}", Tier = "public" }
}

resource "aws_subnet" "app" {
  count = local.az_count

  vpc_id            = aws_vpc.this.id
  availability_zone = local.azs[count.index]
  cidr_block        = cidrsubnet(var.cidr_block, 8, 10 + count.index)

  tags = { Name = "${var.name}-app-${local.azs[count.index]}", Tier = "app" }
}

resource "aws_subnet" "data" {
  count = local.az_count

  vpc_id            = aws_vpc.this.id
  availability_zone = local.azs[count.index]
  cidr_block        = cidrsubnet(var.cidr_block, 8, 20 + count.index)

  tags = { Name = "${var.name}-data-${local.azs[count.index]}", Tier = "data" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-public" }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  count = local.az_count

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# One app route table: in dev a single NAT serves both zones (a zone outage takes egress with it,
# which is acceptable for a demo and halves the NAT cost).
resource "aws_route_table" "app" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-app" }
}

resource "aws_route_table_association" "app" {
  count = local.az_count

  subnet_id      = aws_subnet.app[count.index].id
  route_table_id = aws_route_table.app.id
}

resource "aws_route_table" "data" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-data" }
}

resource "aws_route_table_association" "data" {
  count = local.az_count

  subnet_id      = aws_subnet.data[count.index].id
  route_table_id = aws_route_table.data.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.app.id, aws_route_table.data.id]

  tags = { Name = "${var.name}-s3" }
}
