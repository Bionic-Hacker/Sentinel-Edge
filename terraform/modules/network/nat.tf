# Egress for the app tier, switched by var.nat_mode. "none" removes every hourly charge; the
# deploy window sets "instance" (default) or "gateway".

locals {
  nat_instance = var.nat_mode == "instance" ? 1 : 0
  nat_gateway  = var.nat_mode == "gateway" ? 1 : 0
}

# --- Managed NAT gateway ----------------------------------------------------------------------

resource "aws_eip" "nat" {
  count  = local.nat_gateway
  domain = "vpc"
  tags   = { Name = "${var.name}-nat" }
}

resource "aws_nat_gateway" "this" {
  count = local.nat_gateway

  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id
  tags          = { Name = var.name }

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route" "app_via_gateway" {
  count = local.nat_gateway

  route_table_id         = aws_route_table.app.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[0].id
}

# --- NAT instance -----------------------------------------------------------------------------
# Amazon Linux 2023 on Graviton, forwarding and masquerading HTTP and HTTPS from the app subnets.
# No SSH, no key pair, no instance role: it needs no AWS API access. IMDSv2 only.

data "aws_ssm_parameter" "al2023_arm64" {
  count = local.nat_instance
  name  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

resource "aws_security_group" "nat" {
  count = local.nat_instance

  name        = "${var.name}-nat"
  description = "NAT instance: HTTP and HTTPS from the app subnets out to the internet"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-nat" }
}

resource "aws_vpc_security_group_ingress_rule" "nat_from_app" {
  for_each = local.nat_instance == 1 ? {
    for pair in setproduct(aws_subnet.app[*].cidr_block, [80, 443]) : "${pair[0]}-${pair[1]}" => pair
  } : {}

  security_group_id = aws_security_group.nat[0].id
  description       = "TCP ${each.value[1]} from app subnet ${each.value[0]}"
  ip_protocol       = "tcp"
  from_port         = each.value[1]
  to_port           = each.value[1]
  cidr_ipv4         = each.value[0]
}

resource "aws_vpc_security_group_egress_rule" "nat_out" {
  for_each = local.nat_instance == 1 ? toset(["80", "443"]) : toset([])

  security_group_id = aws_security_group.nat[0].id
  description       = "TCP ${each.value} to the internet (forwarded app traffic and OS updates)"
  ip_protocol       = "tcp"
  from_port         = tonumber(each.value)
  to_port           = tonumber(each.value)
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_instance" "nat" {
  # checkov:skip=CKV_AWS_88: A NAT instance needs a public address; it sits in a public subnet and its security group admits only the app subnets.
  # checkov:skip=CKV_AWS_126: Detailed monitoring is billed per instance; basic monitoring is enough for a demo NAT.
  # checkov:skip=CKV2_AWS_41: The NAT instance calls no AWS API, so it is given no role at all.
  count = local.nat_instance

  ami                         = nonsensitive(data.aws_ssm_parameter.al2023_arm64[0].value)
  instance_type               = var.nat_instance_type
  subnet_id                   = aws_subnet.public[0].id
  vpc_security_group_ids      = [aws_security_group.nat[0].id]
  associate_public_ip_address = true
  source_dest_check           = false
  ebs_optimized               = true
  user_data_replace_on_change = true

  user_data = templatefile("${path.module}/nat-instance.sh.tftpl", {
    vpc_cidr = var.cidr_block
  })

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    http_endpoint               = "enabled"
  }

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
  }

  tags = { Name = "${var.name}-nat" }

  lifecycle {
    # A new AMI release must not replace the NAT mid-window; it is picked up on the next window.
    ignore_changes = [ami]
  }
}

resource "aws_route" "app_via_instance" {
  count = local.nat_instance

  route_table_id         = aws_route_table.app.id
  destination_cidr_block = "0.0.0.0/0"
  network_interface_id   = aws_instance.nat[0].primary_network_interface_id
}
