# The chain from the architecture (ADR-0001), each hop admitting only the one before it:
#
#   CloudFront VPC origin ──443──► alb ──8000──► app ──5432──► db
#
# The ALB's ingress rule names CloudFront's VPC-origin security group, which CloudFront creates in
# Phase 5; until then the ALB admits nothing. The app may also leave the VPC on 443 for AWS APIs
# and Bedrock (through NAT, when NAT is on). The database has no egress at all.
#
# Groups are attached in Phase 4 (ALB, ECS, RDS), so Checkov's "attached" check is excused here.

resource "aws_security_group" "alb" {
  # checkov:skip=CKV2_AWS_5: Attached to the internal ALB in Phase 4.
  name        = "${var.name}-alb"
  description = "Internal ALB: HTTPS from the CloudFront VPC origin only (rule added in Phase 5)"
  vpc_id      = var.vpc_id
  tags        = { Name = "${var.name}-alb" }
}

resource "aws_security_group" "app" {
  # checkov:skip=CKV2_AWS_5: Attached to the ECS service in Phase 4.
  name        = "${var.name}-app"
  description = "API tasks: the app port from the ALB only"
  vpc_id      = var.vpc_id
  tags        = { Name = "${var.name}-app" }
}

resource "aws_security_group" "db" {
  # checkov:skip=CKV2_AWS_5: Attached to the RDS instance in Phase 4.
  name        = "${var.name}-db"
  description = "PostgreSQL: the database port from the API tasks only; no egress"
  vpc_id      = var.vpc_id
  tags        = { Name = "${var.name}-db" }
}

resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Forward requests to the API tasks"
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
  referenced_security_group_id = aws_security_group.app.id
}

resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = aws_security_group.app.id
  description                  = "Requests from the internal ALB"
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
  referenced_security_group_id = aws_security_group.alb.id
}

resource "aws_vpc_security_group_egress_rule" "app_to_db" {
  security_group_id            = aws_security_group.app.id
  description                  = "PostgreSQL"
  ip_protocol                  = "tcp"
  from_port                    = var.db_port
  to_port                      = var.db_port
  referenced_security_group_id = aws_security_group.db.id
}

resource "aws_vpc_security_group_egress_rule" "app_https" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS to AWS APIs and Bedrock (via NAT or the S3 endpoint)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.db.id
  description                  = "PostgreSQL from the API tasks"
  ip_protocol                  = "tcp"
  from_port                    = var.db_port
  to_port                      = var.db_port
  referenced_security_group_id = aws_security_group.app.id
}
