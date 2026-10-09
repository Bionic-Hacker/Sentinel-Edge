# terraform test, with a mocked AWS provider: no credentials, no AWS calls, no cost.

mock_provider "aws" {}

variables {
  name   = "test"
  vpc_id = "vpc-0123456789abcdef0"
}

run "each_hop_admits_only_the_one_before_it" {
  command = apply

  assert {
    condition     = aws_vpc_security_group_ingress_rule.app_from_alb.referenced_security_group_id == aws_security_group.alb.id
    error_message = "The app port must be open to the ALB's group only."
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.db_from_app.referenced_security_group_id == aws_security_group.app.id
    error_message = "PostgreSQL must be open to the app's group only."
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.app_from_alb.from_port == 8000 && aws_vpc_security_group_ingress_rule.db_from_app.from_port == 5432
    error_message = "Ports must be the app port and PostgreSQL."
  }
  assert {
    condition     = aws_vpc_security_group_egress_rule.app_https.from_port == 443 && aws_vpc_security_group_egress_rule.app_https.to_port == 443
    error_message = "The app's only internet egress is HTTPS."
  }
}
