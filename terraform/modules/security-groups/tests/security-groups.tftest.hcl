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

# EC2 accepts only these characters in group and rule descriptions; an apostrophe ("CloudFront's")
# passed validate and every check, then failed the first real apply.
run "descriptions_use_only_characters_ec2_accepts" {
  command = plan

  assert {
    condition = alltrue([
      for d in [
        aws_security_group.alb.description,
        aws_security_group.app.description,
        aws_security_group.db.description,
        aws_vpc_security_group_egress_rule.alb_to_app.description,
        aws_vpc_security_group_ingress_rule.app_from_alb.description,
        aws_vpc_security_group_egress_rule.app_to_db.description,
        aws_vpc_security_group_egress_rule.app_https.description,
        aws_vpc_security_group_ingress_rule.db_from_app.description,
      ] : can(regex("^[a-zA-Z0-9. _:/()#,@+=&;{}!$*\\[\\]-]{1,255}$", d))
    ])
    error_message = "A security group or rule description uses a character EC2 rejects."
  }
}
