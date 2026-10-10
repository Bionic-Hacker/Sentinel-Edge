# terraform test, with a mocked AWS provider: no credentials, no AWS calls, no cost.
# Run by scripts/tf-check.sh (make tf-check, and CI).

mock_provider "aws" {
  # The provider validates ARNs it is given, so mocked ARNs must look like ARNs.
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-2:123456789012:log-group:/aws/vpc/test/flow-logs" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/test-flow-logs" }
  }

  override_data {
    target = data.aws_availability_zones.selected
    values = {
      names    = ["us-east-2b", "us-east-2a"]
      zone_ids = ["use2-az2", "use2-az1"]
    }
  }
  override_data {
    target = data.aws_region.current
    values = { region = "us-east-2" }
  }
  override_data {
    target = data.aws_caller_identity.current
    values = { account_id = "123456789012" }
  }
  override_data {
    target = data.aws_ssm_parameter.al2023_arm64
    values = { value = "ami-0123456789abcdef0" }
  }
  override_data {
    target = data.aws_iam_policy_document.flow_logs_assume
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.flow_logs
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
}

variables {
  name                  = "test"
  availability_zone_ids = ["use2-az1", "use2-az2"]
  kms_key_arn           = "arn:aws:kms:us-east-2:123456789012:key/00000000-0000-0000-0000-000000000000"
}

run "resting_state_has_no_egress_and_no_hourly_resources" {
  command = apply

  assert {
    condition     = length(aws_instance.nat) == 0 && length(aws_nat_gateway.this) == 0 && length(aws_eip.nat) == 0
    error_message = "nat_mode = none must create no NAT, NAT gateway or Elastic IP."
  }
  assert {
    condition     = length(aws_route.app_via_instance) == 0 && length(aws_route.app_via_gateway) == 0
    error_message = "With NAT off, the app tier must have no default route."
  }
}

run "subnets_follow_the_zone_ids_in_order_and_never_assign_public_ips" {
  command = apply

  assert {
    condition     = aws_subnet.app[0].availability_zone == "us-east-2a" && aws_subnet.app[1].availability_zone == "us-east-2b"
    error_message = "Subnets must follow availability_zone_ids order, not the API's order."
  }
  assert {
    condition = (
      aws_subnet.public[0].cidr_block == "10.40.0.0/24" &&
      aws_subnet.app[0].cidr_block == "10.40.10.0/24" &&
      aws_subnet.data[1].cidr_block == "10.40.21.0/24"
    )
    error_message = "Tier ranges must be public 0-, app 10-, data 20-."
  }
  assert {
    condition     = alltrue([for s in aws_subnet.public : s.map_public_ip_on_launch == false])
    error_message = "Public subnets must not hand out public IPs by default."
  }
}

run "data_tier_is_isolated" {
  command = apply

  # The only routes that exist are the public internet route and (with NAT on) the app default
  # route; nothing targets the data route table except the S3 gateway endpoint.
  assert {
    condition     = aws_route.public_internet.route_table_id == aws_route_table.public.id
    error_message = "The internet route must belong to the public route table only."
  }
  assert {
    condition     = contains(aws_vpc_endpoint.s3.route_table_ids, aws_route_table.data.id)
    error_message = "The data tier must reach S3 through the gateway endpoint."
  }
}

run "nat_instance_mode" {
  command = apply

  variables {
    nat_mode = "instance"
  }

  assert {
    condition     = length(aws_instance.nat) == 1 && length(aws_nat_gateway.this) == 0
    error_message = "nat_mode = instance must create exactly one NAT instance and no gateway."
  }
  assert {
    condition     = aws_instance.nat[0].source_dest_check == false && aws_instance.nat[0].metadata_options[0].http_tokens == "required"
    error_message = "The NAT instance must forward traffic and require IMDSv2."
  }
  assert {
    condition     = aws_instance.nat[0].root_block_device[0].encrypted == true
    error_message = "The NAT instance's volume must be encrypted."
  }
  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.nat_from_app) == 4
    error_message = "The NAT may admit only HTTP and HTTPS from each app subnet (2 subnets x 2 ports)."
  }
  assert {
    condition     = alltrue([for r in aws_vpc_security_group_ingress_rule.nat_from_app : contains(["10.40.10.0/24", "10.40.11.0/24"], r.cidr_ipv4)])
    error_message = "NAT ingress must come from the app subnets only."
  }
  assert {
    condition     = length(aws_route.app_via_instance) == 1
    error_message = "The app tier must route through the NAT instance."
  }
  assert {
    condition = alltrue([
      for d in concat(
        [aws_security_group.nat[0].description],
        [for r in aws_vpc_security_group_ingress_rule.nat_from_app : r.description],
        [for r in aws_vpc_security_group_egress_rule.nat_out : r.description],
      ) : can(regex("^[a-zA-Z0-9. _:/()#,@+=&;{}!$*\\[\\]-]{1,255}$", d))
    ])
    error_message = "A NAT security group or rule description uses a character EC2 rejects."
  }
}

run "nat_gateway_mode" {
  command = apply

  variables {
    nat_mode = "gateway"
  }

  assert {
    condition     = length(aws_nat_gateway.this) == 1 && length(aws_instance.nat) == 0 && length(aws_route.app_via_gateway) == 1
    error_message = "nat_mode = gateway must create one NAT gateway, its route, and no instance."
  }
}

run "rejects_unknown_nat_mode" {
  command = plan

  variables {
    nat_mode = "public"
  }

  expect_failures = [var.nat_mode]
}

run "rejects_a_single_zone" {
  command = plan

  variables {
    availability_zone_ids = ["use2-az1"]
  }

  expect_failures = [var.availability_zone_ids]
}
