# terraform test, with a mocked AWS provider: no credentials, no AWS calls, no cost.
# Run by scripts/tf-check.sh (make tf-check, and CI).

mock_provider "aws" {
  mock_resource "aws_lb" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-2:123456789012:loadbalancer/app/sentineledge-dev/0123456789abcdef" }
  }
  mock_resource "aws_lb_target_group" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/sentineledge-dev-api/0123456789abcdef" }
  }
  mock_resource "aws_lb_listener" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-2:123456789012:listener/app/sentineledge-dev/0123456789abcdef/0123456789abcdef" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::sentineledge-dev-alb-logs-0001", id = "sentineledge-dev-alb-logs-0001" }
  }
  override_data {
    target = data.aws_iam_policy_document.logs
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_elb_service_account.this
    values = { arn = "arn:aws:iam::033677994240:root" }
  }
}

variables {
  name              = "sentineledge-dev"
  account_id        = "123456789012"
  vpc_id            = "vpc-0123456789abcdef0"
  subnet_ids        = ["subnet-0aaaaaaaaaaaaaaaa", "subnet-0bbbbbbbbbbbbbbbb"]
  security_group_id = "sg-0aaaaaaaaaaaaaaaa"
  certificate_arn   = "arn:aws:acm:us-east-2:123456789012:certificate/00000000-0000-0000-0000-000000000000"
  host_name         = "sentineledge.example.com"
}

run "internal_and_strict" {
  command = apply

  assert {
    condition     = aws_lb.this.internal == true
    error_message = "The ALB must have no public address (ADR-0001)."
  }
  assert {
    condition     = aws_lb.this.drop_invalid_header_fields == true && aws_lb.this.desync_mitigation_mode == "strictest"
    error_message = "Malformed headers must be dropped and desync handled strictly."
  }
  assert {
    condition     = aws_lb.this.access_logs[0].enabled == true
    error_message = "Access logs must be on."
  }
}

run "https_only_with_modern_tls" {
  command = apply

  assert {
    condition     = aws_lb_listener.https.port == 443 && aws_lb_listener.https.protocol == "HTTPS"
    error_message = "The only listener is HTTPS on 443."
  }
  assert {
    condition     = startswith(aws_lb_listener.https.ssl_policy, "ELBSecurityPolicy-TLS13-1-2")
    error_message = "TLS 1.2 is the minimum, with TLS 1.3 offered."
  }
}

run "only_the_platform_name_reaches_the_api" {
  command = apply

  assert {
    condition     = aws_lb_listener.https.default_action[0].type == "fixed-response" && aws_lb_listener.https.default_action[0].fixed_response[0].status_code == "404"
    error_message = "Requests for any other host must be refused at the ALB."
  }
  assert {
    condition     = one(one(aws_lb_listener_rule.api.condition).host_header).values == toset(["sentineledge.example.com"])
    error_message = "Only the platform's host name is forwarded."
  }
  assert {
    condition     = aws_lb_target_group.api.health_check[0].path == "/api/v1/health"
    error_message = "Targets are checked on the health endpoint."
  }
}

run "the_log_bucket_is_private_and_tls_only" {
  command = apply

  assert {
    condition     = aws_s3_bucket_public_access_block.logs.block_public_policy && aws_s3_bucket_public_access_block.logs.restrict_public_buckets
    error_message = "The log bucket must block public access."
  }
  assert {
    condition     = one([for st in data.aws_iam_policy_document.logs.statement : st.effect if st.sid == "TlsOnly"]) == "Deny" && one([for st in data.aws_iam_policy_document.logs.statement : one(st.condition).variable if st.sid == "TlsOnly"]) == "aws:SecureTransport"
    error_message = "The log bucket must refuse requests without TLS."
  }
}

run "a_long_name_is_refused" {
  command = plan

  variables {
    name = "sentineledge-development-environment"
  }

  expect_failures = [var.name]
}
