# terraform test, with a mocked AWS provider: no credentials, no AWS calls, no cost.
# Run by scripts/tf-check.sh (make tf-check, and CI).

mock_provider "aws" {
  mock_resource "aws_wafv2_web_acl" {
    defaults = { arn = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/sentineledge-dev-edge/00000000-0000-0000-0000-000000000000" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:aws-waf-logs-sentineledge-dev-edge" }
  }
}

variables {
  name = "sentineledge-dev-edge"
}

run "cloudfront_scope_with_the_managed_groups" {
  command = apply

  assert {
    condition     = aws_wafv2_web_acl.this.scope == "CLOUDFRONT"
    error_message = "A CloudFront web ACL."
  }
  assert {
    condition = toset([for r in aws_wafv2_web_acl.this.rule : one(one(r.statement).managed_rule_group_statement).name if length(one(r.statement).managed_rule_group_statement) > 0]) == toset([
      "AWSManagedRulesAmazonIpReputationList", "AWSManagedRulesCommonRuleSet", "AWSManagedRulesKnownBadInputsRuleSet", "AWSManagedRulesSQLiRuleSet",
    ])
    error_message = "IP reputation, the core rule set, known bad inputs and SQL injection."
  }
  assert {
    condition     = one([for r in aws_wafv2_web_acl.this.rule : r.priority if r.name == "ip-reputation"]) == 0
    error_message = "Known-bad sources are refused before any other rule."
  }
}

run "sign_in_is_rate_limited_per_ip" {
  command = apply

  assert {
    condition     = one([for r in aws_wafv2_web_acl.this.rule : one(one(r.statement).rate_based_statement).limit if r.name == "sign-in-rate"]) == 100
    error_message = "Sign-in endpoints: 100 requests per IP per 5 minutes."
  }
  assert {
    condition     = one([for r in aws_wafv2_web_acl.this.rule : one(one(one(one(r.statement).rate_based_statement).scope_down_statement).byte_match_statement).search_string if r.name == "sign-in-rate"]) == "/api/v1/auth/"
    error_message = "The sign-in limit applies to /api/v1/auth/*."
  }
  assert {
    condition     = alltrue([for r in aws_wafv2_web_acl.this.rule : length(one(r.action).block) == 1 if contains(["sign-in-rate", "api-rate", "body-too-large"], r.name)])
    error_message = "Rate and size rules block; they do not merely count."
  }
}

run "credentials_never_reach_the_logs" {
  command = apply

  assert {
    condition     = toset([for f in aws_wafv2_web_acl_logging_configuration.this.redacted_fields : one(f.single_header).name]) == toset(["authorization", "cookie"])
    error_message = "Authorization and Cookie headers are redacted from WAF logs."
  }
  assert {
    condition     = startswith(aws_cloudwatch_log_group.waf.name, "aws-waf-logs-")
    error_message = "WAF requires its log group name to start with aws-waf-logs-."
  }
}

run "the_body_cap_cannot_exceed_what_is_inspected" {
  command = plan

  variables {
    max_body_bytes = 1048576
  }

  expect_failures = [var.max_body_bytes]
}
