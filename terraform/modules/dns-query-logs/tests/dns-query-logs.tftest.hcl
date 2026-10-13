# terraform test, with a mocked AWS provider: no credentials, no AWS calls, no cost.

mock_provider "aws" {
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/route53/sentineledge.example.com" }
  }
}

variables {
  zone_id    = "Z0123456789ABCDEFGHIJ"
  zone_name  = "sentineledge.example.com"
  account_id = "123456789012"
}

run "every_query_is_logged_to_us_east_1_and_kept_a_year" {
  command = apply

  assert {
    condition     = aws_cloudwatch_log_group.this.name == "/aws/route53/sentineledge.example.com"
    error_message = "Route 53 query logs go to a log group named after the zone."
  }
  assert {
    condition     = aws_cloudwatch_log_group.this.retention_in_days == 365
    error_message = "Query logs are kept a year."
  }
  assert {
    condition     = aws_route53_query_log.this.zone_id == "Z0123456789ABCDEFGHIJ"
    error_message = "The query log is attached to the platform's zone."
  }
}

run "only_this_zone_may_write" {
  command = apply

  assert {
    condition     = strcontains(aws_cloudwatch_log_resource_policy.route53.policy_document, "arn:aws:route53:::hostedzone/Z0123456789ABCDEFGHIJ")
    error_message = "The log policy admits only this zone (aws:SourceArn)."
  }
  assert {
    condition     = strcontains(aws_cloudwatch_log_resource_policy.route53.policy_document, "123456789012")
    error_message = "The log policy admits only this account (aws:SourceAccount)."
  }
}

run "a_bad_account_id_is_refused" {
  command = plan

  variables {
    account_id = "not-an-account"
  }

  expect_failures = [var.account_id]
}
