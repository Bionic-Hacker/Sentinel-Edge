# AWS WAF for the CloudFront distribution (Phase 5, ADR-0004, ADR-0008, ADR-0027). CLOUDFRONT
# scope, so the provider must be us-east-1. Changes happen only here, through reviewed plans:
# the application can read WAF data but never change it.
#
# Evaluated in order; the first terminating match wins:
#   0  IP reputation (AWS managed)            block known-bad sources before anything else
#   1  Core rule set (AWS managed)            OWASP-style generic protections
#   2  Known bad inputs (AWS managed)         Log4Shell, Java deserialisation, bad paths
#   3  SQL injection (AWS managed)
#   10 Oversized body                         SentinelEdge's own cap: no API body is near 64 KB
#   20 Sign-in rate (per IP)                  /api/v1/auth/* tightly, ahead of the app's limiter
#   21 API rate (per IP)                      /api/* generally
#
# The core rule set's own 8 KB body-size rule counts instead of blocking: SentinelEdge's
# legitimate bodies are small but not always under 8 KB, and rule 10 enforces the real cap.

resource "aws_wafv2_web_acl" "this" {
  name        = var.name
  description = "SentinelEdge edge protection: managed rules, body cap, per-IP rate limits"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # Inspect up to 64 KB of each body, so the size cap below is enforced on what is inspected.
  association_config {
    request_body {
      cloudfront {
        default_size_inspection_limit = "KB_64"
      }
    }
  }

  rule {
    name     = "ip-reputation"
    priority = 0

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAmazonIpReputationList"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "core-rule-set"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
        rule_action_override {
          name = "SizeRestrictions_BODY"
          action_to_use {
            count {}
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-core-rule-set"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "known-bad-inputs"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "sql-injection"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesSQLiRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-sql-injection"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "body-too-large"
    priority = 10

    action {
      block {}
    }

    statement {
      size_constraint_statement {
        comparison_operator = "GT"
        size                = var.max_body_bytes
        field_to_match {
          body {
            oversize_handling = "MATCH"
          }
        }
        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-body-too-large"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "sign-in-rate"
    priority = 20

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit                 = var.auth_rate_limit
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"

        scope_down_statement {
          byte_match_statement {
            positional_constraint = "STARTS_WITH"
            search_string         = "/api/v1/auth/"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-sign-in-rate"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "api-rate"
    priority = 21

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit                 = var.api_rate_limit
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"

        scope_down_statement {
          byte_match_statement {
            positional_constraint = "STARTS_WITH"
            search_string         = "/api/"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-api-rate"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = var.name
    sampled_requests_enabled   = true
  }
}

# Every request WAF evaluates is logged, with credentials redacted. The log group name must
# start with aws-waf-logs-, and it must be in us-east-1 with the web ACL.
resource "aws_cloudwatch_log_group" "waf" {
  # checkov:skip=CKV_AWS_158: Encrypted with CloudWatch's own key; a customer key in us-east-1 would be a second KMS key ($1 a month) for logs kept 30 days during a deploy window.
  # checkov:skip=CKV_AWS_338: Kept 30 days: the edge exists only during a deploy window, and evidence is exported from it.
  name              = "aws-waf-logs-${var.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  resource_arn            = aws_wafv2_web_acl.this.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }
  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
}
