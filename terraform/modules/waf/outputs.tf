output "arn" {
  description = "Web ACL ARN, attached to the CloudFront distribution."
  value       = aws_wafv2_web_acl.this.arn
}

output "log_group" {
  description = "WAF log group (us-east-1)."
  value       = aws_cloudwatch_log_group.waf.name
}
