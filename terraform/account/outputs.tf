output "platform_kms_key_arn" {
  description = "Customer-managed key for platform data (trail, logs, alerts; images and secrets from Part 2)."
  value       = aws_kms_key.platform.arn
}

output "security_alerts_topic_arn" {
  description = "SNS topic that security alarms publish to."
  value       = aws_sns_topic.security_alerts.arn
}

output "cloudtrail_bucket" {
  description = "Bucket holding the account trail's log files and digests."
  value       = aws_s3_bucket.cloudtrail.id
}

output "cloudtrail_log_group" {
  description = "CloudWatch log group the trail streams to."
  value       = aws_cloudwatch_log_group.cloudtrail.name
}

output "local_bedrock_role_arn" {
  description = "Role that make bedrock-credentials assumes for the local API (InvokeModel on one model)."
  value       = aws_iam_role.local_bedrock.arn
}
