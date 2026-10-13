output "log_group" {
  description = "The query log group (us-east-1)."
  value       = aws_cloudwatch_log_group.this.name
}
