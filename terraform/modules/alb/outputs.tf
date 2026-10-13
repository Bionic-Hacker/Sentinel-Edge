output "arn" {
  description = "Load balancer ARN (CloudFront's VPC origin targets it in Phase 5)."
  value       = aws_lb.this.arn
}

output "dns_name" {
  description = "Internal DNS name."
  value       = aws_lb.this.dns_name
}

output "target_group_arn" {
  description = "The API target group."
  value       = aws_lb_target_group.api.arn
}

output "log_bucket" {
  description = "Access-log bucket."
  value       = aws_s3_bucket.logs.id
}

output "arn_suffix" {
  description = "The LoadBalancer dimension for CloudWatch metrics."
  value       = aws_lb.this.arn_suffix
}

output "target_group_arn_suffix" {
  description = "The TargetGroup dimension for CloudWatch metrics."
  value       = aws_lb_target_group.api.arn_suffix
}
