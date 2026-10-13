output "distribution_id" {
  description = "CloudFront distribution ID (cache invalidation after make spa-push)."
  value       = aws_cloudfront_distribution.this.id
}

output "distribution_domain_name" {
  description = "The distribution's own *.cloudfront.net name."
  value       = aws_cloudfront_distribution.this.domain_name
}

output "spa_bucket" {
  description = "Where make spa-push uploads the built SPA."
  value       = aws_s3_bucket.spa.id
}

output "vpc_origin_id" {
  description = "The CloudFront VPC origin (its service security group must be admitted by the ALB)."
  value       = aws_cloudfront_vpc_origin.alb.id
}
