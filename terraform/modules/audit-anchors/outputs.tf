output "bucket" {
  description = "Bucket name (SENTINEL_AUDIT_ANCHOR_BUCKET)."
  value       = aws_s3_bucket.this.id
}

output "arn" {
  description = "Bucket ARN."
  value       = aws_s3_bucket.this.arn
}
