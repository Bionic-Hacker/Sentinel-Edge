output "state_bucket" {
  description = "Remote-state bucket for every other stack."
  value       = aws_s3_bucket.state.id
}

output "state_kms_key_arn" {
  description = "KMS key that encrypts state objects."
  value       = aws_kms_key.state.arn
}

output "access_log_bucket" {
  description = "Bucket that receives S3 server access logs from the other buckets."
  value       = aws_s3_bucket.access_logs.id
}

output "region" {
  description = "Region of the state bucket."
  value       = var.region
}
