output "repository_url" {
  description = "Registry URL to tag and push images to."
  value       = aws_ecr_repository.this.repository_url
}

output "repository_arn" {
  description = "Repository ARN (for the ECS task execution role in Phase 4)."
  value       = aws_ecr_repository.this.arn
}
