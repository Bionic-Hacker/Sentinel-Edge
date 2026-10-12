output "secret_arns" {
  description = "ARN of each secret, by key: db_app_password, db_migrator_password, jwt_signing_key, mfa_encryption_key."
  value       = { for k, s in aws_secretsmanager_secret.this : k => s.arn }
}
