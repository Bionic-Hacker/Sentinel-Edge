output "secret_arns" {
  description = "ARN of each secret, by key: db_app_password, db_migrator_password, jwt_signing_key, mfa_encryption_key."
  value       = { for k, s in aws_secretsmanager_secret.this : k => s.arn }
}

output "admin_otp_secret_arn" {
  description = "Where the admin task stores a new administrator's one-time password."
  value       = aws_secretsmanager_secret.admin_otp.arn
}
