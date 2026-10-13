output "address" {
  description = "Host name the application connects to (and verifies the certificate against)."
  value       = aws_db_instance.this.address
}

output "port" {
  description = "PostgreSQL port."
  value       = aws_db_instance.this.port
}

output "db_name" {
  description = "Application database name."
  value       = aws_db_instance.this.db_name
}

output "master_user_secret_arn" {
  description = "The RDS-managed secret holding the master credentials (username and password keys)."
  value       = aws_db_instance.this.master_user_secret[0].secret_arn
}

output "instance_arn" {
  description = "Instance ARN."
  value       = aws_db_instance.this.arn
}

output "identifier" {
  description = "Instance identifier (the CloudWatch dimension)."
  value       = aws_db_instance.this.identifier
}
