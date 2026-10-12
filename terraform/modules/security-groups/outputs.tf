output "alb_security_group_id" {
  description = "Internal ALB security group."
  value       = aws_security_group.alb.id
}

output "app_security_group_id" {
  description = "API task security group."
  value       = aws_security_group.app.id
}

output "db_security_group_id" {
  description = "Database security group."
  value       = aws_security_group.db.id
}
