output "vpc_id" {
  description = "VPC ID."
  value       = aws_vpc.this.id
}

output "vpc_cidr_block" {
  description = "VPC address range."
  value       = aws_vpc.this.cidr_block
}

output "public_subnet_ids" {
  description = "Public subnets (NAT only)."
  value       = aws_subnet.public[*].id
}

output "app_subnet_ids" {
  description = "App subnets: ECS tasks and the internal ALB."
  value       = aws_subnet.app[*].id
}

output "app_subnet_cidr_blocks" {
  description = "App subnet ranges (the ALB's forwarded-header trust list in Phase 4)."
  value       = aws_subnet.app[*].cidr_block
}

output "data_subnet_ids" {
  description = "Isolated data subnets: RDS."
  value       = aws_subnet.data[*].id
}

output "nat_mode" {
  description = "Egress mode in effect: none, instance or gateway."
  value       = var.nat_mode
}

output "flow_log_group" {
  description = "CloudWatch log group holding the VPC flow logs."
  value       = aws_cloudwatch_log_group.flow_logs.name
}
