output "cluster_name" {
  description = "ECS cluster."
  value       = aws_ecs_cluster.this.name
}

output "service_name" {
  description = "The API service."
  value       = aws_ecs_service.api.name
}

output "task_definitions" {
  description = "Task definition families for one-off runs (make ecs-task TASK=…)."
  value = {
    api     = aws_ecs_task_definition.api.family
    migrate = aws_ecs_task_definition.migrate.family
    dbadmin = aws_ecs_task_definition.dbadmin.family
  }
}

output "log_groups" {
  description = "Log group per task family."
  value       = { for f, g in aws_cloudwatch_log_group.this : f => g.name }
}
