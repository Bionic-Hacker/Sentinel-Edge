# ECS on Fargate: the API service and two one-off tasks (ADR-0026).
#
#   dbadmin  run once per window: creates the application's database roles and schema with the
#            RDS master credentials (db/bootstrap-roles.sh, the same script as locally and in CI)
#   migrate  run once per release: Alembic as sentinel_migrator, the schema owner
#   api      the service behind the internal ALB, as sentinel_app, which has only per-table grants
#   anchor   hourly: anchors the audit chain's head in an S3 Object Lock bucket (ADR-0005)
#   admin    on demand: creates an administrator; the one-time password goes to Secrets Manager
#
# Each task family has its own execution role, which can read only that family's secrets, and
# only the API has a task role (for Bedrock). No container gets a shell: ECS Exec is off, every
# root filesystem is read-only, all Linux capabilities are dropped, and images are referenced by
# digest.

locals {
  families = toset(["api", "migrate", "dbadmin", "anchor", "admin"])

  # Where the RDS certificate bundle sits in both images (Phase 4 M3).
  rds_ca_path = "/srv/certs/rds-global-bundle.pem"
}

resource "aws_cloudwatch_log_group" "this" {
  for_each = local.families

  name              = "/ecs/${var.name}/${each.key}"
  retention_in_days = 365
  kms_key_id        = var.kms_key_arn
}

resource "aws_cloudwatch_log_group" "exec" {
  name              = "/ecs/${var.name}/exec-audit"
  retention_in_days = 365
  kms_key_id        = var.kms_key_arn
}

resource "aws_ecs_cluster" "this" {
  # checkov:skip=CKV_AWS_65: Container Insights is billed per metric; the ALB, ECS service events and task logs are enough evidence for a short window.
  name = var.name

  setting {
    name  = "containerInsights"
    value = "disabled"
  }

  # ECS Exec is off on every task; if it is ever switched on, sessions are encrypted and logged.
  configuration {
    execute_command_configuration {
      kms_key_id = var.kms_key_arn
      logging    = "OVERRIDE"

      log_configuration {
        cloud_watch_encryption_enabled = true
        cloud_watch_log_group_name     = aws_cloudwatch_log_group.exec.name
      }
    }
  }
}

resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name       = aws_ecs_cluster.this.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = var.use_spot ? "FARGATE_SPOT" : "FARGATE"
    weight            = 1
  }
}
