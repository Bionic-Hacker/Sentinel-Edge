# Task definitions. Shared hardening: read-only root filesystem, a non-root user, every Linux
# capability dropped, no privilege escalation, a scratch volume for /tmp (Fargate has no tmpfs),
# logs to the family's encrypted log group.

locals {
  log_options = {
    for f in local.families : f => {
      "awslogs-group"         = aws_cloudwatch_log_group.this[f].name
      "awslogs-region"        = var.region
      "awslogs-stream-prefix" = f
    }
  }

  hardening = {
    readonlyRootFilesystem = true
    privileged             = false
    linuxParameters = {
      capabilities       = { drop = ["ALL"] }
      initProcessEnabled = false
    }
    mountPoints = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]
  }

  # Configuration shared by the API and migrations: what backend/app/core/config.py reads.
  # environment = dev makes the app refuse unverified database TLS, plain-HTTP origins and
  # debug logging (deployed defaults).
  app_environment = [
    { name = "SENTINEL_ENVIRONMENT", value = var.environment },
    { name = "SENTINEL_LOG_LEVEL", value = "INFO" },
    { name = "SENTINEL_DB_HOST", value = var.db_host },
    { name = "SENTINEL_DB_PORT", value = tostring(var.db_port) },
    { name = "SENTINEL_DB_NAME", value = var.db_name },
    { name = "SENTINEL_DB_SSLMODE", value = "verify-full" },
    { name = "SENTINEL_DB_SSLROOTCERT", value = local.rds_ca_path },
    # Every app task validates these at start (a deployed environment refuses a plain-HTTP origin),
    # so migrations and the anchor task need them as much as the API does.
    { name = "SENTINEL_TRUSTED_HOSTS", value = var.host_name },
    { name = "SENTINEL_PUBLIC_ORIGINS", value = "https://${var.host_name}" },
    { name = "SENTINEL_AWS_REGION", value = var.region },
  ]
}

resource "aws_ecs_task_definition" "api" {
  family                   = "${var.name}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.api_cpu
  memory                   = var.api_memory
  execution_role_arn       = aws_iam_role.execution["api"].arn
  task_role_arn            = aws_iam_role.api_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([merge(local.hardening, {
    name         = "api"
    image        = var.api_image
    essential    = true
    user         = "10001:10001"
    portMappings = [{ containerPort = var.app_port, protocol = "tcp" }]
    environment = concat(local.app_environment, [
      # The ALB (and, in Phase 5, CloudFront's VPC origin) connect from the app subnets; the
      # API trusts X-Forwarded-For from those addresses only.
      { name = "SENTINEL_TRUSTED_PROXY_CIDRS", value = join(",", var.trusted_proxy_cidrs) },
      { name = "SENTINEL_AI_PROVIDER", value = var.ai_provider },
      { name = "SENTINEL_AI_MODEL", value = "us.${var.bedrock_model_id}" },
      # Two attempts must fit inside CloudFront's 60-second origin timeout (Phase 5).
      { name = "SENTINEL_AI_TIMEOUT_SECONDS", value = "25" },
    ])
    secrets = [
      { name = "SENTINEL_DB_PASSWORD", valueFrom = var.secret_arns["db_app_password"] },
      { name = "SENTINEL_JWT_SIGNING_KEY", valueFrom = var.secret_arns["jwt_signing_key"] },
      { name = "SENTINEL_MFA_ENCRYPTION_KEY", valueFrom = var.secret_arns["mfa_encryption_key"] },
    ]
    healthCheck = {
      command     = ["CMD", "python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:${var.app_port}/api/v1/health', timeout=2).status == 200 else 1)"]
      interval    = 15
      timeout     = 3
      retries     = 3
      startPeriod = 15
    }
    logConfiguration = { logDriver = "awslogs", options = local.log_options["api"] }
  })])
}

resource "aws_ecs_task_definition" "migrate" {
  family                   = "${var.name}-migrate"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution["migrate"].arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([merge(local.hardening, {
    name        = "migrate"
    image       = var.api_image
    essential   = true
    user        = "10001:10001"
    command     = ["alembic", "upgrade", "head"]
    environment = local.app_environment
    secrets = [
      { name = "SENTINEL_DB_MIGRATOR_PASSWORD", valueFrom = var.secret_arns["db_migrator_password"] },
    ]
    logConfiguration = { logDriver = "awslogs", options = local.log_options["migrate"] }
  })])
}

resource "aws_ecs_task_definition" "dbadmin" {
  family                   = "${var.name}-dbadmin"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution["dbadmin"].arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  volume {
    name = "tmp"
  }

  # libpq reads PG* variables; the script refuses to run as an application role.
  container_definitions = jsonencode([merge(local.hardening, {
    name      = "dbadmin"
    image     = var.dbadmin_image
    essential = true
    user      = "70:70"
    environment = [
      { name = "PGHOST", value = var.db_host },
      { name = "PGPORT", value = tostring(var.db_port) },
      { name = "PGDATABASE", value = var.db_name },
      { name = "PGSSLMODE", value = "verify-full" },
      { name = "PGSSLROOTCERT", value = local.rds_ca_path },
      { name = "PGCONNECT_TIMEOUT", value = "10" },
    ]
    secrets = [
      { name = "PGUSER", valueFrom = "${var.master_secret_arn}:username::" },
      { name = "PGPASSWORD", valueFrom = "${var.master_secret_arn}:password::" },
      { name = "SENTINEL_DB_APP_PASSWORD", valueFrom = var.secret_arns["db_app_password"] },
      { name = "SENTINEL_DB_MIGRATOR_PASSWORD", valueFrom = var.secret_arns["db_migrator_password"] },
    ]
    logConfiguration = { logDriver = "awslogs", options = local.log_options["dbadmin"] }
  })])
}

# Hourly (EventBridge Scheduler, anchor.tf): verify the audit chain and anchor its head in the
# Object Lock bucket (ADR-0005).
resource "aws_ecs_task_definition" "anchor" {
  family                   = "${var.name}-anchor"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution["anchor"].arn
  task_role_arn            = aws_iam_role.anchor_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([merge(local.hardening, {
    name      = "anchor"
    image     = var.api_image
    essential = true
    user      = "10001:10001"
    command   = ["python", "-m", "app.cli", "audit-anchor", "export"]
    environment = concat(local.app_environment, [
      { name = "SENTINEL_AUDIT_ANCHOR_BUCKET", value = var.audit_anchor_bucket },
    ])
    secrets = [
      { name = "SENTINEL_DB_PASSWORD", valueFrom = var.secret_arns["db_app_password"] },
    ]
    logConfiguration = { logDriver = "awslogs", options = local.log_options["anchor"] }
  })])
}
