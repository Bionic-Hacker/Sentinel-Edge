# terraform test, with a mocked AWS provider: no credentials, no AWS calls, no cost.
# Run by scripts/tf-check.sh (make tf-check, and CI).

mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/sentineledge-dev-x" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-2:123456789012:log-group:/ecs/sentineledge-dev/x" }
  }
  mock_resource "aws_ecs_cluster" {
    defaults = { arn = "arn:aws:ecs:us-east-2:123456789012:cluster/sentineledge-dev", id = "arn:aws:ecs:us-east-2:123456789012:cluster/sentineledge-dev" }
  }
  mock_resource "aws_ecs_task_definition" {
    defaults = { arn = "arn:aws:ecs:us-east-2:123456789012:task-definition/sentineledge-dev-x:1" }
  }
  override_data {
    target = data.aws_iam_policy_document.ecs_tasks_assume
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.execution
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.api_task
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
}

variables {
  name                   = "sentineledge-dev"
  account_id             = "123456789012"
  region                 = "us-east-2"
  kms_key_arn            = "arn:aws:kms:us-east-2:123456789012:key/00000000-0000-0000-0000-000000000000"
  subnet_ids             = ["subnet-0aaaaaaaaaaaaaaaa", "subnet-0bbbbbbbbbbbbbbbb"]
  security_group_id      = "sg-0aaaaaaaaaaaaaaaa"
  target_group_arn       = "arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/sentineledge-dev-api/0123456789abcdef"
  host_name              = "sentineledge.example.com"
  trusted_proxy_cidrs    = ["10.40.10.0/24", "10.40.11.0/24"]
  api_image              = "123456789012.dkr.ecr.us-east-2.amazonaws.com/sentineledge/api@sha256:0000000000000000000000000000000000000000000000000000000000000000"
  dbadmin_image          = "123456789012.dkr.ecr.us-east-2.amazonaws.com/sentineledge/dbadmin@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  api_repository_arn     = "arn:aws:ecr:us-east-2:123456789012:repository/sentineledge/api"
  dbadmin_repository_arn = "arn:aws:ecr:us-east-2:123456789012:repository/sentineledge/dbadmin"
  db_host                = "sentineledge-dev.abc.us-east-2.rds.amazonaws.com"
  db_name                = "sentineledge"
  master_secret_arn      = "arn:aws:secretsmanager:us-east-2:123456789012:secret:rds!db-0000-AbCdEf"
  secret_arns = {
    db_app_password      = "arn:aws:secretsmanager:us-east-2:123456789012:secret:sentineledge-dev/db-app-password-AbCdEf"
    db_migrator_password = "arn:aws:secretsmanager:us-east-2:123456789012:secret:sentineledge-dev/db-migrator-password-AbCdEf"
    jwt_signing_key      = "arn:aws:secretsmanager:us-east-2:123456789012:secret:sentineledge-dev/jwt-signing-key-AbCdEf"
    mfa_encryption_key   = "arn:aws:secretsmanager:us-east-2:123456789012:secret:sentineledge-dev/mfa-encryption-key-AbCdEf"
  }
}

run "every_container_is_hardened" {
  command = apply

  assert {
    condition = alltrue([for td in [aws_ecs_task_definition.api, aws_ecs_task_definition.migrate, aws_ecs_task_definition.dbadmin] :
      jsondecode(td.container_definitions)[0].readonlyRootFilesystem == true &&
      jsondecode(td.container_definitions)[0].privileged == false &&
      jsondecode(td.container_definitions)[0].linuxParameters.capabilities.drop == ["ALL"] &&
      !startswith(jsondecode(td.container_definitions)[0].user, "0")
    ])
    error_message = "Every container: read-only root, unprivileged, no capabilities, not root."
  }
  assert {
    condition     = aws_ecs_service.api.enable_execute_command == false
    error_message = "No shell into running tasks (ECS Exec off)."
  }
  assert {
    condition     = one(aws_ecs_service.api.network_configuration).assign_public_ip == false
    error_message = "Tasks never get a public address."
  }
}

run "the_api_enforces_deployed_defaults" {
  command = apply

  assert {
    condition     = one([for e in jsondecode(aws_ecs_task_definition.api.container_definitions)[0].environment : e.value if e.name == "SENTINEL_DB_SSLMODE"]) == "verify-full"
    error_message = "The API must verify the database certificate."
  }
  assert {
    condition     = one([for e in jsondecode(aws_ecs_task_definition.api.container_definitions)[0].environment : e.value if e.name == "SENTINEL_ENVIRONMENT"]) == "dev"
    error_message = "A deployed environment name makes the app enforce its deployed defaults."
  }
  assert {
    condition     = one([for e in jsondecode(aws_ecs_task_definition.api.container_definitions)[0].environment : e.value if e.name == "SENTINEL_PUBLIC_ORIGINS"]) == "https://sentineledge.example.com"
    error_message = "The public origin is the platform's HTTPS name."
  }
}

run "secrets_go_only_where_needed" {
  command = apply

  assert {
    condition     = toset([for s in jsondecode(aws_ecs_task_definition.api.container_definitions)[0].secrets : s.name]) == toset(["SENTINEL_DB_PASSWORD", "SENTINEL_JWT_SIGNING_KEY", "SENTINEL_MFA_ENCRYPTION_KEY"])
    error_message = "The API gets its own role's password and the auth keys, nothing else."
  }
  assert {
    condition     = toset([for s in jsondecode(aws_ecs_task_definition.migrate.container_definitions)[0].secrets : s.name]) == toset(["SENTINEL_DB_MIGRATOR_PASSWORD"])
    error_message = "Migrations get only the migrator's password."
  }
  assert {
    condition     = length([for s in jsondecode(aws_ecs_task_definition.api.container_definitions)[0].secrets : s if strcontains(s.valueFrom, "rds!")]) == 0
    error_message = "The API must never receive the RDS master credentials."
  }
  assert {
    condition     = aws_ecs_task_definition.migrate.task_role_arn == null && aws_ecs_task_definition.dbadmin.task_role_arn == null
    error_message = "Only the API has a task role."
  }
}

run "spot_by_default" {
  command = apply

  assert {
    condition     = one(aws_ecs_service.api.capacity_provider_strategy).capacity_provider == "FARGATE_SPOT"
    error_message = "Dev runs on Fargate Spot."
  }
  assert {
    condition     = one(aws_ecs_service.api.deployment_circuit_breaker).rollback == true
    error_message = "A failing deployment rolls back."
  }
}

run "an_image_by_tag_is_refused" {
  command = plan

  variables {
    api_image = "123456789012.dkr.ecr.us-east-2.amazonaws.com/sentineledge/api:latest"
  }

  expect_failures = [var.api_image]
}

run "offline_ai_is_refused_in_aws" {
  command = plan

  variables {
    ai_provider = "offline"
  }

  expect_failures = [var.ai_provider]
}
