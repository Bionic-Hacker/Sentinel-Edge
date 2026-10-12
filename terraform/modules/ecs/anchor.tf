# EventBridge Scheduler runs the anchor task every hour while the workload exists. Its role may
# start that one task definition and pass its two roles to ECS, nothing else.

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${var.name}-anchor-scheduler"
  description        = "EventBridge Scheduler: run the audit-anchor task, nothing else."
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

data "aws_iam_policy_document" "scheduler" {
  statement {
    sid       = "RunTheAnchorTask"
    actions   = ["ecs:RunTask"]
    resources = ["${trimsuffix(aws_ecs_task_definition.anchor.arn, ":${aws_ecs_task_definition.anchor.revision}")}:*"]

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.this.arn]
    }
  }
  statement {
    sid       = "PassItsRoles"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.execution["anchor"].arn, aws_iam_role.anchor_task.arn]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "scheduler" {
  name   = "run-anchor-task"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler.json
}

resource "aws_scheduler_schedule" "anchor" {
  name        = "${var.name}-audit-anchor"
  description = "Anchor the audit chain's head in S3 Object Lock (ADR-0005)."
  state       = "ENABLED"
  kms_key_arn = var.kms_key_arn

  schedule_expression = var.anchor_schedule

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_ecs_cluster.this.arn
    role_arn = aws_iam_role.scheduler.arn

    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.anchor.arn
      launch_type         = "FARGATE"
      task_count          = 1

      network_configuration {
        subnets          = var.subnet_ids
        security_groups  = [var.security_group_id]
        assign_public_ip = false
      }
    }

    retry_policy {
      maximum_retry_attempts       = 2
      maximum_event_age_in_seconds = 1800
    }
  }
}
