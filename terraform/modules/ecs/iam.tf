# One execution role per task family (pull its image, write its logs, read its secrets), and one
# task role, for the API only. Every permission is written next to its reason (C-IAM-03).

data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:ecs:${var.region}:${var.account_id}:*"]
    }
  }
}

locals {
  # The secrets each family's execution role may read, and nothing else.
  family_secrets = {
    api     = [var.secret_arns["db_app_password"], var.secret_arns["jwt_signing_key"], var.secret_arns["mfa_encryption_key"]]
    migrate = [var.secret_arns["db_migrator_password"]]
    dbadmin = [var.master_secret_arn, var.secret_arns["db_app_password"], var.secret_arns["db_migrator_password"]]
    anchor  = [var.secret_arns["db_app_password"]]
  }
  family_repository = {
    api     = var.api_repository_arn
    migrate = var.api_repository_arn
    dbadmin = var.dbadmin_repository_arn
    anchor  = var.api_repository_arn
  }
}

resource "aws_iam_role" "execution" {
  for_each = local.families

  name               = "${var.name}-${each.key}-execution"
  description        = "ECS pulls the ${each.key} image, writes its logs and injects its secrets."
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

data "aws_iam_policy_document" "execution" {
  for_each = local.families

  # ECR's login token is account-wide; the pull itself is limited to one repository.
  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid       = "PullOwnImage"
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
    resources = [local.family_repository[each.key]]
  }
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.this[each.key].arn}:*"]
  }
  statement {
    sid       = "ReadOwnSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = local.family_secrets[each.key]
  }
  # Secrets and image layers are encrypted under the platform key; decrypt only on their behalf.
  statement {
    sid       = "DecryptForSecretsAndImages"
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.amazonaws.com", "ecr.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "execution" {
  for_each = local.families

  name   = "pull-log-secrets"
  role   = aws_iam_role.execution[each.key].id
  policy = data.aws_iam_policy_document.execution[each.key].json
}

# The API's own identity: Bedrock through the US inference profile, the same single permission
# the local role has (account stack, ADR-0024). Nothing else.
resource "aws_iam_role" "api_task" {
  name               = "${var.name}-api-task"
  description        = "The running API: invoke one Bedrock model through its US profile."
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

locals {
  inference_profile_arn = "arn:aws:bedrock:${var.region}:${var.account_id}:inference-profile/us.${var.bedrock_model_id}"
}

data "aws_iam_policy_document" "api_task" {
  statement {
    sid       = "InvokeThroughTheUsProfile"
    actions   = ["bedrock:InvokeModel"]
    resources = [local.inference_profile_arn]
  }
  statement {
    sid       = "TheModelOnlyThroughThatProfile"
    actions   = ["bedrock:InvokeModel"]
    resources = [for r in var.bedrock_profile_regions : "arn:aws:bedrock:${r}::foundation-model/${var.bedrock_model_id}"]

    condition {
      test     = "StringEquals"
      variable = "bedrock:InferenceProfileArn"
      values   = [local.inference_profile_arn]
    }
  }
}

resource "aws_iam_role_policy" "api_task" {
  name   = "invoke-one-model"
  role   = aws_iam_role.api_task.id
  policy = data.aws_iam_policy_document.api_task.json
}

# The anchor task: write new anchors and read them back. It cannot delete them, change their
# retention or bypass Object Lock (no s3:DeleteObject*, s3:PutObjectRetention or
# s3:BypassGovernanceRetention).
resource "aws_iam_role" "anchor_task" {
  name               = "${var.name}-anchor-task"
  description        = "Hourly audit anchor: put and read objects under anchors/ in one bucket."
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

data "aws_iam_policy_document" "anchor_task" {
  statement {
    sid       = "WriteAndReadAnchors"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["arn:aws:s3:::${var.audit_anchor_bucket}/anchors/*"]
  }
  statement {
    sid       = "ListAnchors"
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.audit_anchor_bucket}"]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["anchors/*"]
    }
  }
  statement {
    sid       = "EncryptAnchorsWithThePlatformKey"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [var.kms_key_arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "anchor_task" {
  name   = "anchor-audit-chain"
  role   = aws_iam_role.anchor_task.id
  policy = data.aws_iam_policy_document.anchor_task.json
}
