# The platform key: encrypts the CloudTrail logs and log group, the security-alerts topic, and
# (from Part 2) the environment's logs, images and secrets. One customer-managed key keeps the
# standing cost at $1 a month; a separate key per service is the step up for production.

locals {
  trail_name = "${var.project}-account"
  trail_arn  = "arn:aws:cloudtrail:${var.region}:${var.account_id}:trail/${local.trail_name}"
}

data "aws_iam_policy_document" "platform_key" {
  # checkov:skip=CKV_AWS_109: A KMS key policy must grant the account kms:* or the key becomes unmanageable; IAM policies then decide who may use it.
  # checkov:skip=CKV_AWS_111: Same as above: "*" in a key policy means this key only, and access is delegated to IAM.
  # checkov:skip=CKV_AWS_356: In a key policy the resource can only be "*", which refers to the key itself.
  statement {
    sid       = "AccountAdministersKeyThroughIam"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
  }

  statement {
    sid       = "CloudTrailEncryptsThisAccountsTrail"
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${var.account_id}:trail/*"]
    }
  }

  statement {
    sid       = "CloudTrailDescribesKey"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid = "CloudWatchLogsEncryptsThisAccountsLogGroups"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.region}:${var.account_id}:log-group:*"]
    }
  }

  # Alarms publish to the encrypted alerts topic, so CloudWatch needs the key for that message.
  statement {
    sid       = "CloudWatchAlarmsPublishToEncryptedTopic"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_kms_key" "platform" {
  description             = "SentinelEdge platform data: audit trail, logs, alerts, images, secrets"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.platform_key.json
}

resource "aws_kms_alias" "platform" {
  name          = "alias/${var.project}-platform"
  target_key_id = aws_kms_key.platform.key_id
}
