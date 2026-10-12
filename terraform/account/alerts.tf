# Security alarms on the account trail (CIS AWS Foundations, monitoring section). Metric filters
# are free and the first ten alarms are in the always-free tier. Each alarm e-mails the
# security-alerts topic. Expect trail or key alerts only when you change those things yourself;
# root use should never happen. (People sign in with AWS Builder ID, and IAM users cannot use the
# console in this account, so there is no IAM console sign-in alarm.)

locals {
  security_alarms = {
    "root-account-usage" = {
      description = "The root user was used. Root is for account recovery only."
      pattern     = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
      threshold   = 1
    }
    "cloudtrail-config-changed" = {
      description = "A trail was created, changed, stopped or deleted."
      pattern     = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
      threshold   = 1
    }
    "kms-key-disabled-or-deleted" = {
      description = "A customer-managed KMS key was disabled or scheduled for deletion."
      pattern     = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
      threshold   = 1
    }
    "unauthorized-api-calls" = {
      description = "Ten or more access-denied API calls in five minutes: probing, or a broken role."
      pattern     = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
      threshold   = 10
    }
  }
}

resource "aws_sns_topic" "security_alerts" {
  name              = "${var.project}-security-alerts"
  kms_master_key_id = aws_kms_key.platform.arn
}

data "aws_iam_policy_document" "security_alerts" {
  statement {
    sid       = "CloudWatchAlarmsInThisAccountPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudwatch:${var.region}:${var.account_id}:alarm:*"]
    }
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = data.aws_iam_policy_document.security_alerts.json
}

resource "aws_sns_topic_subscription" "security_alerts_email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "security" {
  for_each = local.security_alarms

  name           = each.key
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = each.value.pattern

  metric_transformation {
    name      = each.key
    namespace = "SentinelEdge/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security" {
  for_each = local.security_alarms

  alarm_name          = "${var.project}-${each.key}"
  alarm_description   = each.value.description
  namespace           = "SentinelEdge/Security"
  metric_name         = aws_cloudwatch_log_metric_filter.security[each.key].metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}
