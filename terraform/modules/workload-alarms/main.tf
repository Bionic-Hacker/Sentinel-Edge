# CloudWatch alarms for the running workload (C-MON-01), to the account's encrypted
# security-alerts topic (whose subscription the owner confirmed in Phase 3). They exist only while
# the workload does. Container Insights is off (cost), so task health is read from the ALB.

locals {
  lb = { LoadBalancer = var.alb_arn_suffix }
  tg = { LoadBalancer = var.alb_arn_suffix, TargetGroup = var.target_group_arn_suffix }
  db = { DBInstanceIdentifier = var.db_identifier }

  alarms = {
    "api-no-healthy-task" = {
      description = "No healthy API task behind the ALB: the platform is down."
      namespace   = "AWS/ApplicationELB", metric = "HealthyHostCount", dimensions = local.tg
      statistic   = "Minimum", threshold = 1, operator = "LessThanThreshold", periods = 2
    }
    "api-5xx" = {
      description = "The API is returning server errors."
      namespace   = "AWS/ApplicationELB", metric = "HTTPCode_Target_5XX_Count", dimensions = local.tg
      statistic   = "Sum", threshold = 10, operator = "GreaterThanOrEqualToThreshold", periods = 1
    }
    "api-4xx-burst" = {
      description = "A burst of refused requests (401, 403, 404, 429): probing, credential stuffing or a broken client."
      namespace   = "AWS/ApplicationELB", metric = "HTTPCode_Target_4XX_Count", dimensions = local.tg
      statistic   = "Sum", threshold = 200, operator = "GreaterThanOrEqualToThreshold", periods = 1
    }
    "alb-unrouted" = {
      description = "Requests the ALB answered itself (any other host name, malformed requests)."
      namespace   = "AWS/ApplicationELB", metric = "HTTPCode_ELB_4XX_Count", dimensions = local.lb
      statistic   = "Sum", threshold = 100, operator = "GreaterThanOrEqualToThreshold", periods = 1
    }
    "db-cpu" = {
      description = "Database CPU above 80% for 15 minutes."
      namespace   = "AWS/RDS", metric = "CPUUtilization", dimensions = local.db
      statistic   = "Average", threshold = 80, operator = "GreaterThanThreshold", periods = 3
    }
    "db-storage" = {
      description = "Database free storage below 2 GB."
      namespace   = "AWS/RDS", metric = "FreeStorageSpace", dimensions = local.db
      statistic   = "Minimum", threshold = 2147483648, operator = "LessThanThreshold", periods = 1
    }
  }
}

data "aws_sns_topic" "alerts" {
  name = var.alerts_topic_name
}

resource "aws_cloudwatch_metric_alarm" "this" {
  for_each = local.alarms

  alarm_name          = "${var.name}-${each.key}"
  alarm_description   = each.value.description
  namespace           = each.value.namespace
  metric_name         = each.value.metric
  dimensions          = each.value.dimensions
  statistic           = each.value.statistic
  period              = 300
  evaluation_periods  = each.value.periods
  threshold           = each.value.threshold
  comparison_operator = each.value.operator
  treat_missing_data  = "notBreaching"
  alarm_actions       = [data.aws_sns_topic.alerts.arn]
  ok_actions          = [data.aws_sns_topic.alerts.arn]
}

# The API logs JSON; any ERROR line counts. The log group is the API's own (encrypted, a year).
resource "aws_cloudwatch_log_metric_filter" "api_errors" {
  name           = "${var.name}-api-errors"
  log_group_name = var.api_log_group
  pattern        = "{ $.level = \"ERROR\" }"

  metric_transformation {
    name          = "ApiErrorLogs"
    namespace     = "SentinelEdge/Workload"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "api_errors" {
  alarm_name          = "${var.name}-api-error-logs"
  alarm_description   = "The API logged errors."
  namespace           = "SentinelEdge/Workload"
  metric_name         = aws_cloudwatch_log_metric_filter.api_errors.metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [data.aws_sns_topic.alerts.arn]
}
