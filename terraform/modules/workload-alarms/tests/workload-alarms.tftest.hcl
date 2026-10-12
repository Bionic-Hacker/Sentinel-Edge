# terraform test, with a mocked AWS provider: no credentials, no AWS calls, no cost.
# Run by scripts/tf-check.sh (make tf-check, and CI).

mock_provider "aws" {
  override_data {
    target = data.aws_sns_topic.alerts
    values = { arn = "arn:aws:sns:us-east-2:123456789012:sentineledge-security-alerts" }
  }
}

variables {
  name                    = "sentineledge-dev"
  alerts_topic_name       = "sentineledge-security-alerts"
  alb_arn_suffix          = "app/sentineledge-dev/0123456789abcdef"
  target_group_arn_suffix = "targetgroup/sentineledge-dev-api/0123456789abcdef"
  db_identifier           = "sentineledge-dev"
  api_log_group           = "/ecs/sentineledge-dev/api"
}

run "every_alarm_notifies_the_security_topic" {
  command = apply

  assert {
    condition     = alltrue([for a in aws_cloudwatch_metric_alarm.this : a.alarm_actions == toset(["arn:aws:sns:us-east-2:123456789012:sentineledge-security-alerts"])]) && aws_cloudwatch_metric_alarm.api_errors.alarm_actions == toset(["arn:aws:sns:us-east-2:123456789012:sentineledge-security-alerts"])
    error_message = "Every alarm must notify the confirmed security-alerts topic."
  }
  assert {
    condition     = length(output.alarm_names) == 7
    error_message = "Availability, errors, a 4xx burst, unrouted requests, database CPU and storage, and logged errors."
  }
}

run "the_platform_being_down_alarms" {
  command = apply

  assert {
    condition     = aws_cloudwatch_metric_alarm.this["api-no-healthy-task"].metric_name == "HealthyHostCount" && aws_cloudwatch_metric_alarm.this["api-no-healthy-task"].comparison_operator == "LessThanThreshold" && aws_cloudwatch_metric_alarm.this["api-no-healthy-task"].threshold == 1
    error_message = "Fewer than one healthy task must alarm."
  }
  assert {
    condition     = aws_cloudwatch_log_metric_filter.api_errors.pattern == "{ $.level = \"ERROR\" }"
    error_message = "ERROR lines in the API's JSON log are counted."
  }
}
