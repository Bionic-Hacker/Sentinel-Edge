output "alarm_names" {
  description = "Every alarm this module creates."
  value       = concat([for a in aws_cloudwatch_metric_alarm.this : a.alarm_name], [aws_cloudwatch_metric_alarm.api_errors.alarm_name])
}
