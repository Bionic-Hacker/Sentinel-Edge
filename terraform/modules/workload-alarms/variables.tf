variable "name" {
  description = "Alarm name prefix, e.g. sentineledge-dev."
  type        = string
}

variable "alerts_topic_name" {
  description = "The account stack's security-alerts SNS topic."
  type        = string
}

variable "alb_arn_suffix" {
  description = "The ALB's ARN suffix (app/<name>/<id>), the LoadBalancer dimension."
  type        = string
}

variable "target_group_arn_suffix" {
  description = "The API target group's ARN suffix, the TargetGroup dimension."
  type        = string
}

variable "db_identifier" {
  description = "RDS instance identifier."
  type        = string
}

variable "api_log_group" {
  description = "The API's log group."
  type        = string
}
