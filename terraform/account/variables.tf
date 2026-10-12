variable "account_id" {
  description = "The AWS account this stack may change. Any other account is refused."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "region" {
  description = "Home region. CloudTrail is multi-region; everything else here lives in this region."
  type        = string
  default     = "us-east-2"
}

variable "project" {
  description = "Prefix for resource names. Must match the bootstrap stack's."
  type        = string
  default     = "sentineledge"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.project))
    error_message = "project must be 3-21 lower-case letters, digits or hyphens."
  }
}

variable "alert_email" {
  description = "Address subscribed to security alerts. AWS sends a confirmation e-mail that must be accepted."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be an e-mail address."
  }
}

variable "log_retention_days" {
  description = "Retention of the CloudTrail log group and the trail's S3 objects, in days."
  type        = number
  default     = 365

  validation {
    condition     = contains([365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "Use a CloudWatch Logs retention value of at least 365 days."
  }
}

variable "bedrock_model_id" {
  description = "The one Bedrock model the local API may invoke, through its US inference profile (SENTINEL_AI_MODEL is us.<this>)."
  type        = string
  default     = "amazon.nova-micro-v1:0"
}

variable "bedrock_profile_regions" {
  description = "Regions the US inference profile routes calls to."
  type        = list(string)
  default     = ["us-east-1", "us-east-2", "us-west-2"]
}
