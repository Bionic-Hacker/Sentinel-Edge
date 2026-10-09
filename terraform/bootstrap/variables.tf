variable "account_id" {
  description = "The AWS account this stack may change. Any other account is refused."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "region" {
  description = "Home region for the state bucket and every regional resource."
  type        = string
  default     = "us-east-2"
}

variable "project" {
  description = "Prefix for resource names. Lower case, used in globally unique bucket names."
  type        = string
  default     = "sentineledge"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.project))
    error_message = "project must be 3-21 lower-case letters, digits or hyphens."
  }
}

variable "budget_email" {
  description = "Address that receives the cost budget alerts."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.budget_email))
    error_message = "budget_email must be an e-mail address."
  }
}

variable "monthly_budget_usd" {
  description = "Monthly cost budget for the whole account, in US dollars."
  type        = number
  default     = 30
}

variable "budget_alert_thresholds_usd" {
  description = "Actual-spend amounts (USD) that each send an alert. At most four: AWS allows five notifications per budget, and one is the forecast alert."
  type        = list(number)
  default     = [5, 15, 30]

  validation {
    condition     = length(var.budget_alert_thresholds_usd) >= 1 && length(var.budget_alert_thresholds_usd) <= 4
    error_message = "Give between one and four thresholds."
  }
}
