variable "zone_id" {
  description = "The Route 53 hosted zone whose queries are logged."
  type        = string
}

variable "zone_name" {
  description = "The zone's name, used in the log group's name."
  type        = string
}

variable "account_id" {
  description = "The account that owns the zone (the log policy admits only its zone)."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "retention_days" {
  description = "How long query logs are kept."
  type        = number
  default     = 365
}
