variable "name" {
  description = "Web ACL name, e.g. sentineledge-dev-edge."
  type        = string
}

variable "auth_rate_limit" {
  description = "Requests per IP per 5 minutes to /api/v1/auth/* before WAF blocks (the app's own limiter is tighter per account)."
  type        = number
  default     = 100

  validation {
    condition     = var.auth_rate_limit >= 10 && var.auth_rate_limit <= 2000
    error_message = "auth_rate_limit must be between 10 (WAF's minimum) and 2000."
  }
}

variable "api_rate_limit" {
  description = "Requests per IP per 5 minutes to /api/* before WAF blocks."
  type        = number
  default     = 2000

  validation {
    condition     = var.api_rate_limit >= 100
    error_message = "api_rate_limit must be at least 100."
  }
}

variable "max_body_bytes" {
  description = "Largest request body allowed through the edge (inspection covers 64 KB)."
  type        = number
  default     = 65536

  validation {
    condition     = var.max_body_bytes > 0 && var.max_body_bytes <= 65536
    error_message = "max_body_bytes must be at most 65536 (the inspection limit)."
  }
}

variable "log_retention_days" {
  description = "Days WAF logs are kept."
  type        = number
  default     = 30
}
