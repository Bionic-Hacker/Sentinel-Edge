variable "name" {
  description = "Bucket name prefix, e.g. sentineledge-dev."
  type        = string
}

variable "kms_key_arn" {
  description = "Platform KMS key (SSE-KMS)."
  type        = string
}

variable "retention_days" {
  description = "Object Lock retention (GOVERNANCE) for each anchor."
  type        = number
  default     = 30

  validation {
    condition     = var.retention_days >= 1 && var.retention_days <= 365
    error_message = "retention_days must be between 1 and 365."
  }
}

variable "keep_after_lock_days" {
  description = "Days an anchor is kept after its lock ends, before it expires."
  type        = number
  default     = 60
}
