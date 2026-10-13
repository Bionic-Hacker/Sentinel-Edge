variable "name" {
  description = "Secret name prefix, e.g. sentineledge-dev."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key that encrypts the secrets."
  type        = string
}

variable "recovery_window_in_days" {
  description = "Days a deleted secret can be restored. 0 deletes at once, so the next deploy window can recreate the same names."
  type        = number
  default     = 0

  validation {
    condition     = var.recovery_window_in_days == 0 || (var.recovery_window_in_days >= 7 && var.recovery_window_in_days <= 30)
    error_message = "recovery_window_in_days must be 0 or between 7 and 30."
  }
}
