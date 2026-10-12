variable "name" {
  description = "Name prefix, e.g. sentineledge-dev (32 characters at most with suffixes)."
  type        = string

  validation {
    condition     = length(var.name) <= 28
    error_message = "name must be 28 characters or fewer (target group names are limited to 32)."
  }
}

variable "account_id" {
  description = "This account's ID (the access-log prefix)."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID."
  type        = string
}

variable "subnet_ids" {
  description = "The app subnets (two zones). The ALB has no public address."
  type        = list(string)
}

variable "security_group_id" {
  description = "The ALB security group."
  type        = string
}

variable "certificate_arn" {
  description = "The issued ACM certificate for host_name, in this Region."
  type        = string
}

variable "host_name" {
  description = "The only host name forwarded to the API; anything else gets a 404."
  type        = string
}

variable "app_port" {
  description = "Port the API tasks listen on."
  type        = number
  default     = 8000
}

variable "ssl_policy" {
  description = "TLS policy: TLS 1.3, and TLS 1.2 with forward-secret AEAD ciphers only."
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
}

variable "idle_timeout_seconds" {
  description = "Idle timeout. An AI analysis can take up to 75 seconds (Phase 9), so above that."
  type        = number
  default     = 90
}

variable "deletion_protection" {
  description = "Refuse deletion. Off in dev."
  type        = bool
  default     = false
}

variable "force_destroy_logs" {
  description = "Delete the access-log bucket with its logs on destroy (dev: evidence is captured separately)."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Days access logs are kept."
  type        = number
  default     = 90
}
