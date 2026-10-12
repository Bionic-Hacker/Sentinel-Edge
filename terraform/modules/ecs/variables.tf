variable "name" {
  description = "Name prefix, e.g. sentineledge-dev."
  type        = string
}

variable "environment" {
  description = "SENTINEL_ENVIRONMENT for the app (a deployed value: dev, staging or production)."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "environment must be a deployed environment, so the app enforces its deployed defaults."
  }
}

variable "account_id" {
  description = "This account's ID."
  type        = string
}

variable "region" {
  description = "Home Region."
  type        = string
}

variable "kms_key_arn" {
  description = "Platform KMS key (logs, secrets, images)."
  type        = string
}

variable "subnet_ids" {
  description = "App subnets for the tasks (no public addresses)."
  type        = list(string)
}

variable "security_group_id" {
  description = "The app security group (from the ALB in; to the database and HTTPS out)."
  type        = string
}

variable "target_group_arn" {
  description = "The ALB target group for the API."
  type        = string
}

variable "host_name" {
  description = "The platform's public host name."
  type        = string
}

variable "trusted_proxy_cidrs" {
  description = "Subnets whose X-Forwarded-For the API trusts: where the ALB's nodes are."
  type        = list(string)
}

variable "app_port" {
  description = "API container port."
  type        = number
  default     = 8000
}

variable "api_image" {
  description = "API image by digest: <account>.dkr.ecr.<region>.amazonaws.com/sentineledge/api@sha256:<64 hex>."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}\\.dkr\\.ecr\\.[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9/_-]+@sha256:[0-9a-f]{64}$", var.api_image))
    error_message = "api_image must be an ECR image referenced by digest (…@sha256:…), never by a tag."
  }
}

variable "dbadmin_image" {
  description = "Role-bootstrap image by digest."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}\\.dkr\\.ecr\\.[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9/_-]+@sha256:[0-9a-f]{64}$", var.dbadmin_image))
    error_message = "dbadmin_image must be an ECR image referenced by digest (…@sha256:…), never by a tag."
  }
}

variable "api_repository_arn" {
  description = "ECR repository the API and migrate tasks pull from."
  type        = string
}

variable "dbadmin_repository_arn" {
  description = "ECR repository the dbadmin task pulls from."
  type        = string
}

variable "db_host" {
  description = "RDS host name (the certificate is verified against it)."
  type        = string
}

variable "db_port" {
  description = "RDS port."
  type        = number
  default     = 5432
}

variable "db_name" {
  description = "Application database."
  type        = string
}

variable "secret_arns" {
  description = "Application secrets by key (module app-secrets)."
  type        = map(string)
}

variable "master_secret_arn" {
  description = "The RDS-managed master secret (dbadmin only)."
  type        = string
}

variable "api_cpu" {
  description = "API task CPU units."
  type        = number
  default     = 512
}

variable "api_memory" {
  description = "API task memory (MiB). Argon2id uses 64 MiB per hash."
  type        = number
  default     = 1024
}

variable "api_desired_count" {
  description = "Running API tasks. 0 until the roles and migrations have run in a new window."
  type        = number
  default     = 1

  validation {
    condition     = var.api_desired_count >= 0 && var.api_desired_count <= 4
    error_message = "api_desired_count must be between 0 and 4."
  }
}

variable "use_spot" {
  description = "Run on Fargate Spot (about 70% cheaper; tasks can be interrupted and are replaced)."
  type        = bool
  default     = true
}

variable "ai_provider" {
  description = "SENTINEL_AI_PROVIDER: disabled or bedrock in AWS (offline is a local test aid)."
  type        = string
  default     = "bedrock"

  validation {
    condition     = contains(["disabled", "bedrock"], var.ai_provider)
    error_message = "ai_provider must be disabled or bedrock in AWS."
  }
}

variable "bedrock_model_id" {
  description = "The one model the API may invoke, through its US inference profile."
  type        = string
  default     = "amazon.nova-micro-v1:0"
}

variable "bedrock_profile_regions" {
  description = "Regions the US inference profile routes calls to."
  type        = list(string)
  default     = ["us-east-1", "us-east-2", "us-west-2"]
}

variable "audit_anchor_bucket" {
  description = "The Object Lock bucket for audit-chain anchors (module audit-anchors)."
  type        = string
}

variable "anchor_schedule" {
  description = "When the audit chain is anchored (EventBridge Scheduler expression)."
  type        = string
  default     = "rate(1 hour)"
}
