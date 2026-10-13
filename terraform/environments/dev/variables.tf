variable "account_id" {
  description = "The AWS account this stack may change. Any other account is refused."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "region" {
  description = "Home Region of the account."
  type        = string
  default     = "us-east-2"
}

variable "project" {
  description = "Prefix for resource names. Must match the bootstrap and account stacks'."
  type        = string
  default     = "sentineledge"
}

variable "environment" {
  description = "Environment name, used in resource names and tags."
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "VPC address range."
  type        = string
  default     = "10.40.0.0/16"
}

variable "availability_zone_ids" {
  description = "Availability Zone IDs for the subnets (us-east-2)."
  type        = list(string)
  default     = ["use2-az1", "use2-az2"]
}

variable "nat_mode" {
  description = "App-tier egress: none (between windows, free), instance (deploy window default) or gateway."
  type        = string
  default     = "none"
}

variable "app_domain" {
  description = "Public host name of the platform: the apex of a zone delegated from the owner's domain (ADR-0025). Empty requests no zone and no certificates."
  type        = string
  default     = "sentineledge.bionichacker.dev"

  validation {
    condition     = var.app_domain == "" || can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.){2,}[a-z]{2,63}$", var.app_domain))
    error_message = "app_domain must be empty or a lower-case name below a registered domain, such as sentineledge.example.com."
  }
}

variable "dns_delegated" {
  description = "Set true once the registrar's NS records for app_domain are live: Terraform then waits for both certificates to be issued."
  type        = bool
  default     = false
}

variable "caa_iodef" {
  description = "Optional CAA iodef URL (mailto: or https:) where certificate authorities report refused requests."
  type        = string
  default     = ""
}

# --- Phase 4: the deploy-window switch and the workload's settings (ADR-0026) ---

variable "workload" {
  description = "true during a deploy window: the database, secrets, internal ALB and ECS exist. false between windows: none of them do."
  type        = bool
  default     = false

  validation {
    condition     = !var.workload || (var.nat_mode != "none" && var.dns_delegated && var.app_domain != "")
    error_message = "The workload needs nat_mode instance or gateway (tasks pull images and read secrets through NAT) and an issued certificate (app_domain set and dns_delegated = true)."
  }
  validation {
    condition     = !var.workload || (var.api_image != "" && var.dbadmin_image != "")
    error_message = "The workload needs api_image and dbadmin_image: run make images-push first (it writes images.auto.tfvars)."
  }
}

variable "api_image" {
  description = "API image by digest. make images-push writes it to images.auto.tfvars."
  type        = string
  default     = ""
}

variable "dbadmin_image" {
  description = "Role-bootstrap image by digest. make images-push writes it to images.auto.tfvars."
  type        = string
  default     = ""
}

variable "api_desired_count" {
  description = "Running API tasks. 0 for the first apply of a window, until the roles and migrations have run."
  type        = number
  default     = 1
}

variable "use_spot" {
  description = "Run the API on Fargate Spot (about 70% cheaper; interrupted tasks are replaced)."
  type        = bool
  default     = true
}

variable "ai_provider" {
  description = "The API's AI provider in AWS: bedrock (through the task role) or disabled."
  type        = string
  default     = "bedrock"
}

variable "app_secrets_generation" {
  description = "Increase to generate and store new application secrets (rotation)."
  type        = number
  default     = 1
}
