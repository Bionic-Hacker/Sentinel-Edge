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
  description = "Public host name of the platform (an is-a.dev subdomain, ADR-0025)."
  type        = string
  default     = "app.sentineledge.is-a.dev"
}
