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
