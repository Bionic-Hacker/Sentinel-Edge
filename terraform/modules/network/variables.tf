variable "name" {
  description = "Name prefix for every resource, e.g. sentineledge-dev."
  type        = string
}

variable "cidr_block" {
  description = "VPC address range. Each tier takes /24s from it: public 0-, app 10-, data 20-."
  type        = string
  default     = "10.40.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.cidr_block)) && tonumber(split("/", var.cidr_block)[1]) <= 16
    error_message = "cidr_block must be a valid IPv4 range of /16 or larger."
  }
}

variable "availability_zone_ids" {
  description = "Availability Zone IDs to use (IDs, not names, mean the same zones in every account). Two is the minimum for an ALB and an RDS subnet group."
  type        = list(string)

  validation {
    condition     = length(var.availability_zone_ids) >= 2 && length(var.availability_zone_ids) <= 3
    error_message = "Give two or three Availability Zone IDs."
  }
}

variable "nat_mode" {
  description = <<-EOT
    How the app subnets reach the internet (AWS APIs, Bedrock, ECR):
    "none" (no egress; the free resting state between deploy windows),
    "instance" (one t4g.nano NAT instance, about $0.009/hour with its public IPv4 address),
    "gateway" (one managed NAT gateway, about $0.05/hour).
  EOT
  type        = string
  default     = "none"

  validation {
    condition     = contains(["none", "instance", "gateway"], var.nat_mode)
    error_message = "nat_mode must be none, instance or gateway."
  }
}

variable "nat_instance_type" {
  description = "Instance type of the NAT instance (Graviton, so the AMI is arm64)."
  type        = string
  default     = "t4g.nano"
}

variable "kms_key_arn" {
  description = "KMS key for the flow-log group."
  type        = string
}

variable "flow_log_retention_days" {
  description = "Retention of VPC flow logs, in days."
  type        = number
  default     = 365
}
