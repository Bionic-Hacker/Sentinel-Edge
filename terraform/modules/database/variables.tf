variable "name" {
  description = "Instance identifier and name prefix, e.g. sentineledge-dev."
  type        = string
}

variable "data_subnet_ids" {
  description = "The isolated data subnets (at least two zones, as RDS requires)."
  type        = list(string)

  validation {
    condition     = length(var.data_subnet_ids) >= 2
    error_message = "RDS needs subnets in at least two Availability Zones."
  }
}

variable "security_group_id" {
  description = "The database security group (admits only the API tasks)."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key for storage, the master secret, Performance Insights and logs."
  type        = string
}

variable "engine_major_version" {
  description = "PostgreSQL major version; minor versions are upgraded automatically."
  type        = string
  default     = "17"
}

variable "instance_class" {
  description = "Instance class. db.t4g.micro is the smallest and cheapest."
  type        = string
  default     = "db.t4g.micro"
}

variable "allocated_storage_gb" {
  description = "Initial gp3 storage in GB; autoscaling may double it."
  type        = number
  default     = 20

  validation {
    condition     = var.allocated_storage_gb >= 20
    error_message = "gp3 storage starts at 20 GB."
  }
}

variable "db_name" {
  description = "Application database name."
  type        = string
  default     = "sentineledge"
}

variable "master_username" {
  description = "The administrative role. It must not be one of the application's roles (db/bootstrap-roles.sh refuses them)."
  type        = string
  default     = "sentinel_admin"

  validation {
    condition     = !contains(["sentinel_app", "sentinel_migrator", "postgres", "rdsadmin"], var.master_username)
    error_message = "master_username must be a separate administrative role, not an application role or a reserved name."
  }
}

variable "multi_az" {
  description = "Standby in a second zone. Off in dev (it doubles the cost)."
  type        = bool
  default     = false
}

variable "backup_retention_days" {
  description = "Automated backup retention."
  type        = number
  default     = 1

  validation {
    condition     = var.backup_retention_days >= 1
    error_message = "Keep at least one day of automated backups."
  }
}

variable "deletion_protection" {
  description = "Refuse deletion. Off in dev, where the database is rebuilt each window."
  type        = bool
  default     = false
}

variable "final_snapshot" {
  description = "Take a final snapshot when the instance is destroyed."
  type        = bool
  default     = false
}
