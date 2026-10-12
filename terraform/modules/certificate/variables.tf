variable "domain_name" {
  description = "The one host name the certificate covers, e.g. app.example.com."
  type        = string
}

variable "zone_id" {
  description = "Route 53 zone that holds the name, used when publish_validation_record is true."
  type        = string
  default     = ""
}

variable "publish_validation_record" {
  description = "Publish the validation record in zone_id. True for exactly one certificate per name."
  type        = bool
  default     = false

  validation {
    condition     = !var.publish_validation_record || var.zone_id != ""
    error_message = "publish_validation_record needs zone_id."
  }
}

variable "wait_for_issued" {
  description = "Wait (up to 30 minutes) until ACM has issued the certificate. Set once the zone is delegated."
  type        = bool
  default     = false
}
