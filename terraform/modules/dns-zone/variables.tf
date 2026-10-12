variable "zone_name" {
  description = "The delegated name, e.g. sentineledge.example.com. The platform is served at its apex."
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.){2,}[a-z]{2,63}$", var.zone_name))
    error_message = "zone_name must be a lower-case name below a registered domain, such as sentineledge.example.com."
  }
}

variable "caa_issuers" {
  description = "Certificate authorities allowed to issue for the zone (CAA issue). ACM accepts amazon.com."
  type        = list(string)
  default     = ["amazon.com"]

  validation {
    condition     = length(var.caa_issuers) > 0 && alltrue([for ca in var.caa_issuers : can(regex("^[a-z0-9.-]+$", ca))])
    error_message = "caa_issuers must name at least one issuer domain."
  }
}

variable "caa_iodef" {
  description = "Optional CAA iodef URL (mailto: or https:) where CAs report refused requests. Empty for none."
  type        = string
  default     = ""

  validation {
    condition     = var.caa_iodef == "" || can(regex("^(mailto:|https://)", var.caa_iodef))
    error_message = "caa_iodef must be empty or start with mailto: or https://."
  }
}
