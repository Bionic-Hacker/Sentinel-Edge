variable "secret_arns" {
  description = "The secrets to write, by key (module app-secrets' secret_arns)."
  type        = map(string)

  validation {
    condition     = toset(keys(var.secret_arns)) == toset(["db_app_password", "db_migrator_password", "jwt_signing_key", "mfa_encryption_key"])
    error_message = "secret_arns must name exactly the four application secrets."
  }
}

variable "generation" {
  description = "Increase to generate and store new values (rotation). The values themselves are never in state."
  type        = number
  default     = 1

  validation {
    condition     = var.generation >= 1 && floor(var.generation) == var.generation
    error_message = "generation must be a whole number of at least 1."
  }
}
