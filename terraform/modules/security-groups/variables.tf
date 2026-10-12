variable "name" {
  description = "Name prefix, e.g. sentineledge-dev."
  type        = string
}

variable "vpc_id" {
  description = "VPC the groups belong to."
  type        = string
}

variable "app_port" {
  description = "Port the API container listens on (uvicorn)."
  type        = number
  default     = 8000
}

variable "db_port" {
  description = "PostgreSQL port."
  type        = number
  default     = 5432
}
