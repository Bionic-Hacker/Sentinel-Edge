variable "repository_name" {
  description = "Repository name, e.g. sentineledge/api."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key that encrypts image layers."
  type        = string
}

variable "keep_tagged_images" {
  description = "How many tagged images to keep; older ones expire."
  type        = number
  default     = 10
}
