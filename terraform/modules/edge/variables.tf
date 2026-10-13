variable "name" {
  description = "Name prefix, e.g. sentineledge-dev."
  type        = string
}

variable "domain" {
  description = "The platform's name (the zone apex), e.g. sentineledge.bionichacker.dev."
  type        = string
}

variable "zone_id" {
  description = "The delegated Route 53 zone for domain."
  type        = string
}

variable "certificate_arn" {
  description = "The issued us-east-1 ACM certificate for domain."
  type        = string
}

variable "web_acl_arn" {
  description = "The CLOUDFRONT-scope WAF web ACL (module waf)."
  type        = string
}

variable "alb_arn" {
  description = "The internal ALB the VPC origin reaches."
  type        = string
}

variable "alb_dns_name" {
  description = "The internal ALB's DNS name."
  type        = string
}

variable "origin_read_timeout_seconds" {
  description = "How long CloudFront waits for the API (60 is CloudFront's default maximum; the app keeps AI calls under it)."
  type        = number
  default     = 60

  validation {
    condition     = var.origin_read_timeout_seconds >= 1 && var.origin_read_timeout_seconds <= 60
    error_message = "origin_read_timeout_seconds must be between 1 and 60 without a quota increase."
  }
}
