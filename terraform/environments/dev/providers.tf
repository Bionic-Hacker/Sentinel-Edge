locals {
  default_tags = {
    Project     = "SentinelEdge"
    Stack       = "dev"
    Environment = var.environment
    ManagedBy   = "Terraform"
    Repository  = "Bionic-Hacker/Sentinel-Edge"
  }
}

# The account's home Region (fixed at sign-up; see docs/aws-setup.md).
provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = local.default_tags
  }
}

# us-east-1 only for what CloudFront requires there: its certificate (and, in Phase 5, its WAF
# web ACL).
provider "aws" {
  alias               = "us_east_1"
  region              = "us-east-1"
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = local.default_tags
  }
}
