provider "aws" {
  region = var.region

  # Refuse to touch any account but the one named in terraform.tfvars (ADR-0014).
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = {
      Project    = "SentinelEdge"
      Stack      = "bootstrap"
      ManagedBy  = "Terraform"
      Repository = "Bionic-Hacker/Sentinel-Edge"
    }
  }
}
