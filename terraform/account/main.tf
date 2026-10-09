# Account-wide guardrails. Each is free, and each removes a whole class of mistake before any
# workload exists. IAM Access Analyzer would belong here, but this account (AWS's new sign-up
# experience) denies it through an AWS-managed service control policy; see docs/aws-setup.md.

# No bucket in this account can be made public, whatever its own settings say.
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Every new EBS volume (the NAT instance's, from Part 2) is encrypted.
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

# GitHub Actions identity provider. No role trusts it yet: deployment roles, scoped to a GitHub
# environment, arrive with the pipeline in Phase 11 (ADR-0010). Until then it grants nothing.
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}
