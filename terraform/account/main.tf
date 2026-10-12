# Account-wide guardrails. Each is free, and each removes a whole class of mistake before any
# workload exists. Two account-level resources were planned and are left out, because this
# account (AWS's new sign-up experience) denies them through an AWS-managed service control
# policy: IAM Access Analyzer, and the GitHub Actions OIDC provider (iam:CreateOpenIDConnectProvider)
# that ADR-0010 needs for Phase 11. See docs/aws-setup.md.

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
