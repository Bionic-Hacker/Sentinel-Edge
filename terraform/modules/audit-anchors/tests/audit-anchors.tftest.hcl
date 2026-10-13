# terraform test, with a mocked AWS provider: no credentials, no AWS calls, no cost.
# Run by scripts/tf-check.sh (make tf-check, and CI).

mock_provider "aws" {
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::sentineledge-dev-audit-anchors-0001", id = "sentineledge-dev-audit-anchors-0001" }
  }
  override_data {
    target = data.aws_iam_policy_document.this
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
}

variables {
  name        = "sentineledge-dev"
  kms_key_arn = "arn:aws:kms:us-east-2:123456789012:key/00000000-0000-0000-0000-000000000000"
}

run "anchors_are_locked_and_encrypted" {
  command = apply

  assert {
    condition     = aws_s3_bucket.this.object_lock_enabled == true
    error_message = "The bucket must have Object Lock."
  }
  assert {
    condition     = one(one(aws_s3_bucket_object_lock_configuration.this.rule).default_retention).mode == "GOVERNANCE" && one(one(aws_s3_bucket_object_lock_configuration.this.rule).default_retention).days == 30
    error_message = "Every anchor is retained 30 days in governance mode by default."
  }
  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.this.rule).apply_server_side_encryption_by_default).kms_master_key_id == var.kms_key_arn
    error_message = "Anchors are encrypted under the platform key."
  }
  assert {
    condition     = aws_s3_bucket.this.force_destroy == false
    error_message = "The bucket must never be destroyed with its anchors."
  }
}

run "private_and_tls_only" {
  command = apply

  assert {
    condition     = aws_s3_bucket_public_access_block.this.block_public_policy && aws_s3_bucket_public_access_block.this.restrict_public_buckets
    error_message = "The bucket must block public access."
  }
  assert {
    condition     = one([for st in data.aws_iam_policy_document.this.statement : st.effect if st.sid == "TlsOnly"]) == "Deny"
    error_message = "Requests without TLS are refused."
  }
  assert {
    condition     = one([for st in data.aws_iam_policy_document.this.statement : st.effect if st.sid == "PlatformKeyOnly"]) == "Deny"
    error_message = "Objects under any other key are refused."
  }
}

run "anchors_expire_only_after_their_lock" {
  command = apply

  assert {
    condition     = one([for r in aws_s3_bucket_lifecycle_configuration.this.rule : one(r.expiration).days if r.id == "expire-old-anchors"]) > 30
    error_message = "Anchors must outlive their Object Lock retention."
  }
}

run "a_year_and_more_is_refused" {
  command = plan

  variables {
    retention_days = 400
  }

  expect_failures = [var.retention_days]
}
