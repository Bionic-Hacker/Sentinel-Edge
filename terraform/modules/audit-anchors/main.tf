# Where the audit chain's head is anchored (ADR-0005, Phase 4): an S3 bucket with Object Lock.
#
# Every anchor is retained in GOVERNANCE mode for `retention_days`: during that time no one can
# overwrite or delete it without s3:BypassGovernanceRetention, which no SentinelEdge role has
# (the anchor task can only put and read). The bucket stays between deploy windows: it costs
# almost nothing and the anchors outlive the database they vouch for.
#
# Governance rather than compliance mode, deliberately: compliance mode cannot be lifted even by
# the account, which would make the bucket impossible to delete for the whole retention period
# if this demo account is ever closed.

resource "aws_s3_bucket" "this" {
  # checkov:skip=CKV_AWS_18: Access to anchors is recorded by CloudTrail; a separate access-log bucket adds nothing here.
  # checkov:skip=CKV_AWS_144: Cross-region replication is not warranted for a dev portfolio; Object Lock protects the copies that exist.
  # checkov:skip=CKV2_AWS_62: No consumer for event notifications on anchors.
  bucket_prefix       = "${var.name}-audit-anchors-"
  object_lock_enabled = true
  force_destroy       = false
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

# Anchors expire some time after their lock ends; the newest is always recent.
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "expire-old-anchors"
    status = "Enabled"
    filter {
      prefix = "anchors/"
    }
    expiration {
      days = var.retention_days + var.keep_after_lock_days
    }
    noncurrent_version_expiration {
      noncurrent_days = var.retention_days + var.keep_after_lock_days
    }
  }

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

data "aws_iam_policy_document" "this" {
  statement {
    sid       = "TlsOnly"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  # Objects must be written under the platform key, never unencrypted or under another key.
  statement {
    sid       = "PlatformKeyOnly"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.this.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [var.kms_key_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.this.json

  depends_on = [aws_s3_bucket_public_access_block.this]
}
