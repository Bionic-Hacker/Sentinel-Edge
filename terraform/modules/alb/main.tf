# The internal Application Load Balancer: the only way into the API tasks (ADR-0001, ADR-0026).
#
# - Internal: no public address. In Phase 5 CloudFront reaches it through a VPC origin; until
#   then nothing outside the VPC can (its security group admits nothing yet).
# - HTTPS only, TLS 1.2 or 1.3 with the ACM certificate for the platform's name; no port 80.
# - Requests for any other host name get a 404 from the ALB itself, before reaching the API.
# - Malformed headers are dropped and HTTP desync is handled in the strictest mode.
# - Access logs go to a dedicated bucket.

data "aws_elb_service_account" "this" {}

resource "aws_s3_bucket" "logs" {
  # checkov:skip=CKV_AWS_18: This is the access-log bucket; logging it to itself would loop.
  # checkov:skip=CKV_AWS_144: Cross-region replication is not warranted for dev load-balancer logs.
  # checkov:skip=CKV_AWS_145: ALB access logs support only SSE-S3 (AWS-managed keys), not SSE-KMS.
  # checkov:skip=CKV2_AWS_62: No consumer for event notifications on access logs.
  bucket_prefix = "${var.name}-alb-logs-"
  force_destroy = var.force_destroy_logs
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration {
      days = var.log_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

data "aws_iam_policy_document" "logs" {
  statement {
    sid       = "ElbDeliversAccessLogs"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/alb/AWSLogs/${var.account_id}/*"]
    principals {
      type        = "AWS"
      identifiers = [data.aws_elb_service_account.this.arn]
    }
  }
  statement {
    sid       = "TlsOnly"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]
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
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs.json

  depends_on = [aws_s3_bucket_public_access_block.logs]
}

resource "aws_lb" "this" {
  # checkov:skip=CKV_AWS_150: Deletion protection is a variable, off in dev where the ALB exists only during a deploy window (ADR-0026).
  # checkov:skip=CKV2_AWS_28: AWS WAF is attached at CloudFront in Phase 5 (ADR-0008); the ALB is internal and reachable only from the VPC origin.
  name                                        = var.name
  internal                                    = true
  load_balancer_type                          = "application"
  subnets                                     = var.subnet_ids
  security_groups                             = [var.security_group_id]
  drop_invalid_header_fields                  = true
  desync_mitigation_mode                      = "strictest"
  enable_deletion_protection                  = var.deletion_protection
  enable_http2                                = true
  idle_timeout                                = var.idle_timeout_seconds
  preserve_host_header                        = true
  xff_header_processing_mode                  = "append"
  enable_xff_client_port                      = false
  enable_tls_version_and_cipher_suite_headers = false

  access_logs {
    bucket  = aws_s3_bucket.logs.id
    prefix  = "alb"
    enabled = true
  }

  depends_on = [aws_s3_bucket_policy.logs]
}

resource "aws_lb_target_group" "api" {
  # checkov:skip=CKV_AWS_378: TLS terminates at the ALB; the hop to the tasks stays inside private subnets, admitted only from the ALB's security group (ADR-0026).
  name                 = "${var.name}-api"
  vpc_id               = var.vpc_id
  target_type          = "ip"
  protocol             = "HTTP"
  port                 = var.app_port
  deregistration_delay = 15

  health_check {
    path                = "/api/v1/health"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_policy
  certificate_arn   = var.certificate_arn

  # Anything not addressed to the platform's name is refused here.
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Not found"
      status_code  = "404"
    }
  }
}

resource "aws_lb_listener_rule" "api" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10

  condition {
    host_header {
      values = [var.host_name]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}
