# The edge (Phase 5, ADR-0001, ADR-0011, ADR-0027): one CloudFront distribution for
# sentineledge.bionichacker.dev.
#
#   /api/*   → a CloudFront VPC origin → the internal ALB (HTTPS, Host forwarded so the ALB's
#              host rule and the origin certificate both match the platform's name)
#   anything → a private S3 bucket through Origin Access Control (the SPA); paths without a file
#              extension are routed to index.html by a viewer-request function
#
# AWS WAF is attached (module waf), viewers get TLS 1.2 or later only, and the SPA gets exactly the
# security headers nginx sets locally (frontend/security-headers.conf; a test compares them).

locals {
  # Mirrors frontend/security-headers.conf header for header (test_edge_headers_match_nginx).
  spa_headers = {
    "Content-Security-Policy"      = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    "Strict-Transport-Security"    = "max-age=63072000; includeSubDomains"
    "X-Content-Type-Options"       = "nosniff"
    "X-Frame-Options"              = "DENY"
    "Referrer-Policy"              = "no-referrer"
    "Permissions-Policy"           = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
    "Cross-Origin-Opener-Policy"   = "same-origin"
    "Cross-Origin-Resource-Policy" = "same-origin"
    "Cross-Origin-Embedder-Policy" = "require-corp"
  }
  # Headers CloudFront has no dedicated setting for.
  custom_headers = ["Permissions-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy", "Cross-Origin-Embedder-Policy"]
  hsts_max_age   = tonumber(regex("max-age=([0-9]+)", local.spa_headers["Strict-Transport-Security"])[0])
}

# ---- The SPA bucket: private, reachable only by this distribution ----

resource "aws_s3_bucket" "spa" {
  # checkov:skip=CKV_AWS_18: Every request through the edge is in the WAF logs; S3 access logs would repeat them.
  # checkov:skip=CKV_AWS_144: The bucket holds a build that make spa-push recreates; replication adds nothing.
  # checkov:skip=CKV_AWS_145: The SPA is public content served to every visitor; SSE-S3 suffices, and SSE-KMS would need the key in us-east-1 shared with CloudFront.
  # checkov:skip=CKV2_AWS_62: No consumer for event notifications.
  bucket_prefix = "${var.name}-spa-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "spa" {
  bucket                  = aws_s3_bucket.spa.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "spa" {
  bucket = aws_s3_bucket.spa.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "spa" {
  bucket = aws_s3_bucket.spa.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "spa" {
  bucket = aws_s3_bucket.spa.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "spa" {
  bucket = aws_s3_bucket.spa.id
  rule {
    id     = "old-builds"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

data "aws_iam_policy_document" "spa" {
  statement {
    sid       = "OnlyThisDistributionReads"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.spa.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.this.arn]
    }
  }
  statement {
    sid       = "TlsOnly"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.spa.arn, "${aws_s3_bucket.spa.arn}/*"]
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

resource "aws_s3_bucket_policy" "spa" {
  bucket = aws_s3_bucket.spa.id
  policy = data.aws_iam_policy_document.spa.json

  depends_on = [aws_s3_bucket_public_access_block.spa]
}

resource "aws_cloudfront_origin_access_control" "spa" {
  name                              = "${var.name}-spa"
  description                       = "SentinelEdge SPA bucket: signed requests from CloudFront only"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# ---- The private origin: CloudFront reaches the internal ALB inside the VPC ----

resource "aws_cloudfront_vpc_origin" "alb" {
  vpc_origin_endpoint_config {
    name                   = "${var.name}-alb"
    arn                    = var.alb_arn
    http_port              = 80
    https_port             = 443
    origin_protocol_policy = "https-only"

    origin_ssl_protocols {
      items    = ["TLSv1.2"]
      quantity = 1
    }
  }
}

# ---- Behaviour ----

resource "aws_cloudfront_function" "spa_router" {
  name    = "${var.name}-spa-router"
  runtime = "cloudfront-js-2.0"
  comment = "Route SPA paths (no file extension) to index.html"
  publish = true
  code    = file("${path.module}/spa-router.js")
}

data "aws_cloudfront_cache_policy" "optimized" {
  name = "Managed-CachingOptimized"
}

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "all_viewer" {
  name = "Managed-AllViewer"
}

resource "aws_cloudfront_response_headers_policy" "spa" {
  # checkov:skip=CKV_AWS_259: HSTS is set for two years with includeSubDomains, as locally; the preload directive is left out because the whole .dev TLD is already on the browsers' preload list.
  name    = "${var.name}-spa"
  comment = "SPA security headers, identical to the local nginx (ADR-0011)"

  security_headers_config {
    content_security_policy {
      content_security_policy = local.spa_headers["Content-Security-Policy"]
      override                = true
    }
    strict_transport_security {
      access_control_max_age_sec = local.hsts_max_age
      include_subdomains         = strcontains(local.spa_headers["Strict-Transport-Security"], "includeSubDomains")
      preload                    = false
      override                   = true
    }
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = local.spa_headers["X-Frame-Options"]
      override     = true
    }
    referrer_policy {
      referrer_policy = local.spa_headers["Referrer-Policy"]
      override        = true
    }
  }

  custom_headers_config {
    dynamic "items" {
      for_each = local.custom_headers
      content {
        header   = items.value
        value    = local.spa_headers[items.value]
        override = true
      }
    }
  }

  remove_headers_config {
    items {
      header = "x-amz-server-side-encryption"
    }
    items {
      header = "x-amz-version-id"
    }
  }
}

# The API sets its own, stricter headers; the edge adds HSTS and nosniff without overriding them.
resource "aws_cloudfront_response_headers_policy" "api" {
  # checkov:skip=CKV_AWS_259: The API sends its own HSTS (the same value); the edge adds it only if missing, so override is off on purpose.
  name    = "${var.name}-api"
  comment = "API: HSTS and nosniff at the edge; the API's own headers are kept"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = local.hsts_max_age
      include_subdomains         = true
      preload                    = false
      override                   = false
    }
    content_type_options {
      override = false
    }
  }
}

resource "aws_cloudfront_distribution" "this" {
  # checkov:skip=CKV_AWS_86: WAF logs every request the edge receives, with credentials redacted; standard logs would duplicate them without redaction.
  # checkov:skip=CKV_AWS_310: One origin per path by design (ADR-0001); failover to a second region is out of scope for dev.
  # checkov:skip=CKV2_AWS_47: The attached web ACL (module waf) includes AWSManagedRulesKnownBadInputsRuleSet, which covers Log4j; Checkov cannot follow web_acl_id across modules, and the waf module's tests assert the group.
  # checkov:skip=CKV_AWS_374: No geographic restriction: a portfolio is meant to be reachable from anywhere; WAF's IP reputation list blocks known-bad sources.
  enabled             = true
  comment             = "SentinelEdge ${var.domain}"
  aliases             = [var.domain]
  is_ipv6_enabled     = true
  http_version        = "http2and3"
  price_class         = "PriceClass_100"
  default_root_object = "index.html"
  web_acl_id          = var.web_acl_arn

  origin {
    origin_id                = "spa"
    domain_name              = aws_s3_bucket.spa.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.spa.id
  }

  origin {
    origin_id   = "api"
    domain_name = var.alb_dns_name

    vpc_origin_config {
      vpc_origin_id            = aws_cloudfront_vpc_origin.alb.id
      origin_read_timeout      = var.origin_read_timeout_seconds
      origin_keepalive_timeout = 5
    }
  }

  default_cache_behavior {
    target_origin_id           = "spa"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD"]
    cached_methods             = ["GET", "HEAD"]
    compress                   = true
    cache_policy_id            = data.aws_cloudfront_cache_policy.optimized.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.spa.id

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.spa_router.arn
    }
  }

  ordered_cache_behavior {
    path_pattern               = "/api/*"
    target_origin_id           = "api"
    viewer_protocol_policy     = "https-only"
    allowed_methods            = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods             = ["GET", "HEAD"]
    compress                   = true
    cache_policy_id            = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id   = data.aws_cloudfront_origin_request_policy.all_viewer.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.api.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = var.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

# ---- The platform's name, at the apex of its delegated zone ----

resource "aws_route53_record" "alias" {
  for_each = toset(["A", "AAAA"])

  zone_id = var.zone_id
  name    = var.domain
  type    = each.key

  alias {
    name                   = aws_cloudfront_distribution.this.domain_name
    zone_id                = aws_cloudfront_distribution.this.hosted_zone_id
    evaluate_target_health = false
  }
}
