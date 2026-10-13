# terraform test, with a mocked AWS provider: no credentials, no AWS calls, no cost.
# Run by scripts/tf-check.sh (make tf-check, and CI).

mock_provider "aws" {
  mock_resource "aws_s3_bucket" {
    defaults = {
      arn                         = "arn:aws:s3:::sentineledge-dev-spa-0001"
      id                          = "sentineledge-dev-spa-0001"
      bucket_regional_domain_name = "sentineledge-dev-spa-0001.s3.us-east-1.amazonaws.com"
    }
  }
  mock_resource "aws_cloudfront_distribution" {
    defaults = {
      arn            = "arn:aws:cloudfront::123456789012:distribution/E0000000000000"
      domain_name    = "d111111abcdef8.cloudfront.net"
      hosted_zone_id = "Z2FDTNDATAQYW2"
    }
  }
  mock_resource "aws_cloudfront_function" {
    defaults = { arn = "arn:aws:cloudfront::123456789012:function/sentineledge-dev-spa-router" }
  }
  override_data {
    target = data.aws_iam_policy_document.spa
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
}

variables {
  name            = "sentineledge-dev"
  domain          = "sentineledge.example.com"
  zone_id         = "Z0123456789ABCDEFGHIJ"
  certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000001"
  web_acl_arn     = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/sentineledge-dev-edge/00000000-0000-0000-0000-000000000000"
  alb_arn         = "arn:aws:elasticloadbalancing:us-east-2:123456789012:loadbalancer/app/sentineledge-dev/0123456789abcdef"
  alb_dns_name    = "internal-sentineledge-dev-123456789.us-east-2.elb.amazonaws.com"
}

run "viewers_get_modern_tls_and_waf" {
  command = apply

  assert {
    condition     = aws_cloudfront_distribution.this.viewer_certificate[0].minimum_protocol_version == "TLSv1.2_2021" && aws_cloudfront_distribution.this.viewer_certificate[0].ssl_support_method == "sni-only"
    error_message = "TLS 1.2 or later, with the ACM certificate."
  }
  assert {
    condition     = aws_cloudfront_distribution.this.web_acl_id == var.web_acl_arn
    error_message = "WAF must be attached."
  }
  assert {
    condition     = aws_cloudfront_distribution.this.default_cache_behavior[0].viewer_protocol_policy == "redirect-to-https" && one([for b in aws_cloudfront_distribution.this.ordered_cache_behavior : b.viewer_protocol_policy if b.path_pattern == "/api/*"]) == "https-only"
    error_message = "Plain HTTP is redirected for pages and refused for the API."
  }
}

run "the_api_is_reached_only_through_the_vpc_origin" {
  command = apply

  assert {
    condition     = one([for o in aws_cloudfront_distribution.this.origin : length(o.vpc_origin_config) if o.origin_id == "api"]) == 1
    error_message = "The API origin must be a VPC origin, never a public one."
  }
  assert {
    condition     = aws_cloudfront_vpc_origin.alb.vpc_origin_endpoint_config[0].origin_protocol_policy == "https-only"
    error_message = "CloudFront to the ALB is HTTPS only."
  }
  assert {
    condition     = one([for b in aws_cloudfront_distribution.this.ordered_cache_behavior : b.cache_policy_id if b.path_pattern == "/api/*"]) == data.aws_cloudfront_cache_policy.disabled.id
    error_message = "API responses are never cached at the edge."
  }
}

run "the_spa_bucket_is_private" {
  command = apply

  assert {
    condition     = aws_s3_bucket_public_access_block.spa.block_public_policy && aws_s3_bucket_public_access_block.spa.restrict_public_buckets
    error_message = "The SPA bucket must block public access."
  }
  assert {
    condition     = one([for o in aws_cloudfront_distribution.this.origin : o.origin_access_control_id if o.origin_id == "spa"]) == aws_cloudfront_origin_access_control.spa.id && aws_cloudfront_origin_access_control.spa.signing_behavior == "always"
    error_message = "CloudFront reaches the bucket only with signed requests (OAC)."
  }
  assert {
    condition     = one([for st in data.aws_iam_policy_document.spa.statement : one(st.condition).variable if st.sid == "OnlyThisDistributionReads"]) == "AWS:SourceArn"
    error_message = "Only this distribution may read the bucket."
  }
}

run "spa_headers_match_the_local_edge" {
  command = apply

  assert {
    condition     = one(one(aws_cloudfront_response_headers_policy.spa.security_headers_config).content_security_policy).content_security_policy == local.spa_headers["Content-Security-Policy"]
    error_message = "CSP must be exactly the nginx one."
  }
  assert {
    condition     = one(one(aws_cloudfront_response_headers_policy.spa.security_headers_config).strict_transport_security).access_control_max_age_sec == 63072000
    error_message = "HSTS for two years, as locally."
  }
  assert {
    condition     = toset([for i in one(aws_cloudfront_response_headers_policy.spa.custom_headers_config).items : "${i.header}: ${i.value}"]) == toset([for h in local.custom_headers : "${h}: ${local.spa_headers[h]}"])
    error_message = "Permissions-Policy and the cross-origin isolation headers must match nginx."
  }
  assert {
    condition     = one(one(aws_cloudfront_response_headers_policy.api.security_headers_config).strict_transport_security).override == false
    error_message = "The edge must not override the API's own headers."
  }
}

run "the_name_points_at_the_distribution" {
  command = apply

  assert {
    condition     = length(aws_route53_record.alias) == 2 && aws_route53_record.alias["A"].alias[0].name == "d111111abcdef8.cloudfront.net"
    error_message = "A and AAAA alias records at the zone apex."
  }
}
