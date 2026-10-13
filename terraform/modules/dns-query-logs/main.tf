# Route 53 query logging for the platform's public zone (Phase 5, completing C-DNS-01).
#
# Every DNS query Route 53 answers for the zone is logged: the name, type, response code and the
# resolver's edge location. Route 53 writes query logs only to CloudWatch Logs in us-east-1, so
# this module runs with the us-east-1 provider. The zone exists between deploy windows, so the
# logs do too; at this zone's volume they cost cents.

locals {
  log_group_name = "/aws/route53/${var.zone_name}"
  zone_arn       = "arn:aws:route53:::hostedzone/${var.zone_id}"
}

resource "aws_cloudwatch_log_group" "this" {
  # checkov:skip=CKV_AWS_158: Encrypted with CloudWatch's own key; a customer key in us-east-1 would be a second KMS key ($1 a month) for public DNS query names, which are not secret.
  name              = local.log_group_name
  retention_in_days = var.retention_days
}

# Route 53 writes as the service principal, so the log group needs a resource policy. It admits
# only this account's zone (aws:SourceArn, aws:SourceAccount), not any zone anywhere.
locals {
  route53_writes = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "Route53QueryLogs"
      Effect    = "Allow"
      Principal = { Service = "route53.amazonaws.com" }
      Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource  = "${aws_cloudwatch_log_group.this.arn}:*"
      Condition = {
        ArnLike      = { "aws:SourceArn" = local.zone_arn }
        StringEquals = { "aws:SourceAccount" = var.account_id }
      }
    }]
  })
}

resource "aws_cloudwatch_log_resource_policy" "route53" {
  policy_name     = "route53-query-logs-${replace(var.zone_name, ".", "-")}"
  policy_document = local.route53_writes
}

resource "aws_route53_query_log" "this" {
  zone_id                  = var.zone_id
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.this.arn

  depends_on = [aws_cloudwatch_log_resource_policy.route53]
}
