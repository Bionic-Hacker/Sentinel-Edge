# terraform test, with a mocked AWS provider: no credentials, no AWS calls, no cost.
# Run by scripts/tf-check.sh (make tf-check, and CI).

mock_provider "aws" {
  mock_resource "aws_acm_certificate" {
    defaults = {
      arn = "arn:aws:acm:us-east-2:123456789012:certificate/00000000-0000-0000-0000-000000000000"
      domain_validation_options = [{
        domain_name           = "sentineledge.example.com"
        resource_record_name  = "_abc.sentineledge.example.com."
        resource_record_type  = "CNAME"
        resource_record_value = "_def.acm-validations.aws."
      }]
    }
  }
}

variables {
  domain_name = "sentineledge.example.com"
}

run "defaults_request_only_the_certificate" {
  command = apply

  assert {
    condition     = aws_acm_certificate.this.validation_method == "DNS"
    error_message = "Certificates are validated by DNS, never by email."
  }
  assert {
    condition     = aws_acm_certificate.this.options[0].certificate_transparency_logging_preference == "ENABLED"
    error_message = "Certificate Transparency logging must stay on."
  }
  assert {
    condition     = length(aws_route53_record.validation) == 0 && length(aws_acm_certificate_validation.this) == 0
    error_message = "Without a zone, nothing is published and nothing waits."
  }
  assert {
    condition     = output.issued_certificate_arn == null
    error_message = "issued_certificate_arn must stay null until issuance is waited for."
  }
}

run "the_publishing_certificate_writes_one_validation_record" {
  command = apply

  variables {
    zone_id                   = "Z0123456789ABCDEFGHIJ"
    publish_validation_record = true
  }

  assert {
    condition     = length(aws_route53_record.validation) == 1
    error_message = "One name needs exactly one validation record."
  }
  assert {
    condition     = aws_route53_record.validation["sentineledge.example.com"].name == "_abc.sentineledge.example.com." && aws_route53_record.validation["sentineledge.example.com"].type == "CNAME"
    error_message = "The record must be the CNAME ACM asked for."
  }
  assert {
    condition     = aws_route53_record.validation["sentineledge.example.com"].allow_overwrite == false
    error_message = "The validation record must never silently replace an existing one."
  }
}

run "waiting_yields_the_issued_arn" {
  command = apply

  variables {
    zone_id                   = "Z0123456789ABCDEFGHIJ"
    publish_validation_record = true
    wait_for_issued           = true
  }

  assert {
    condition     = length(aws_acm_certificate_validation.this) == 1
    error_message = "wait_for_issued must wait for the certificate."
  }
  assert {
    condition     = output.issued_certificate_arn == aws_acm_certificate.this.arn
    error_message = "issued_certificate_arn must be the certificate's ARN once waited for."
  }
}

run "publishing_without_a_zone_is_refused" {
  command = plan

  variables {
    publish_validation_record = true
  }

  expect_failures = [var.publish_validation_record]
}
