# terraform test, with a mocked AWS provider: no credentials, no AWS calls, no cost.
# Run by scripts/tf-check.sh (make tf-check, and CI).

mock_provider "aws" {}

variables {
  zone_name = "sentineledge.example.com"
}

run "caa_allows_only_amazon_and_no_wildcards" {
  command = plan

  assert {
    condition     = aws_route53_zone.this.name == "sentineledge.example.com"
    error_message = "The zone must be the delegated name itself."
  }
  assert {
    condition     = aws_route53_zone.this.force_destroy == false
    error_message = "The zone must never be deleted with its records."
  }
  assert {
    condition     = aws_route53_record.caa.name == "sentineledge.example.com" && aws_route53_record.caa.type == "CAA"
    error_message = "CAA belongs at the zone apex, so it covers every name below it."
  }
  assert {
    condition     = toset(aws_route53_record.caa.records) == toset(["0 issue \"amazon.com\"", "0 issuewild \";\""])
    error_message = "CAA must allow only Amazon and forbid wildcard certificates."
  }
}

run "iodef_is_added_only_when_set" {
  command = plan

  variables {
    caa_iodef = "mailto:security@example.com"
  }

  assert {
    condition     = contains(aws_route53_record.caa.records, "0 iodef \"mailto:security@example.com\"")
    error_message = "A configured iodef address must be published."
  }
  assert {
    condition     = contains(aws_route53_record.caa.records, "0 issuewild \";\"")
    error_message = "Adding iodef must not drop the wildcard ban."
  }
}

run "a_bare_domain_is_refused" {
  command = plan

  variables {
    zone_name = "example.com"
  }

  expect_failures = [var.zone_name]
}

run "an_iodef_that_is_not_a_url_is_refused" {
  command = plan

  variables {
    caa_iodef = "security@example.com"
  }

  expect_failures = [var.caa_iodef]
}
