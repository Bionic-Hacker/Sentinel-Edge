# terraform test, with a mocked AWS provider: no credentials, no AWS calls, no cost.
# Run by scripts/tf-check.sh (make tf-check, and CI).

mock_provider "aws" {
  mock_resource "aws_secretsmanager_secret" {
    defaults = { arn = "arn:aws:secretsmanager:us-east-2:123456789012:secret:sentineledge-dev/x-AbCdEf" }
  }
}

variables {
  name        = "sentineledge-dev"
  kms_key_arn = "arn:aws:kms:us-east-2:123456789012:key/00000000-0000-0000-0000-000000000000"
}

run "four_secrets_under_the_platform_key" {
  command = plan

  assert {
    condition     = length(aws_secretsmanager_secret.this) == 4
    error_message = "The app needs exactly four secrets."
  }
  assert {
    condition     = alltrue([for s in aws_secretsmanager_secret.this : s.kms_key_id == var.kms_key_arn])
    error_message = "Every secret must be encrypted under the platform key, not the AWS-managed key."
  }
  assert {
    condition     = toset([for s in aws_secretsmanager_secret.this : s.name]) == toset(["sentineledge-dev/db-app-password", "sentineledge-dev/db-migrator-password", "sentineledge-dev/jwt-signing-key", "sentineledge-dev/mfa-encryption-key"])
    error_message = "Secret names must follow name/key."
  }
}

run "the_admin_password_has_its_own_secret" {
  command = plan

  assert {
    condition     = aws_secretsmanager_secret.admin_otp.name == "sentineledge-dev/admin-one-time-password" && aws_secretsmanager_secret.admin_otp.kms_key_id == var.kms_key_arn
    error_message = "The one-time password is kept apart from the four application secrets, under the platform key."
  }
}

run "deleted_secrets_can_be_recreated_next_window" {
  command = plan

  assert {
    condition     = alltrue([for s in aws_secretsmanager_secret.this : s.recovery_window_in_days == 0])
    error_message = "Dev deletes secrets at once, so the next window can recreate the same names."
  }
}

run "a_short_recovery_window_is_refused" {
  command = plan

  variables {
    recovery_window_in_days = 3
  }

  expect_failures = [var.recovery_window_in_days]
}
