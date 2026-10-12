# Generates the application's secret values during apply and writes them straight to Secrets
# Manager (ADR-0026). Each value comes from an ephemeral resource and goes into a write-only
# argument, so it never appears in a plan, in state or in a log: Terraform cannot read it back
# and neither can anyone holding the state file.
#
# Values are regenerated on every run, but a write-only argument is sent to AWS only when its
# version changes, so the stored secrets change only when `generation` is increased.
#
# Secrets Manager's generator draws from A-Z, a-z and 0-9 here (no punctuation), so the values
# are safe in connection strings and environment variables.
#
# Not covered by `terraform test`: mocked providers cannot yet stand in for ephemeral resources.
# `terraform validate`, Checkov and the apply itself check it; the app refuses to start with a
# malformed key (backend/app/core/config.py).

ephemeral "aws_secretsmanager_random_password" "db_app_password" {
  password_length     = 40
  exclude_punctuation = true
}

ephemeral "aws_secretsmanager_random_password" "db_migrator_password" {
  password_length     = 40
  exclude_punctuation = true
}

ephemeral "aws_secretsmanager_random_password" "jwt_signing_key" {
  password_length     = 64
  exclude_punctuation = true
}

# A Fernet key is 32 random bytes in URL-safe base64: 43 characters and one "=" of padding.
# 43 characters from this generator's alphabet (a subset of base64's) carry 256 bits of
# entropy, and the decoder discards the last character's two spare bits.
ephemeral "aws_secretsmanager_random_password" "mfa_encryption_key" {
  password_length     = 43
  exclude_punctuation = true
}

resource "aws_secretsmanager_secret_version" "db_app_password" {
  secret_id                = var.secret_arns["db_app_password"]
  secret_string_wo         = ephemeral.aws_secretsmanager_random_password.db_app_password.random_password
  secret_string_wo_version = var.generation
}

resource "aws_secretsmanager_secret_version" "db_migrator_password" {
  secret_id                = var.secret_arns["db_migrator_password"]
  secret_string_wo         = ephemeral.aws_secretsmanager_random_password.db_migrator_password.random_password
  secret_string_wo_version = var.generation
}

resource "aws_secretsmanager_secret_version" "jwt_signing_key" {
  secret_id                = var.secret_arns["jwt_signing_key"]
  secret_string_wo         = ephemeral.aws_secretsmanager_random_password.jwt_signing_key.random_password
  secret_string_wo_version = var.generation
}

resource "aws_secretsmanager_secret_version" "mfa_encryption_key" {
  secret_id                = var.secret_arns["mfa_encryption_key"]
  secret_string_wo         = "${ephemeral.aws_secretsmanager_random_password.mfa_encryption_key.random_password}="
  secret_string_wo_version = var.generation
}
