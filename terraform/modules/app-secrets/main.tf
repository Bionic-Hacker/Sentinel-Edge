# The application's secrets in Secrets Manager, under the platform key (ADR-0026). This module
# creates the four secrets; module app-secret-values generates their values and writes them.
# The split exists because `terraform test` cannot mock ephemeral resources, and this half is
# the part worth testing.

locals {
  secrets = {
    db_app_password      = "Password of sentinel_app, the API's runtime role (ADR-0015)"
    db_migrator_password = "Password of sentinel_migrator, the schema owner used only by migrations"
    jwt_signing_key      = "HS256 signing key for access tokens"
    mfa_encryption_key   = "Fernet key that encrypts TOTP secrets at rest"
  }
}

resource "aws_secretsmanager_secret" "this" {
  # checkov:skip=CKV2_AWS_57: Rotation is by `generation` in module app-secret-values (a new apply), done in a deploy window with a rolling restart; the RDS master secret is rotated by RDS.
  for_each = local.secrets

  name                    = "${var.name}/${replace(each.key, "_", "-")}"
  description             = each.value
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.recovery_window_in_days
}

