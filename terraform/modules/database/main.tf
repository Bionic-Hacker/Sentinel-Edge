# PostgreSQL on RDS in the isolated data subnets (ADR-0001, ADR-0015, ADR-0026).
#
# - No route out of the data subnets and a security group that admits only the API tasks.
# - Encrypted at rest with the platform key; TLS required on every connection (rds.force_ssl),
#   and the application verifies the server certificate (sslmode verify-full).
# - The master password is created and held by RDS in Secrets Manager, under the platform key:
#   it never appears in Terraform's plan or state. The master is used once per window, by the
#   role-bootstrap task; the API and migrations use their own roles.

resource "aws_db_subnet_group" "this" {
  name        = var.name
  description = "Isolated data subnets: no route out of the VPC"
  subnet_ids  = var.data_subnet_ids
}

resource "aws_db_parameter_group" "this" {
  name        = "${var.name}-pg${var.engine_major_version}"
  family      = "postgres${var.engine_major_version}"
  description = "SentinelEdge: TLS required, connections logged"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "ssl_min_protocol_version"
    value = "TLSv1.2"
  }
  parameter {
    name  = "log_connections"
    value = "1"
  }
  parameter {
    name  = "log_disconnections"
    value = "1"
  }
  # Statements slower than a second are logged with their duration, not their parameters.
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# RDS creates this group itself when logs are exported, without encryption or retention.
# Creating it first sets both.
resource "aws_cloudwatch_log_group" "postgresql" {
  name              = "/aws/rds/instance/${var.name}/postgresql"
  retention_in_days = 365
  kms_key_id        = var.kms_key_arn
}

resource "aws_db_instance" "this" {
  # checkov:skip=CKV_AWS_157: Single-AZ by decision for a dev environment rebuilt each window (ADR-0026); multi_az is a variable.
  # checkov:skip=CKV_AWS_118: Enhanced monitoring is billed through CloudWatch; Database Insights (free tier) and the exported logs cover a demo.
  # checkov:skip=CKV_AWS_293: Deletion protection is a variable, off in dev: the database is synthetic and rebuilt each window (ADR-0026).
  # checkov:skip=CKV2_AWS_60: Snapshots are not kept for a synthetic dev database (ADR-0026); copy_tags_to_snapshot is set for when they are.
  identifier     = var.name
  engine         = "postgres"
  engine_version = var.engine_major_version
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage_gb
  max_allocated_storage = var.allocated_storage_gb * 2
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.kms_key_arn

  db_name                       = var.db_name
  username                      = var.master_username
  manage_master_user_password   = true
  master_user_secret_kms_key_id = var.kms_key_arn

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [var.security_group_id]
  publicly_accessible    = false
  multi_az               = var.multi_az
  parameter_group_name   = aws_db_parameter_group.this.name
  ca_cert_identifier     = "rds-ca-rsa2048-g1"

  iam_database_authentication_enabled = true
  auto_minor_version_upgrade          = true
  allow_major_version_upgrade         = false
  apply_immediately                   = true

  backup_retention_period   = var.backup_retention_days
  copy_tags_to_snapshot     = true
  deletion_protection       = var.deletion_protection
  skip_final_snapshot       = !var.final_snapshot
  final_snapshot_identifier = var.final_snapshot ? "${var.name}-final" : null

  performance_insights_enabled          = true
  performance_insights_kms_key_id       = var.kms_key_arn
  performance_insights_retention_period = 7

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  depends_on = [aws_cloudwatch_log_group.postgresql]
}
