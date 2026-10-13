# terraform test, with a mocked AWS provider: no credentials, no AWS calls, no cost.
# Run by scripts/tf-check.sh (make tf-check, and CI).

mock_provider "aws" {
  mock_resource "aws_db_instance" {
    defaults = {
      arn                = "arn:aws:rds:us-east-2:123456789012:db:sentineledge-dev"
      master_user_secret = [{ secret_arn = "arn:aws:secretsmanager:us-east-2:123456789012:secret:rds!db-0000-AbCdEf", kms_key_id = "k", secret_status = "active" }]
    }
  }
}

variables {
  name              = "sentineledge-dev"
  data_subnet_ids   = ["subnet-0aaaaaaaaaaaaaaaa", "subnet-0bbbbbbbbbbbbbbbb"]
  security_group_id = "sg-0cccccccccccccccc"
  kms_key_arn       = "arn:aws:kms:us-east-2:123456789012:key/00000000-0000-0000-0000-000000000000"
}

run "private_encrypted_and_tls_only" {
  command = plan

  assert {
    condition     = aws_db_instance.this.publicly_accessible == false
    error_message = "The database must never be publicly accessible."
  }
  assert {
    condition     = aws_db_instance.this.storage_encrypted && aws_db_instance.this.kms_key_id == var.kms_key_arn
    error_message = "Storage must be encrypted under the platform key."
  }
  assert {
    condition     = one([for p in aws_db_parameter_group.this.parameter : p.value if p.name == "rds.force_ssl"]) == "1"
    error_message = "Every connection must use TLS (rds.force_ssl = 1)."
  }
  assert {
    condition     = one([for p in aws_db_parameter_group.this.parameter : p.value if p.name == "ssl_min_protocol_version"]) == "TLSv1.2"
    error_message = "TLS 1.2 is the minimum."
  }
  assert {
    condition     = alltrue([for p in aws_db_parameter_group.this.parameter : p.apply_method == "pending-reboot" if contains(["rds.force_ssl", "ssl_min_protocol_version"], p.name)])
    error_message = "Static parameters are declared pending-reboot, as RDS reports them."
  }
  assert {
    condition     = aws_db_instance.this.vpc_security_group_ids == toset([var.security_group_id])
    error_message = "Only the database security group may be attached."
  }
}

run "the_master_password_is_held_by_rds" {
  command = plan

  assert {
    condition     = aws_db_instance.this.manage_master_user_password == true && aws_db_instance.this.password == null
    error_message = "RDS must generate and hold the master password; Terraform must never see it."
  }
  assert {
    condition     = aws_db_instance.this.master_user_secret_kms_key_id == var.kms_key_arn
    error_message = "The master secret must be encrypted under the platform key."
  }
}

run "logs_are_encrypted_and_kept" {
  command = plan

  assert {
    condition     = aws_cloudwatch_log_group.postgresql.kms_key_id == var.kms_key_arn && aws_cloudwatch_log_group.postgresql.retention_in_days == 365
    error_message = "Database logs must be encrypted and kept a year."
  }
  assert {
    condition     = contains(aws_db_instance.this.enabled_cloudwatch_logs_exports, "postgresql")
    error_message = "PostgreSQL logs must be exported."
  }
}

run "dev_defaults_are_the_cheapest" {
  command = plan

  assert {
    condition     = aws_db_instance.this.instance_class == "db.t4g.micro" && aws_db_instance.this.multi_az == false
    error_message = "Dev runs one db.t4g.micro."
  }
  assert {
    condition     = aws_db_instance.this.skip_final_snapshot == true
    error_message = "Dev keeps no final snapshot unless asked (synthetic data)."
  }
}

run "an_application_role_cannot_be_the_master" {
  command = plan

  variables {
    master_username = "sentinel_app"
  }

  expect_failures = [var.master_username]
}
