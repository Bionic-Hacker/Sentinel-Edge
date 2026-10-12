terraform {
  # Partial configuration: bucket, region and kms_key_id come from backend.hcl, which
  # scripts/tf.sh writes (git-ignored). This environment's own key (ADR-0014).
  backend "s3" {
    key          = "dev/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
