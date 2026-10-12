terraform {
  # Partial configuration: bucket, region and kms_key_id come from backend.hcl, which
  # scripts/tf.sh writes from the bootstrap stack's outputs (git-ignored). Each stack has its own
  # key, so no two stacks can share or overwrite state (ADR-0014).
  backend "s3" {
    key          = "account/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
