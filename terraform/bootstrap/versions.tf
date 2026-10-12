terraform {
  # 1.10 is the first release with S3-native state locking (use_lockfile), used by every other
  # stack. This stack keeps its own state locally: it creates the bucket the others use.
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.66"
    }
  }
}
