terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.66"
      # aws: us-east-1 (CloudFront, its function and policies, the alias records);
      # aws.home: the account's home Region, for the SPA bucket (S3 in us-east-1 is denied here).
      configuration_aliases = [aws.home]
    }
  }
}
