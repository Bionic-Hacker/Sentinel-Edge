# Terraform (Phase 3)

No Terraform code exists in Phase 1, and no AWS resources have been created.

Planned layout and conventions are recorded in ADR-0014 and the Phase 1 plan:

```
terraform/
├── bootstrap/        # state bucket (SSE-KMS, versioned, TLS-only), GitHub OIDC provider
├── modules/          # vpc, security-groups, alb, cloudfront, waf, ecs, ecr, rds, iam, acm,
│                     # route53, cloudwatch, cloudtrail, secrets-manager, s3
└── environments/
    ├── dev/          # own backend.tf, providers.tf (allowed_account_ids), tfvars
    ├── staging/
    └── production/
```

Rules that apply from the first commit: no credentials, secrets, or `*.tfvars` with real values in
git (`.gitignore` and Gitleaks enforce this); state is remote and encrypted; Checkov must pass.
