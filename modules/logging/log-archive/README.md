# Log Archive Module

Centralised S3-based log storage for the Log Archive Account with 7-year retention, cross-region replication, and UK GDPR-compliant lifecycle policies.

## Features

- Primary bucket in eu-west-2 (London), replica in eu-west-1 (Ireland)
- KMS encryption with customer-managed keys
- Object versioning and MFA delete protection
- S3 Object Lock for immutable retention (7 years / 2,555 days)
- Intelligent-Tiering lifecycle for cost optimisation
- Cross-region replication for disaster recovery
- Public access fully blocked

## Usage

```hcl
module "log_archive" {
  source = "../../modules/logging/log-archive"

  providers = {
    aws         = aws
    aws.replica = aws.replica
  }

  primary_bucket_name = "uk-landing-zone-logs-primary-<ACCOUNT_ID>"
  replica_bucket_name = "uk-landing-zone-logs-replica-<ACCOUNT_ID>"
  kms_key_arn         = module.kms_logs.key_arn
  replica_kms_key_arn = module.kms_logs_replica.key_arn
  common_tags         = local.common_tags
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.9.0 |
| aws | ~> 5.0 |

Two provider configurations are required: default (`aws`) for eu-west-2 and `aws.replica` for eu-west-1.

## Compliance

- UK GDPR Article 5(1)(e): Storage limitation
- UK GDPR Article 32: Security of processing
- NCSC Principle 6: Operational security (7-year retention)
