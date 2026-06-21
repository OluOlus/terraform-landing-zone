# Backup Module

AWS Backup centralised vault management with cross-region replication to eu-west-1, supporting RTO of 4 hours and RPO of 1 hour.

## Features

- Primary vault in eu-west-2 with KMS encryption
- Cross-region vault in eu-west-1 for disaster recovery
- Backup plans: daily (35-day retention), weekly (90-day), monthly (365-day)
- Automated backup testing via AWS Backup Audit Manager
- SNS alerts for backup job failures
- Vault lock for immutable backups (compliance mode)

## Usage

```hcl
module "backup" {
  source = "../../modules/management/backup"

  providers = {
    aws         = aws
    aws.replica = aws.replica
  }

  vault_name               = "uk-landing-zone-backup"
  kms_key_arn              = module.kms.backup_key_arn
  secondary_vault_region   = "eu-west-1"
  secondary_vault_kms_key_arn = module.kms_replica.backup_key_arn
  common_tags              = local.common_tags
}
```

## Compliance

- NCSC Principle 3: Asset protection and resilience
- Disaster Recovery: RTO 4h / RPO 1h
