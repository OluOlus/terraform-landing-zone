# S3 Storage Module

This module creates secure, compliant S3 buckets with encryption, versioning, and access controls for the landing zone.

## Features

- Server-side encryption with KMS
- Versioning and lifecycle policies
- Public access blocking
- Access logging and monitoring
- Cross-region replication support
- Compliance with UK data protection standards

## Security Controls

- All buckets encrypted by default
- Public access blocked by default
- Bucket policies enforce secure access
- Access logging enabled
- MFA delete protection available
- SSL/TLS required for all requests

## Usage

```hcl
module "s3_bucket" {
  source = "./modules/storage/s3"

  bucket_name = "landing-zone-data-bucket"
  environment = "production"
  
  # Encryption
  kms_key_id = module.kms.key_id
  
  # Versioning and lifecycle
  enable_versioning = true
  lifecycle_rules = [
    {
      id     = "archive_old_versions"
      status = "Enabled"
      transitions = [
        {
          days          = 30
          storage_class = "STANDARD_IA"
        },
        {
          days          = 90
          storage_class = "GLACIER"
        }
      ]
    }
  ]
  
  # Access controls
  allowed_principals = [
    "arn:aws:iam::123456789012:role/DataProcessingRole"
  ]
  
  common_tags = var.common_tags
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| bucket_name | Name for the S3 bucket | `string` | n/a | yes |
| environment | Environment name | `string` | n/a | yes |
| kms_key_id | KMS key ID for encryption | `string` | n/a | yes |
| enable_versioning | Enable bucket versioning | `bool` | `true` | no |
| lifecycle_rules | List of lifecycle rules | `list(object)` | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| bucket_id | The S3 bucket ID |
| bucket_arn | The S3 bucket ARN |
| bucket_domain_name | The S3 bucket domain name |
| bucket_regional_domain_name | The S3 bucket regional domain name |

## Compliance

This module implements storage security controls for:
- UK GDPR (data encryption and retention)
- Security Standards (secure storage practices)
- AWS Security Best Practices
- Data residency requirements