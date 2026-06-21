# KMS Encryption Module

This module creates and manages AWS KMS keys for encryption across the landing zone infrastructure.

## Features

- Multi-region KMS key support
- Service-specific key policies (CloudTrail, CloudWatch, S3, Config, SNS)
- Key rotation and monitoring
- Compliance with UK security standards
- CloudWatch alarms for key monitoring
- Support for KMS grants and replica keys

## Usage

```hcl
module "kms" {
  source = "./modules/security/kms"

  key_name        = "landing-zone-main"
  key_description = "Main encryption key for landing zone"
  key_alias       = "landing-zone/main"
  
  # Enable service access
  allow_cloudtrail_access       = true
  allow_cloudwatch_logs_access  = true
  allow_s3_access              = true
  
  # Monitoring
  enable_key_monitoring = true
  alarm_sns_topic_arns = [aws_sns_topic.alerts.arn]
  
  common_tags = var.common_tags
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| key_name | Name for the KMS key | `string` | n/a | yes |
| key_description | Description for the KMS key | `string` | n/a | yes |
| key_alias | Alias for the KMS key | `string` | n/a | yes |
| enable_key_rotation | Enable automatic key rotation | `bool` | `true` | no |
| deletion_window_in_days | Key deletion window | `number` | `30` | no |

## Outputs

| Name | Description |
|------|-------------|
| key_id | The KMS key ID |
| key_arn | The KMS key ARN |
| key_alias | The KMS key alias |

## Compliance

This module implements encryption standards required for:
- UK GDPR compliance
- Security Standards Cloud Security Principles
- AWS Security Best Practices