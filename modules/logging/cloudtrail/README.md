# CloudTrail Module

Deploys AWS CloudTrail for comprehensive API audit logging across all UK regions with 7-year retention.

## Features

- Multi-region trail covering eu-west-2 and eu-west-1
- S3 log delivery with KMS encryption
- Log file validation enabled (tamper detection)
- Management and data event logging
- CloudWatch Logs integration for real-time monitoring
- SNS alerts for critical API events

## Usage

```hcl
module "cloudtrail" {
  source = "../../modules/logging/cloudtrail"

  trail_name         = "uk-landing-zone-cloudtrail"
  s3_bucket_name     = module.log_archive.cloudtrail_bucket_name
  kms_key_arn        = module.kms.cloudtrail_key_arn
  cloudwatch_log_group_arn = module.cloudwatch.log_group_arn
  common_tags        = local.common_tags
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.9.0 |
| aws | ~> 5.0 |

## Compliance

- NCSC Principle 6: Operational security
- UK GDPR Article 30: Records of processing activities
- Cyber Essentials: Audit logging
