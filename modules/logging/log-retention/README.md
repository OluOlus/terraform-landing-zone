# Log Retention Module

Manages lifecycle policies for centralised log storage, enforcing 7-year retention with automated tiering to Glacier for cost optimisation.

## Features

- 7-year (2,555-day) retention for compliance
- Automated tiering: Standard → Standard-IA (30d) → Glacier IR (90d) → Glacier (365d) → Deep Archive (2555d)
- CloudWatch log group retention configuration
- Lambda-based log cleanup for expired data
- Compliance audit reporting

## Usage

```hcl
module "log_retention" {
  source = "../../modules/logging/log-retention"

  log_archive_bucket_name = module.log_archive.primary_bucket_name
  retention_years         = 7
  common_tags             = local.common_tags
}
```

## Compliance

- UK GDPR Article 17: Right to erasure (controlled deletion)
- NCSC Principle 6: Operational security
- Cyber Essentials: Secure configuration
