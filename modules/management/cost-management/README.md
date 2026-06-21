# Cost Management Module

AWS Budgets, Cost Anomaly Detection, and Cost and Usage Reports for financial governance across all accounts.

## Features

- Per-account monthly budgets with SNS alerting at 80% and 100% thresholds
- OU-level budget rollups
- AWS Cost Anomaly Detection with ML-driven alerting
- Cost and Usage Reports delivered to S3 in eu-west-2
- Chargeback tagging by CostCenter, Environment, and Project
- Untagged resource detection and automated remediation trigger

## Usage

```hcl
module "cost_management" {
  source = "../../modules/management/cost-management"

  aws_region           = "eu-west-2"
  monthly_budget_usd   = 10000
  alert_email          = "finops@example.com"
  cur_s3_region        = "eu-west-2"
  common_tags          = local.common_tags
}
```

## Compliance

- Requirement 11: Cost Management and Tagging
- UK GDPR: Data minimisation (automated lifecycle)
