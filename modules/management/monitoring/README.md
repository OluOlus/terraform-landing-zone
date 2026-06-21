# Monitoring Module

CloudWatch dashboards and alarms for UK Compliance, Security Posture, and Cost & Usage visibility.

## Features

- UK Compliance Dashboard: NCSC controls status, UK GDPR compliance indicators
- Security Posture Dashboard: Security Hub findings, GuardDuty alerts, Config compliance
- Cost & Usage Dashboard: Billing trends by account, OU, and tag dimensions
- CloudWatch alarms: root account usage, unauthorised API calls, Security Hub critical findings
- SNS topic for alarm routing to ops team

## Usage

```hcl
module "monitoring" {
  source = "../../modules/management/monitoring"

  environment        = "management"
  aws_region         = "eu-west-2"
  notification_email = "ops@example.com"
  tags               = local.common_tags
}
```

## Compliance

- Requirement 7.6: UK Compliance, Security Posture, and Cost dashboards
- NCSC Principle 6: Operational security
