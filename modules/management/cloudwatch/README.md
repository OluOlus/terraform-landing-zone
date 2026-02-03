# CloudWatch Monitoring Module

This module sets up comprehensive CloudWatch monitoring, logging, and alerting for the landing zone infrastructure.

## Features

- Centralized log groups with retention policies
- Custom metrics and dashboards
- Automated alerting with SNS integration
- Cost optimization through log retention
- Security monitoring and compliance logging
- Performance monitoring dashboards

## Components

### Log Groups
- Application logs with configurable retention
- Security audit logs
- Performance monitoring logs
- Cost optimization logs

### Dashboards
- Infrastructure overview dashboard
- Security monitoring dashboard
- Cost analysis dashboard
- Performance metrics dashboard

### Alarms
- High CPU utilization alerts
- Memory usage alerts
- Disk space alerts
- Security event alerts
- Cost threshold alerts

## Usage

```hcl
module "cloudwatch" {
  source = "./modules/management/cloudwatch"

  environment = "production"
  
  # Log retention settings
  default_log_retention_days = 30
  security_log_retention_days = 365
  
  # Alerting
  sns_topic_arn = aws_sns_topic.alerts.arn
  
  # Cost monitoring
  cost_alert_threshold = 1000
  
  common_tags = var.common_tags
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| environment | Environment name | `string` | n/a | yes |
| default_log_retention_days | Default log retention in days | `number` | `30` | no |
| security_log_retention_days | Security log retention in days | `number` | `365` | no |
| sns_topic_arn | SNS topic ARN for alerts | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| log_group_names | List of created log group names |
| dashboard_urls | URLs of created dashboards |
| alarm_names | List of created alarm names |

## Compliance

This module supports compliance requirements for:
- UK GDPR (log retention and monitoring)
- Security Standards (security event monitoring)
- AWS Well-Architected Framework (operational excellence)