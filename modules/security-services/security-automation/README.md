# Security Automation Module

This module provides automated security remediation capabilities for the AWS Secure Landing Zone. It integrates with Security Hub, GuardDuty, and AWS Config to automatically respond to security violations and compliance issues.

## Features

- **Automated Remediation**: Automatically fixes common security violations
- **Multi-Source Integration**: Responds to findings from Security Hub, GuardDuty, and Config
- **UK Compliance Focus**: Specifically designed for regulatory requirements (Security Standards, GDPR)
- **Orchestrated Response**: Intelligent routing of security findings to appropriate remediation functions
- **Comprehensive Monitoring**: CloudWatch metrics, alarms, and SNS notifications
- **Audit Trail**: Complete logging and tracking of all remediation actions

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                Security Automation Architecture                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │ Security    │    │ GuardDuty   │    │ Config      │         │
│  │ Hub         │    │ Findings    │    │ Compliance  │         │
│  │ Findings    │    │             │    │ Changes     │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│         │                   │                   │              │
│         ▼                   ▼                   ▼              │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                EventBridge Rules                           │ │
│  └─────────────────────────────────────────────────────────────┘ │
│         │                   │                   │              │
│         ▼                   ▼                   ▼              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │ Security    │    │ GuardDuty   │    │ Config      │         │
│  │ Hub         │    │ Orchestrator│    │ Orchestrator│         │
│  │ Orchestrator│    │             │    │             │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│         │                   │                   │              │
│         └───────────────────┼───────────────────┘              │
│                             ▼                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              Remediation Functions                         │ │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐          │ │
│  │  │ S3 Public   │ │ Unencrypted │ │ Untagged    │          │ │
│  │  │ Access      │ │ Volumes     │ │ Resources   │          │ │
│  │  │ Remediation │ │ Remediation │ │ Remediation │          │ │
│  │  └─────────────┘ └─────────────┘ └─────────────┘          │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                             │                                  │
│                             ▼                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              Monitoring & Notifications                    │ │
│  │  • CloudWatch Metrics & Alarms                            │ │
│  │  • SNS Notifications                                      │ │
│  │  • S3 Audit Logs                                         │ │
│  │  • Security Hub Updates                                   │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Remediation Capabilities

### S3 Public Access Remediation
- **Triggers**: S3 buckets with public access violations
- **Actions**:
  - Blocks all public access using S3 Block Public Access
  - Removes public bucket policies
  - Removes public ACLs
  - Applies compliance tags
  - Verifies encryption is enabled
- **Compliance**: Security Standards Cloud Security Principles, GDPR

### Unencrypted Volumes Remediation
- **Triggers**: EBS volumes without encryption
- **Actions**:
  - Creates encrypted snapshots
  - Replaces unencrypted volumes with encrypted versions
  - Handles both attached and detached volumes
  - Applies compliance tags
  - Maintains instance availability during remediation
- **Compliance**: Security Standards Data Protection at Rest, GDPR

### Untagged Resources Remediation
- **Triggers**: Resources missing mandatory UK tags
- **Actions**:
  - Applies mandatory compliance tags
  - Validates data classification values
  - Ensures resource-classification compatibility
  - Supports multiple AWS services (EC2, S3, RDS, Lambda, IAM)
- **Compliance**: UK mandatory tagging requirements

## Usage

### Basic Usage

```hcl
module "security_automation" {
  source = "./modules/security-services/security-automation"

  # Basic configuration
  aws_region = "us-east-1"
  
  # Enable remediation functions
  enable_s3_public_access_remediation    = true
  enable_unencrypted_volumes_remediation = true
  enable_untagged_resources_remediation  = true
  
  # Notification configuration
  notification_email = "security-team@company.com"
  
  common_tags = {
    DataClassification = "confidential"
    Environment       = "production"
    CostCenter        = "security"
    Owner            = "security-team"
    Project          = "uk-landing-zone"
  }
}
```

### Advanced Configuration

```hcl
module "security_automation" {
  source = "./modules/security-services/security-automation"

  # Regional configuration
  aws_region = "us-east-1"
  
  # Remediation configuration
  enable_s3_public_access_remediation    = true
  enable_unencrypted_volumes_remediation = true
  enable_untagged_resources_remediation  = true
  
  # Severity thresholds
  remediation_severity_levels      = ["HIGH", "CRITICAL"]
  guardduty_remediation_severities = [7.0, 8.0, 8.5, 9.0, 10.0]
  
  # Lambda configuration
  lambda_timeout     = 300
  lambda_memory_size = 512
  
  # Compliance configuration
  ncsc_compliance_mode           = true
  uk_gdpr_compliance_mode        = true
  cyber_essentials_compliance_mode = true
  
  # region-specific tagging
  mandatory_uk_tags = [
    "DataClassification",
    "Environment", 
    "CostCenter",
    "Owner",
    "Project"
  ]
  
  uk_data_classification_tags = [
    "public",
    "internal",
    "confidential", 
    "restricted"
  ]
  
  # Operational configuration
  remediation_dry_run           = false
  enable_manual_approval        = true
  approval_timeout_minutes      = 60
  enable_compliance_reporting   = true
  compliance_report_frequency   = "weekly"
  
  # Cross-account configuration
  enable_cross_account_remediation = false
  trusted_remediation_accounts     = []
  
  # Storage configuration
  remediation_log_retention_days  = 2555  # 7 years
  cloudwatch_log_retention_days   = 365
  
  # Notification configuration
  notification_email = "security-team@company.com"
  
  common_tags = {
    DataClassification = "confidential"
    Environment       = "production"
    CostCenter        = "security"
    Owner            = "security-team"
    Project          = "uk-landing-zone"
  }
}
```

### Security Tooling Account Configuration

```hcl
module "security_automation" {
  source = "./modules/security-services/security-automation"

  # Security tooling account specific configuration
  aws_region = "us-east-1"
  
  # Enable all remediation capabilities
  enable_s3_public_access_remediation    = true
  enable_unencrypted_volumes_remediation = true
  enable_untagged_resources_remediation  = true
  
  # High sensitivity configuration
  remediation_severity_levels      = ["MEDIUM", "HIGH", "CRITICAL"]
  guardduty_remediation_severities = [4.0, 7.0, 8.0, 8.5, 9.0, 10.0]
  
  # Enhanced monitoring
  enable_compliance_reporting   = true
  compliance_report_frequency   = "daily"
  
  # Manual approval for high-impact actions
  enable_manual_approval    = true
  approval_timeout_minutes  = 30
  
  # Cross-account remediation for organization
  enable_cross_account_remediation = true
  trusted_remediation_accounts = [
    "123456789012",  # Production UK Account
    "123456789013",  # Non-Production UK Account
    "123456789014"   # Sandbox Account
  ]
  
  common_tags = {
    DataClassification = "restricted"
    Environment       = "security"
    CostCenter        = "security"
    Owner            = "security-team"
    Project          = "uk-landing-zone"
  }
}
```

## Variables

### Core Configuration

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| `aws_region` | AWS region for deployment | `string` | `"us-east-1"` | no |
| `remediation_bucket_prefix` | S3 bucket prefix for artifacts | `string` | `"uk-security-automation-artifacts"` | no |
| `notification_email` | Email for notifications | `string` | `null` | no |

### Remediation Configuration

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| `enable_s3_public_access_remediation` | Enable S3 public access remediation | `bool` | `true` | no |
| `enable_unencrypted_volumes_remediation` | Enable unencrypted volumes remediation | `bool` | `true` | no |
| `enable_untagged_resources_remediation` | Enable untagged resources remediation | `bool` | `true` | no |
| `remediation_severity_levels` | Security Hub severity levels for remediation | `list(string)` | `["HIGH", "CRITICAL"]` | no |
| `guardduty_remediation_severities` | GuardDuty severity levels for remediation | `list(number)` | `[7.0, 8.0, 8.5, 9.0, 10.0]` | no |

### Compliance Configuration

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| `ncsc_compliance_mode` | Enable Security Standards compliance mode | `bool` | `true` | no |
| `uk_gdpr_compliance_mode` | Enable GDPR compliance mode | `bool` | `true` | no |
| `cyber_essentials_compliance_mode` | Enable Security Essentials compliance mode | `bool` | `true` | no |
| `mandatory_uk_tags` | List of mandatory UK tags | `list(string)` | `["DataClassification", "Environment", "CostCenter", "Owner", "Project"]` | no |

### Operational Configuration

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| `remediation_dry_run` | Enable dry-run mode | `bool` | `false` | no |
| `enable_manual_approval` | Require manual approval for high-impact actions | `bool` | `true` | no |
| `approval_timeout_minutes` | Timeout for manual approval | `number` | `60` | no |
| `lambda_timeout` | Lambda function timeout | `number` | `300` | no |
| `lambda_memory_size` | Lambda function memory size | `number` | `512` | no |

## Outputs

### Core Outputs

| Name | Description |
|------|-------------|
| `security_automation_kms_key_arn` | KMS key ARN for encryption |
| `remediation_artifacts_bucket_name` | S3 bucket name for artifacts |
| `security_automation_sns_topic_arn` | SNS topic ARN for notifications |

### Function Outputs

| Name | Description |
|------|-------------|
| `s3_public_access_remediation_arn` | S3 remediation function ARN |
| `unencrypted_volumes_remediation_arn` | Volumes remediation function ARN |
| `untagged_resources_remediation_arn` | Tagging remediation function ARN |
| `security_hub_orchestrator_arn` | Security Hub orchestrator ARN |
| `guardduty_orchestrator_arn` | GuardDuty orchestrator ARN |
| `config_orchestrator_arn` | Config orchestrator ARN |

### Summary Outputs

| Name | Description |
|------|-------------|
| `remediation_functions_summary` | Summary of all remediation functions |
| `compliance_configuration` | Compliance configuration summary |
| `automation_configuration` | Automation configuration summary |

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0 |
| aws | ~> 5.0 |

## UK Compliance

This module is specifically designed for compliance requirements:

- **Data Residency**: All resources restricted to specified regions (us-west-2, us-east-1)
- **Security Standards Compliance**: Implements Security Standards Cloud Security Principles
- **GDPR**: Supports GDPR compliance requirements
- **Security Essentials**: Aligns with Security Essentials framework
- **Mandatory Tagging**: Enforces region-specific tagging requirements
- **Audit Trail**: Provides comprehensive audit logging for regulatory requirements

## Security Considerations

1. **Encryption**: All data encrypted at rest and in transit using KMS
2. **Access Control**: Least privilege IAM policies for all functions
3. **Audit Logging**: Complete audit trail of all remediation actions
4. **Manual Approval**: High-impact actions require manual approval
5. **Dry Run Mode**: Test remediation actions without making changes
6. **Cross-Account**: Secure cross-account remediation capabilities

## Monitoring and Alerting

The module provides comprehensive monitoring:

- **CloudWatch Metrics**: Custom metrics for remediation success/failure rates
- **CloudWatch Alarms**: Alarms for function failures and duration
- **SNS Notifications**: Real-time notifications for all remediation actions
- **Dashboard Widgets**: Pre-configured CloudWatch dashboard widgets
- **Log Aggregation**: Centralized logging with configurable retention

## Cost Considerations

- Lambda functions use on-demand pricing
- S3 storage costs for remediation artifacts and logs
- CloudWatch costs for metrics, alarms, and log storage
- SNS costs for notifications
- Cross-region data transfer costs (if applicable)

## Troubleshooting

### Common Issues

1. **Permission Errors**: Ensure IAM roles have necessary permissions
2. **Region Restrictions**: Verify all resources are in specified regions
3. **Function Timeouts**: Adjust Lambda timeout for complex remediations
4. **Notification Failures**: Check SNS topic permissions and subscriptions

### Debugging

Enable debug logging:
```bash
export TF_LOG=DEBUG
```

Check Lambda function logs:
```bash
aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/uk-"
```

## Integration

This module integrates with:

- **Security Hub Module**: Receives security findings
- **GuardDuty Module**: Processes threat detection findings
- **Config Module**: Handles compliance violations
- **IAM Identity Center Module**: Uses centralized access controls
- **Logging Module**: Sends logs to centralized log archive

## Contributing

When contributing to this module:

1. Ensure all remediation functions follow compliance requirements
2. Test with both dry-run and live modes
3. Validate cross-account functionality
4. Update documentation for any new remediation capabilities
5. Test integration with Security Hub, GuardDuty, and Config

## License

This module is part of the UK AWS Secure Landing Zone and follows the same licensing terms.