# Security Hub Module

This module implements AWS Security Hub with region-specific compliance frameworks for the UK AWS Secure Landing Zone. It provides centralized security monitoring and compliance reporting across multiple AWS accounts.

## Features

- **Centralized Security Monitoring**: Aggregates security findings from multiple AWS security services
- **UK Compliance Frameworks**: Implements Security Standards Cloud Security Principles, CIS Benchmark, and AWS Foundational Security Best Practices
- **Cross-Region Aggregation**: Supports finding aggregation across specified regions (us-west-2, us-east-1)
- **Organization Management**: Configures Security Hub as organization admin for centralized management
- **Custom Insights**: Provides region-specific security insights and compliance dashboards
- **Automated Remediation**: Includes action targets for automated security remediation

## Compliance Frameworks

### Security Standards Cloud Security Principles
- Data protection in transit and at rest monitoring
- Asset protection and resilience tracking
- User separation and access control monitoring
- Governance framework compliance
- Operational security monitoring
- Personnel security controls

### CIS AWS Foundations Benchmark
- Critical security findings monitoring
- IAM security controls
- Logging and monitoring compliance
- Network security controls
- Storage security monitoring

### AWS Foundational Security Best Practices
- Critical and high severity findings
- Service-specific security monitoring (EC2, S3, RDS, Lambda, IAM)
- Comprehensive security posture assessment

## Usage

### Basic Usage

```hcl
module "security_hub" {
  source = "./modules/security-services/security-hub"
  
  aws_region = "us-east-1"
  
  common_tags = {
    DataClassification = "internal"
    Environment       = "production"
    CostCenter        = "security"
    Owner            = "security-team"
    Project          = "uk-landing-zone"
  }
}
```

### Organization Admin Configuration

```hcl
module "security_hub" {
  source = "./modules/security-services/security-hub"
  
  aws_region         = "us-east-1"
  is_delegated_admin = true
  admin_account_id   = "123456789012"
  
  # Enable automatic enrollment for new accounts
  auto_enable_new_accounts = true
  auto_enable_standards   = "DEFAULT"
  
  # Configure cross-region finding aggregation
  enable_finding_aggregation        = true
  finding_aggregation_linking_mode  = "SPECIFIED_REGIONS"
  finding_aggregation_regions      = ["us-west-2", "us-east-1"]
  
  common_tags = {
    DataClassification = "internal"
    Environment       = "security"
    CostCenter        = "security"
    Owner            = "security-team"
    Project          = "uk-landing-zone"
  }
}
```

### Member Account Configuration

```hcl
module "security_hub" {
  source = "./modules/security-services/security-hub"
  
  aws_region         = "us-east-1"
  is_delegated_admin = false
  
  # Disable organization features for member accounts
  enable_finding_aggregation = false
  
  common_tags = {
    DataClassification = "internal"
    Environment       = "production"
    CostCenter        = "workload-team-1"
    Owner            = "workload-team"
    Project          = "uk-landing-zone"
  }
}
```

## Variables

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| aws_region | AWS region for Security Hub deployment | `string` | `"us-east-1"` | no |
| is_delegated_admin | Whether this account is the delegated Security Hub admin | `bool` | `false` | no |
| admin_account_id | AWS account ID for the Security Hub admin account | `string` | `null` | no |
| enable_cis_standard | Enable CIS AWS Foundations Benchmark standard | `bool` | `true` | no |
| enable_default_standards | Enable default Security Hub standards on account creation | `bool` | `true` | no |
| auto_enable_new_accounts | Automatically enable Security Hub for new organization accounts | `bool` | `true` | no |
| auto_enable_standards | Automatically enable standards for new organization accounts | `string` | `"DEFAULT"` | no |
| enable_finding_aggregation | Enable cross-region finding aggregation | `bool` | `true` | no |
| finding_aggregation_linking_mode | Linking mode for finding aggregation | `string` | `"SPECIFIED_REGIONS"` | no |
| finding_aggregation_regions | List of regions for finding aggregation | `list(string)` | `["us-west-2", "us-east-1"]` | no |
| common_tags | Common tags to apply to all Security Hub resources | `map(string)` | `{}` | yes |

## Outputs

| Name | Description |
|------|-------------|
| security_hub_id | Security Hub account ID |
| security_hub_arn | Security Hub account ARN |
| organization_admin_account_id | Security Hub organization admin account ID |
| finding_aggregator_arn | Security Hub finding aggregator ARN |
| uk_compliance_master_insight_arn | compliance master insight ARN |
| uk_compliance_remediation_action_arn | compliance remediation action target ARN |
| aws_foundational_subscription_arn | AWS Foundational Security Best Practices subscription ARN |
| cis_benchmark_subscription_arn | CIS AWS Foundations Benchmark subscription ARN |
| ncsc_insights | Security Standards compliance insights ARNs |
| cis_insights | CIS benchmark insights ARNs |
| aws_foundational_insights | AWS Foundational Security insights ARNs |
| remediation_actions | Security Hub action targets for automated remediation |

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0 |
| aws | ~> 5.0 |

## UK Compliance

This module is specifically designed for compliance requirements:

- **Data Residency**: All resources are restricted to specified regions (us-west-2, us-east-1)
- **Security Standards Compliance**: Implements Security Standards Cloud Security Principles monitoring
- **Mandatory Tagging**: Enforces region-specific tagging requirements
- **Audit Trail**: Provides comprehensive audit logging for regulatory requirements

## Security Considerations

- Security Hub findings may contain sensitive information - ensure proper access controls
- Cross-region aggregation should only include specified regions for data residency compliance
- Action targets for remediation should be properly secured and monitored
- Regular review of insights and findings is recommended for maintaining security posture

## Integration

This module integrates with:

- **AWS Organizations**: For organization-wide Security Hub management
- **AWS Config**: For compliance rule evaluation
- **Amazon GuardDuty**: For threat detection findings
- **AWS CloudTrail**: For audit logging
- **AWS IAM**: For access control and permissions

## Monitoring and Alerting

The module provides several built-in insights for monitoring:

- UK Compliance Master View
- Security Standards Cloud Security Principles violations
- CIS Benchmark compliance status
- AWS Foundational Security findings
- Service-specific security monitoring

Consider integrating with Amazon CloudWatch and Amazon SNS for automated alerting on security findings.