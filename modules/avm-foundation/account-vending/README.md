# Account Vending Module

This module implements automated account provisioning with UK tags and baseline configurations for the UK AWS Secure Landing Zone. It creates and configures AWS accounts with appropriate organizational unit placement, security controls, and compliance settings.

## Features

- **Automated Account Creation**: Creates AWS accounts using AWS Organizations with proper organizational unit assignment
- **UK Compliance**: Enforces UK data residency, mandatory tagging, and compliance frameworks
- **Baseline Security**: Configures cross-account access roles, KMS encryption, and security controls
- **Cost Management**: Creates budgets and cost monitoring for each account
- **Baseline Configuration**: Deploys baseline infrastructure using CloudFormation StackSets
- **Comprehensive Tagging**: Applies mandatory compliance tags to all resources

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0 |
| aws | ~> 5.0 |
| random | ~> 3.4 |

## Providers

| Name | Version |
|------|---------|
| aws | ~> 5.0 |
| random | ~> 3.4 |

## Resources Created

- `aws_organizations_account` - AWS accounts for workloads
- `aws_iam_role` - Cross-account access roles
- `aws_kms_key` - Account-specific encryption keys
- `aws_kms_alias` - KMS key aliases
- `aws_s3_bucket` - Baseline configuration storage buckets
- `aws_budgets_budget` - Cost management budgets
- `aws_cloudformation_stack_set` - Baseline configuration StackSet
- `aws_cloudformation_stack_set_instance` - StackSet deployments

## Usage

### Basic Usage

```hcl
module "account_vending" {
  source = "./modules/avm-foundation/account-vending"

  workload_accounts = {
    production_app = {
      name                     = "Production-Application"
      email                    = "aws-prod-app@company.com"
      organizational_unit_id   = module.organization.production_uk_ou_id
      account_type            = "workload"
      data_classification     = "confidential"
      environment             = "production"
      cost_center             = "APP-001"
      owner                   = "application-team@company.com"
      project                 = "Core-Application"
      monthly_budget_limit    = 5000
      budget_notification_email = "finance@company.com"
      external_id             = "prod-app-12345"
    }
    
    dev_app = {
      name                     = "Development-Application"
      email                    = "aws-dev-app@company.com"
      organizational_unit_id   = module.organization.non_production_uk_ou_id
      account_type            = "workload"
      data_classification     = "internal"
      environment             = "non-production"
      cost_center             = "APP-001"
      owner                   = "application-team@company.com"
      project                 = "Core-Application"
      monthly_budget_limit    = 1000
      budget_notification_email = "finance@company.com"
      external_id             = "dev-app-67890"
    }
  }

  security_account_id = "123456789012"
  logging_account_id  = "123456789013"

  common_tags = {
    Project             = "UK-AWS-Secure-Landing-Zone"
    ManagedBy           = "Terraform"
    ComplianceFramework = "Security Standards-Cloud-Security-Principles"
    DataResidency       = "UK"
  }
}
```

### Advanced Usage with Custom Configuration

```hcl
module "account_vending" {
  source = "./modules/avm-foundation/account-vending"

  workload_accounts = {
    security_tooling = {
      name                     = "Security-Tooling"
      email                    = "aws-security@company.com"
      organizational_unit_id   = module.organization.core_infrastructure_ou_id
      account_type            = "security"
      data_classification     = "restricted"
      environment             = "security"
      cost_center             = "SEC-001"
      owner                   = "security-team@company.com"
      project                 = "Security-Infrastructure"
      backup_schedule         = "continuous"
      maintenance_window      = "sun:02:00-sun:03:00"
      monthly_budget_limit    = 2000
      budget_notification_email = "security-finance@company.com"
      external_id             = "sec-tool-abcde"
      tags = {
        SecurityLevel = "High"
        Monitoring    = "24x7"
      }
    }
  }

  # Account configuration
  security_account_id = "123456789012"
  logging_account_id  = "123456789013"
  
  # Feature toggles
  enable_account_kms_keys     = true
  create_baseline_s3_buckets  = true
  create_account_budgets      = true
  deploy_baseline_stackset    = true
  enable_cross_account_roles  = true

  # StackSet deployment configuration
  organizational_unit_deployments = {
    production_uk = {
      ou_id  = module.organization.production_uk_ou_id
      region = "us-east-1"
    }
    non_production_uk = {
      ou_id  = module.organization.non_production_uk_ou_id
      region = "us-east-1"
    }
  }

  # Security configuration
  kms_key_deletion_window = 7
  s3_lifecycle_expiration_days = 2555  # 7 years for compliance
  
  # Notification configuration
  notification_email = "aws-notifications@company.com"

  common_tags = {
    Project             = "UK-AWS-Secure-Landing-Zone"
    ManagedBy           = "Terraform"
    ComplianceFramework = "Security Standards-Cloud-Security-Principles"
    DataResidency       = "UK"
    CostCenter          = "PLATFORM-001"
    Owner               = "platform-team@company.com"
  }
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| workload_accounts | Map of workload accounts to create with their configurations | `map(object)` | `{}` | no |
| common_tags | Common tags to apply to all resources | `map(string)` | See variables.tf | no |
| account_access_role_name | Name of the IAM role to create in new accounts for cross-account access | `string` | `"OrganizationAccountAccessRole"` | no |
| iam_user_access_to_billing | Whether IAM users in the account can access billing information | `string` | `"ALLOW"` | no |
| close_on_deletion | Whether to close the account when it is deleted from Terraform | `bool` | `false` | no |
| security_account_id | AWS Account ID of the Security Tooling Account | `string` | n/a | yes |
| logging_account_id | AWS Account ID of the Log Archive Account | `string` | n/a | yes |
| enable_account_kms_keys | Whether to create account-specific KMS keys for encryption | `bool` | `true` | no |
| kms_key_deletion_window | Number of days to wait before deleting KMS keys | `number` | `7` | no |
| create_baseline_s3_buckets | Whether to create baseline S3 buckets for account configuration | `bool` | `true` | no |
| force_destroy_buckets | Force destroy S3 buckets even if they contain objects (use with caution) | `bool` | `false` | no |
| s3_lifecycle_expiration_days | Number of days after which S3 objects expire | `number` | `2555` | no |
| create_account_budgets | Whether to create AWS Budgets for cost management | `bool` | `true` | no |
| deploy_baseline_stackset | Whether to deploy baseline configuration using CloudFormation StackSets | `bool` | `true` | no |
| organizational_unit_deployments | Map of organizational units where baseline StackSet should be deployed | `map(object)` | `{}` | no |
| aws_regions | List of allowed AWS regions for UK data residency | `list(string)` | `["us-west-2", "us-east-1"]` | no |
| account_provisioning_timeout | Timeout for account provisioning in minutes | `number` | `30` | no |
| enable_cross_account_roles | Whether to create cross-account access roles | `bool` | `true` | no |
| notification_email | Email address for account provisioning notifications | `string` | `""` | no |

## Outputs

| Name | Description |
|------|-------------|
| workload_accounts | Map of created workload accounts with their details |
| account_ids | Map of account names to account IDs |
| account_arns | Map of account names to account ARNs |
| cross_account_roles | Map of cross-account access roles created for each account |
| account_kms_keys | Map of KMS keys created for each account |
| baseline_s3_buckets | Map of baseline S3 buckets created for each account |
| account_budgets | Map of AWS Budgets created for each account |
| baseline_stackset | Details of the baseline CloudFormation StackSet |
| account_provisioning_summary | Summary of account provisioning results |
| compliance_status | Compliance status of provisioned accounts |
| account_access_instructions | Instructions for accessing the provisioned accounts |
| next_steps | Recommended next steps after account provisioning |

## Account Configuration Object

The `workload_accounts` variable expects a map of objects with the following structure:

```hcl
{
  name                     = string  # Account name
  email                    = string  # Unique email address for the account
  organizational_unit_id   = string  # OU ID where the account should be placed
  account_type            = string  # Type: workload, security, logging, networking, shared-services
  data_classification     = string  # Classification: public, internal, confidential, restricted
  environment             = string  # Environment: production, non-production, sandbox, security, logging, networking
  cost_center             = string  # Cost center for billing
  owner                   = string  # Owner email address
  project                 = string  # Project name
  backup_schedule         = string  # Backup schedule (optional, default: "daily")
  maintenance_window      = string  # Maintenance window (optional, default: "sun:03:00-sun:04:00")
  monthly_budget_limit    = number  # Monthly budget limit in USD (optional, default: 1000)
  budget_notification_email = string # Email for budget notifications
  external_id             = string  # External ID for cross-account access
  tags                    = map(string) # Additional tags (optional)
}
```

## UK Compliance Features

### Data Residency
- All resources are restricted to specified regions (us-west-2, us-east-1)
- Service Control Policies enforce regional restrictions
- Automated validation of resource locations

### Mandatory Tagging
- Enforces region-specific tagging strategy
- Includes data classification, environment, cost center, and owner tags
- Validates tag compliance during resource creation

### Security Controls
- Creates account-specific KMS keys for encryption at rest
- Configures cross-account access with MFA requirements
- Implements least privilege access principles
- Enables comprehensive audit logging

### Cost Management
- Creates budgets for each account with alerting
- Tracks spending by cost center and project
- Provides cost allocation reporting capabilities

### Baseline Configuration
- Deploys consistent security configuration across accounts
- Enables AWS Config, CloudTrail, and other security services
- Implements region-specific compliance packs

## Security Considerations

1. **Cross-Account Access**: All cross-account roles require MFA and use external IDs for additional security
2. **Encryption**: Account-specific KMS keys provide encryption at rest for all resources
3. **Network Security**: Accounts are isolated by default with controlled cross-account communication
4. **Audit Logging**: Comprehensive logging is enabled for all account activities
5. **Compliance Monitoring**: Continuous compliance monitoring using AWS Config and Security Hub

## Cost Considerations

1. **Account Costs**: Each AWS account has no monthly fee but may incur costs for services used
2. **KMS Keys**: Each account-specific KMS key costs $1/month plus usage charges
3. **S3 Storage**: Baseline S3 buckets incur storage costs based on usage
4. **CloudFormation StackSets**: No additional cost for StackSets themselves
5. **AWS Budgets**: First two budgets per account are free, additional budgets cost $0.02/day

## Troubleshooting

### Common Issues

1. **Email Address Already in Use**: Each AWS account requires a unique email address
2. **Account Limit Reached**: AWS has default limits on the number of accounts per organization
3. **Insufficient Permissions**: Ensure the executing role has Organizations and account creation permissions
4. **StackSet Deployment Failures**: Check CloudFormation events for specific error details

### Validation Commands

```bash
# Validate account creation
aws organizations list-accounts

# Check organizational unit placement
aws organizations list-accounts-for-parent --parent-id <ou-id>

# Verify cross-account role assumption
aws sts assume-role --role-arn <role-arn> --role-session-name test --external-id <external-id>

# Check budget creation
aws budgets describe-budgets --account-id <account-id>
```

## Integration with Other Modules

This module is designed to work with other UK Landing Zone modules:

- **Organization Module**: Provides organizational unit IDs for account placement
- **IAM Identity Center Module**: Configures SSO access to provisioned accounts
- **Security Services Modules**: Deploys security controls to new accounts
- **Networking Modules**: Connects accounts to the hub-and-spoke network architecture

## Examples

See the `examples/` directory for complete usage examples:

- `examples/basic-account-vending/` - Basic account provisioning
- `examples/multi-environment-accounts/` - Multiple environment setup
- `examples/security-account-setup/` - Security tooling account configuration

## Contributing

When contributing to this module:

1. Ensure all resources follow compliance requirements
2. Add appropriate validation rules for input variables
3. Update documentation for any new features
4. Test with multiple account configurations
5. Verify StackSet deployment functionality

## License

This module is part of the UK AWS Secure Landing Zone project and follows the same licensing terms.