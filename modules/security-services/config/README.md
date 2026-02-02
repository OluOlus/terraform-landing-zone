# AWS Config Module - UK Compliance Monitoring

This module provides comprehensive compliance monitoring for the UK AWS Secure Landing Zone using AWS Config service. It implements conformance packs for Security Standards Cloud Security Principles, GDPR, and Security Essentials frameworks.

## Features

- **AWS Config Service**: Centralized configuration recording and compliance monitoring
- **Organization Aggregation**: Cross-account compliance visibility for delegated admin accounts
- **Security Standards Cloud Security Principles**: Complete implementation of all 7 principles
- **GDPR Compliance**: Comprehensive GDPR compliance monitoring and reporting
- **Security Essentials**: Implementation of all 5 Security Essentials controls
- **Custom UK Rules**: Additional rules for region-specific requirements like data residency and mandatory tagging

## Architecture

```
config/
├── main.tf                     # Main Config service configuration
├── variables.tf                # Input variables
├── outputs.tf                  # Output values
├── README.md                   # This file
└── conformance-packs/          # Compliance framework implementations
    ├── main.tf                 # Conformance packs orchestration
    ├── variables.tf            # Conformance pack variables
    ├── outputs.tf              # Conformance pack outputs
    ├── ncsc.tf                 # Security Standards Cloud Security Principles
    ├── uk-gdpr.tf              # GDPR compliance
    ├── cyber-essentials.tf     # Security Essentials compliance
    ├── ncsc-pack.yaml          # Security Standards conformance pack template
    ├── uk-gdpr-pack.yaml       # GDPR conformance pack template
    └── cyber-essentials-pack.yaml # Security Essentials conformance pack template
```

## Usage

### Basic Usage

```hcl
module "config" {
  source = "./modules/security-services/config"

  # Core Config settings
  config_service_role_arn = aws_iam_role.config_role.arn
  config_s3_bucket_name   = "uk-config-bucket-${random_id.suffix.hex}"
  
  # Enable all compliance frameworks
  enable_ncsc_pack             = true
  enable_gdpr_pack             = true
  enable_cyber_essentials_pack = true
  
  # Organization settings (for Security Tooling Account)
  is_delegated_admin    = true
  organization_role_arn = aws_iam_role.config_organization_role.arn
  
  common_tags = {
    Environment         = "production"
    DataClassification  = "confidential"
    ComplianceFramework = "Security Standards,UK-GDPR,Cyber-Essentials"
  }
}
```

### Advanced Configuration

```hcl
module "config" {
  source = "./modules/security-services/config"

  # Core Config settings
  config_service_role_arn     = aws_iam_role.config_role.arn
  config_s3_bucket_name       = "uk-config-bucket-${random_id.suffix.hex}"
  config_s3_key_prefix        = "config/uk-landing-zone"
  recording_frequency         = "CONTINUOUS"
  snapshot_delivery_frequency = "TwentyFour_Hours"
  
  # Security Standards-specific settings
  enable_ncsc_pack              = true
  ncsc_access_key_max_age       = "90"
  ncsc_root_credential_max_age  = "90"
  ncsc_approved_ami_ids         = ["ami-12345678", "ami-87654321"]
  ncsc_kms_key_id              = aws_kms_key.uk_master_key.id
  
  # GDPR-specific settings
  enable_gdpr_pack                = true
  gdpr_data_retention_days        = "2555"  # 7 years
  gdpr_key_rotation_days          = "365"
  gdpr_access_log_retention_days  = "2555"
  gdpr_encryption_key_ids         = aws_kms_key.gdpr_key.id
  
  # Security Essentials-specific settings
  enable_cyber_essentials_pack     = true
  ce_firewall_timeout_seconds      = "300"
  ce_patch_compliance_timeout_days = "30"
  ce_password_min_length           = "14"
  ce_encryption_key_ids            = aws_kms_key.ce_key.id
  
  # region-specific custom rules
  enable_uk_data_residency_rule    = true
  uk_approved_ami_ids              = ["ami-uk-12345", "ami-uk-67890"]
  enable_uk_mandatory_tagging_rule = true
  
  # Organization settings
  is_delegated_admin    = var.is_security_tooling_account
  organization_role_arn = var.is_security_tooling_account ? aws_iam_role.config_organization_role[0].arn : null
  
  common_tags = local.common_tags
}
```

## Compliance Frameworks

### Security Standards Cloud Security Principles

Implements all 7 Security Standards Cloud Security Principles:

1. **Data in Transit Protection**: TLS/HTTPS enforcement
2. **Data at Rest Protection**: Encryption requirements
3. **Asset Protection and Resilience**: Multi-AZ, backups, versioning
4. **Separation Between Users**: IAM, MFA, access controls
5. **Governance Framework**: Policy enforcement, admin access restrictions
6. **Operational Security**: Logging, monitoring, GuardDuty
7. **Personnel Security**: MFA, credential rotation, unused credential detection

### GDPR Compliance

Implements key GDPR articles:

- **Article 25**: Data Protection by Design and by Default
- **Article 30**: Records of Processing Activities
- **Article 32**: Security of Processing
- **Article 33**: Notification of Personal Data Breach
- **Article 35**: Data Protection Impact Assessment
- **Article 17**: Right to be Forgotten
- **Article 20**: Data Portability
- **Article 6**: Lawfulness of Processing
- **Article 5**: Data Minimization
- **Articles 44-49**: International Transfers

### Security Essentials

Implements all 5 Security Essentials controls:

1. **Boundary Firewalls and Internet Gateways**: Security groups, NACLs, VPC Flow Logs
2. **Secure Configuration**: Systems Manager, password policies, default configurations
3. **Access Control**: MFA, privileged access management, user account management
4. **Malware Protection**: GuardDuty, endpoint monitoring
5. **Patch Management**: Systems Manager patch compliance, software updates

## Variables

### Core Variables

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| `config_service_role_arn` | ARN of the IAM role for Config service | `string` | n/a | yes |
| `config_s3_bucket_name` | S3 bucket name for Config delivery | `string` | n/a | yes |
| `enable_config_recorder` | Enable AWS Config recorder | `bool` | `true` | no |
| `recording_frequency` | Recording frequency for Config | `string` | `"CONTINUOUS"` | no |

### Compliance Framework Variables

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| `enable_ncsc_pack` | Enable Security Standards conformance pack | `bool` | `true` | no |
| `enable_gdpr_pack` | Enable GDPR conformance pack | `bool` | `true` | no |
| `enable_cyber_essentials_pack` | Enable Security Essentials conformance pack | `bool` | `true` | no |

### Organization Variables

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| `is_delegated_admin` | Is this the delegated admin account | `bool` | `false` | no |
| `organization_role_arn` | Organization role ARN for aggregator | `string` | `null` | no |

## Outputs

### Core Outputs

| Name | Description |
|------|-------------|
| `config_recorder_name` | Name of the Config recorder |
| `aggregator_arn` | Config aggregator ARN |
| `enabled_compliance_frameworks` | List of enabled compliance frameworks |

### Compliance Pack Outputs

| Name | Description |
|------|-------------|
| `ncsc_pack_arn` | Security Standards conformance pack ARN |
| `gdpr_pack_arn` | GDPR conformance pack ARN |
| `cyber_essentials_pack_arn` | Security Essentials conformance pack ARN |

## Requirements

### Terraform

- Terraform >= 1.0
- AWS Provider >= 5.0

### AWS Permissions

The Config service role requires the following permissions:

- `config:*`
- `s3:GetBucketAcl`
- `s3:ListBucket`
- `s3:GetBucketLocation`
- `s3:PutObject`
- `s3:GetObject`
- `organizations:DescribeOrganization`
- `organizations:ListAccounts`
- `organizations:ListAWSServiceAccessForOrganization`

### Prerequisites

1. AWS Config must be enabled in the account
2. S3 bucket for Config delivery must exist
3. IAM role for Config service must be created
4. For organization aggregation, the account must be designated as Config delegated admin

## Integration

This module integrates with:

- **Security Hub Module**: Config findings are sent to Security Hub
- **GuardDuty Module**: GuardDuty findings complement Config compliance monitoring
- **IAM Identity Center Module**: Access controls for Config resources
- **Logging Module**: Config logs are centralized in the Log Archive Account

## Compliance Reporting

The module provides comprehensive compliance reporting through:

- **AWS Config Dashboard**: Real-time compliance status
- **Conformance Pack Reports**: Framework-specific compliance reports
- **Custom Config Rules**: region-specific compliance requirements
- **Organization Aggregation**: Cross-account compliance visibility

## Troubleshooting

### Common Issues

1. **Config Recorder Not Starting**
   - Verify IAM role permissions
   - Check S3 bucket policy allows Config service
   - Ensure delivery channel is properly configured

2. **Conformance Pack Deployment Failures**
   - Verify all required parameters are provided
   - Check for conflicting Config rules
   - Ensure proper dependencies are in place

3. **Organization Aggregation Issues**
   - Verify account is designated as Config delegated admin
   - Check organization role permissions
   - Ensure all regions are properly configured

### Debugging

Enable debug logging by setting:

```bash
export TF_LOG=DEBUG
export AWS_SDK_LOAD_CONFIG=1
```

## Security Considerations

- All Config data is encrypted in transit and at rest
- Access to Config resources is controlled through IAM
- Conformance pack templates are validated before deployment
- Custom rules follow least privilege principles
- Organization aggregation uses cross-account roles with minimal permissions

## Cost Optimization

- Use `recording_frequency = "DAILY"` for non-critical environments
- Implement S3 lifecycle policies for Config data
- Consider selective resource recording for cost-sensitive workloads
- Monitor Config rule evaluations and optimize as needed

## Support

For issues and questions:

1. Check the troubleshooting section above
2. Review AWS Config documentation
3. Consult the UK Landing Zone architecture documentation
4. Contact the platform team for assistance