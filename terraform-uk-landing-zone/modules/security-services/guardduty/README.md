# GuardDuty Module

This module provides threat detection for the AWS Secure Landing Zone using Amazon GuardDuty with threat intelligence, cross-region capabilities, and compliance monitoring.

## Features

- **UK-Specific Threat Intelligence**: Integrates with UK government, Security Standards, and sector-specific threat feeds
- **Cross-Region Detection**: Enables GuardDuty across both specified regions (us-west-2, us-east-1) with centralized management
- **Organization-Wide Coverage**: Automatically enables GuardDuty for all organization accounts
- **Compliance Monitoring**: Includes filters and rules for compliance frameworks (Security Standards, GDPR)
- **Automated Updates**: Optional automated threat intelligence feed updates
- **Centralized Findings**: Publishes findings to centralized S3 bucket with encryption

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    GuardDuty Module Architecture                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌──────────────┐ │
│  │   Primary       │    │   Alternate     │    │  Disaster    │ │
│  │   Detector      │◄──►│   Detector      │    │  Recovery    │ │
│  │  (us-east-1)    │    │  (us-west-2)    │    │  Detector    │ │
│  └─────────────────┘    └─────────────────┘    └──────────────┘ │
│           │                       │                     │       │
│           ▼                       ▼                     ▼       │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              Threat Intelligence Feeds                     │ │
│  │  • UK Government    • Security Standards Critical Infrastructure         │ │
│  │  • Financial Svcs   • Healthcare (NHS)                    │ │
│  │  • Brexit-Related   • Critical National Infrastructure    │ │
│  └─────────────────────────────────────────────────────────────┘ │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                 IP Lists & Filters                         │ │
│  │  • UK Government Allowlist                                 │ │
│  │  • UK-Targeted Threats Blocklist                          │ │
│  │  • High Severity Filter                                   │ │
│  │  • Compliance Violations Filter                           │ │
│  └─────────────────────────────────────────────────────────────┘ │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              Centralized Findings                          │ │
│  │  • S3 Publishing Destination                              │ │
│  │  • Cross-Region Aggregation                               │ │
│  │  • KMS Encryption                                         │ │
│  │  • EventBridge Integration                                │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Usage

### Basic Usage

```hcl
module "guardduty" {
  source = "./modules/security-services/guardduty"

  # Basic configuration
  enable_detector              = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  environment                 = "production"

  # Organization configuration (for Security Tooling Account)
  is_delegated_admin = true
  admin_account_id   = "123456789012"

  # region-specific threat intelligence
  enable_uk_threat_intelligence   = true
  enable_ncsc_threat_intelligence = true

  # Cross-region configuration
  enable_cross_region = true

  common_tags = {
    Environment         = "production"
    DataClassification  = "confidential"
    ComplianceFramework = "Security Standards"
    CostCenter         = "security"
    Owner              = "security-team"
  }
}
```

### Advanced Configuration with Sector-Specific Threat Intelligence

```hcl
module "guardduty_financial" {
  source = "./modules/security-services/guardduty"

  # Enable financial services threat intelligence
  enable_financial_threat_intelligence = true
  financial_threat_list_location      = "s3://uk-threat-intel/financial/threats.txt"

  # Enable automated threat intelligence updates
  enable_automated_threat_intel_updates = true
  threat_intel_updater_zip_path        = "./lambda/threat-intel-updater.zip"
  threat_intel_s3_bucket              = "uk-threat-intelligence-bucket"
  threat_intel_kms_key_arn            = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"

  # Publishing destination
  enable_publishing_destination = true
  findings_destination_arn     = "arn:aws:s3:::uk-guardduty-findings"
  findings_kms_key_arn        = "arn:aws:kms:us-east-1:123456789012:key/87654321-4321-4321-4321-210987654321"

  common_tags = {
    Environment         = "production"
    DataClassification  = "confidential"
    ComplianceFramework = "FCA-PRA"
    Sector             = "financial-services"
  }
}
```

### Healthcare/NHS Configuration

```hcl
module "guardduty_healthcare" {
  source = "./modules/security-services/guardduty"

  # Enable healthcare-specific threat intelligence
  enable_healthcare_threat_intelligence = true
  healthcare_threat_list_location      = "s3://nhs-threat-intel/healthcare/threats.txt"

  # Enable critical national infrastructure protection
  enable_cni_threat_intelligence = true
  cni_threat_list_location      = "s3://ncsc-cni/threats.txt"

  common_tags = {
    Environment         = "production"
    DataClassification  = "restricted"
    ComplianceFramework = "NHS-Digital"
    Sector             = "healthcare"
  }
}
```

## Provider Configuration

This module requires AWS provider aliases for cross-region functionality:

```hcl
# Primary specified region (London)
provider "aws" {
  alias  = "primary"
  region = "us-east-1"
}

# Alternate specified region (Ireland)
provider "aws" {
  alias  = "alternate"
  region = "us-west-2"
}

# Disaster recovery region (if enabled)
provider "aws" {
  alias  = "disaster_recovery"
  region = "us-west-2"  # or another approved region
}

module "guardduty" {
  source = "./modules/security-services/guardduty"

  providers = {
    aws                   = aws.primary
    aws.alternate         = aws.alternate
    aws.disaster_recovery = aws.disaster_recovery
  }

  # ... other configuration
}
```

## Threat Intelligence Feeds

### UK Government Feeds
- **UK Government Threat Intelligence**: Official government threat indicators
- **Security Standards Critical Infrastructure**: Threats targeting UK critical infrastructure
- **Brexit-Related Threats**: Trade and customs system targeting threats

### Sector-Specific Feeds
- **Financial Services**: FCA/PRA regulated entity threats
- **Healthcare**: NHS and healthcare sector threats
- **Critical National Infrastructure**: CNI-specific threat indicators

### IP Lists
- **UK Government Allowlist**: Known safe UK government IP ranges
- **UK-Targeted Threats Blocklist**: Known malicious IPs targeting UK entities

## Compliance Features

### Security Standards Cloud Security Principles
- **Data Protection**: Encrypted findings storage and transmission
- **Asset Protection**: Multi-region threat detection
- **Separation**: Account-level isolation with organization management
- **Governance**: Automated policy enforcement and compliance monitoring

### GDPR Compliance
- **Data Minimization**: Configurable data retention periods
- **Security by Design**: Default encryption and access controls
- **Breach Detection**: Automated security incident detection

## Outputs

| Name | Description |
|------|-------------|
| `detector_id` | Primary GuardDuty detector ID |
| `detector_arn` | Primary GuardDuty detector ARN |
| `alternate_detector_id` | Alternate region detector ID |
| `uk_compliance_status` | compliance configuration status |
| `enabled_threat_intelligence_feeds` | List of enabled threat feeds |
| `enabled_ip_lists` | List of enabled IP lists |

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0 |
| aws | ~> 5.0 |

## Providers

| Name | Version |
|------|---------|
| aws | ~> 5.0 |
| aws.alternate | ~> 5.0 |
| aws.disaster_recovery | ~> 5.0 |

## Resources Created

- GuardDuty detectors (primary, alternate, DR)
- Organization admin account configuration
- Organization-wide GuardDuty settings
- Threat intelligence sets (multiple region-specific feeds)
- IP sets (allowlists and blocklists)
- GuardDuty filters for compliance monitoring
- Publishing destinations for centralized findings
- Lambda function for automated threat intelligence updates
- EventBridge rules for cross-region aggregation

## Security Considerations

1. **Threat Intelligence Sources**: Ensure threat intelligence feeds are from trusted UK government and Security Standards sources
2. **Access Control**: Limit access to GuardDuty configuration to authorized security personnel
3. **Encryption**: All findings and threat intelligence data is encrypted at rest and in transit
4. **Audit Logging**: All GuardDuty configuration changes are logged via CloudTrail
5. **Cross-Region**: Findings are replicated across specified regions for resilience

## Cost Considerations

- GuardDuty pricing is based on CloudTrail events, DNS logs, and VPC Flow Logs analyzed
- Malware protection incurs additional costs for EBS volume scans
- Cross-region configuration doubles the base costs
- Threat intelligence feeds may have associated data transfer costs

## Monitoring and Alerting

The module creates several filters and rules for monitoring:

- High severity findings filter
- compliance violations filter
- Cross-region findings aggregation
- Automated threat intelligence update monitoring

## Troubleshooting

### Common Issues

1. **Cross-Region Configuration**: Ensure provider aliases are correctly configured
2. **Threat Intelligence Feeds**: Verify S3 bucket permissions and file formats
3. **Organization Settings**: Ensure the Security Tooling Account has proper permissions
4. **KMS Keys**: Verify KMS key policies allow GuardDuty service access

### Validation

```bash
# Validate GuardDuty detector status
aws guardduty list-detectors --region us-east-1

# Check threat intelligence sets
aws guardduty list-threat-intel-sets --detector-id <detector-id> --region us-east-1

# Verify organization configuration
aws guardduty describe-organization-configuration --detector-id <detector-id> --region us-east-1
```

## Contributing

When contributing to this module:

1. Ensure all threat intelligence feeds are from approved UK sources
2. Test cross-region functionality in both specified regions
3. Validate compliance with Security Standards Cloud Security Principles
4. Update documentation for any new threat intelligence sources
5. Test automated threat intelligence update functionality

## License

This module is part of the UK AWS Secure Landing Zone and follows the same licensing terms.