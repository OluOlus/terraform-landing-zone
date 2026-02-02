# Organization Structure Module

This module implements the AWS Organizations structure for the UK AWS Secure Landing Zone, creating organizational units (OUs) and applying service control policies (SCPs) to enforce compliance requirements.

## Overview

The module creates a hierarchical organization structure with region-specific organizational units and applies comprehensive service control policies to ensure compliance with regulatory requirements including Security Standards Cloud Security Principles and GDPR.

## Architecture

```
Root Organization
├── Production-UK OU
│   ├── Production workload accounts
│   └── Applied SCPs: All policies
├── Non-Production-UK OU
│   ├── Development and testing accounts
│   └── Applied SCPs: All policies
├── Sandbox OU
│   ├── Experimentation accounts
│   └── Applied SCPs: Data residency, tagging, IAM hardening (no service restrictions)
└── Core-Infrastructure OU
    ├── Security Tooling Account
    ├── Log Archive Account
    ├── Network Hub Account
    └── Applied SCPs: All policies (strict enforcement)
```

## Organizational Units

### Production-UK
- **Purpose**: Production workloads for UK operations
- **Environment**: production
- **Data Classification**: confidential
- **Applied Policies**: All SCPs with strict enforcement

### Non-Production-UK
- **Purpose**: Development and testing environments
- **Environment**: non-production
- **Data Classification**: internal
- **Applied Policies**: All SCPs with moderate enforcement

### Sandbox
- **Purpose**: Experimentation and proof-of-concept
- **Environment**: sandbox
- **Data Classification**: internal
- **Applied Policies**: Data residency, tagging, IAM hardening (service restrictions relaxed for learning)

### Core-Infrastructure
- **Purpose**: Core infrastructure accounts (Security, Logging, Networking)
- **Environment**: infrastructure
- **Data Classification**: restricted
- **Applied Policies**: All SCPs with strict enforcement

## Service Control Policies

### UK Data Residency Policy
- **Purpose**: Enforces UK data residency requirements
- **Restrictions**: Limits resource creation to specified regions (us-west-2, us-east-1)
- **Exceptions**: Break-glass access for emergency situations
- **Compliance**: GDPR

### Mandatory Tagging Policy
- **Purpose**: Enforces mandatory resource tagging
- **Required Tags**: DataClassification, Environment, CostCenter, Owner
- **Scope**: EC2, RDS, S3, Lambda, ECS, EKS resources
- **Compliance**: UK cost management and governance

### Service Restrictions Policy
- **Purpose**: Restricts access to high-risk AWS services
- **Restricted Services**: AI/ML services, collaboration tools, workspace services
- **Protected Controls**: Prevents disabling CloudTrail, Config, GuardDuty
- **Security**: Prevents leaving organization
- **Compliance**: Security Standards Cloud Security Principles

### IAM Hardening Policy
- **Purpose**: Enforces IAM security best practices
- **Requirements**: MFA for sensitive actions, role protection
- **Restrictions**: Prevents overly permissive policies, protects critical roles
- **Compliance**: Security Standards Personnel Security

## Usage

```hcl
module "organization" {
  source = "./modules/avm-foundation/organization"

  common_tags = {
    Project             = "UK-AWS-Secure-Landing-Zone"
    ManagedBy          = "Terraform"
    ComplianceFramework = "Security Standards-Cloud-Security-Principles"
    DataResidency      = "UK"
  }

  enable_service_control_policies = true
  policy_path                    = "../../policies/scps"
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| common_tags | Common tags to be applied to all resources | `map(string)` | See variables.tf | no |
| enable_service_control_policies | Whether to enable and attach service control policies | `bool` | `true` | no |
| policy_path | Path to the directory containing SCP policy JSON files | `string` | `"../../policies/scps"` | no |

## Outputs

| Name | Description |
|------|-------------|
| organization_id | The ID of the AWS Organization |
| organization_arn | The ARN of the AWS Organization |
| organization_root_id | The ID of the organization root |
| production_uk_ou_id | The ID of the Production UK organizational unit |
| non_production_uk_ou_id | The ID of the Non-Production UK organizational unit |
| sandbox_ou_id | The ID of the Sandbox organizational unit |
| core_infrastructure_ou_id | The ID of the Core Infrastructure organizational unit |
| service_control_policies | Map of service control policy IDs and ARNs |
| organizational_units | Map of all organizational units with their IDs and ARNs |

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0 |
| aws | ~> 5.0 |

## Providers

| Name | Version |
|------|---------|
| aws | ~> 5.0 |

## Resources

- `aws_organizations_organizational_unit` - Creates organizational units
- `aws_organizations_policy` - Creates service control policies
- `aws_organizations_policy_attachment` - Attaches policies to organizational units
- `data.aws_organizations_organization` - References the current organization

## Compliance

This module implements the following compliance requirements:

- **Requirements 1.2**: region-specific Organizational Units for Production UK, Non-Production UK, and Sandbox environments
- **Requirements 6.1**: Service control policies for region lock, mandatory tagging, service restrictions, and IAM hardening
- **GDPR**: Data residency enforcement through region restrictions
- **Security Standards Cloud Security Principles**: Service restrictions and IAM hardening
- **UK Cost Management**: Mandatory tagging for cost allocation and governance

## Security Considerations

1. **Break-Glass Access**: All policies include break-glass exceptions for emergency access
2. **Least Privilege**: Policies enforce least privilege access principles
3. **Defense in Depth**: Multiple layers of policy enforcement
4. **Audit Trail**: All policy violations are logged and monitored
5. **Regional Compliance**: Strict enforcement of UK data residency

## Monitoring and Alerting

The organization structure integrates with:
- AWS Config for compliance monitoring
- AWS CloudTrail for audit logging
- AWS Security Hub for security findings
- Custom compliance dashboards for real-time monitoring