# IAM Identity Center Module

This module implements AWS IAM Identity Center (formerly AWS SSO) for the UK AWS Secure Landing Zone, providing centralized authentication and authorization with compliance controls.

## Features

- **Centralized Authentication**: Single sign-on across all AWS accounts in the organization
- **UK Compliance**: Built-in controls for Security Standards Cloud Security Principles and GDPR
- **Mandatory MFA**: Multi-factor authentication required for all permission sets
- **Least Privilege Access**: Role-based permission sets with minimal required permissions
- **Break Glass Access**: Emergency access with comprehensive auditing and time limits
- **UK Region Enforcement**: All activities restricted to specified regions (us-west-2, us-east-1)

## Permission Sets

### SecurityAdministrator
- **Purpose**: Full access to security services and compliance monitoring
- **Session Duration**: 4 hours
- **MFA Requirement**: Required, max age 1 hour
- **Key Permissions**: SecurityHub, GuardDuty, Config, CloudTrail, KMS
- **Restrictions**: specified regions only, audit trail protection

### NetworkAdministrator  
- **Purpose**: Full access to networking services and infrastructure
- **Session Duration**: 4 hours
- **MFA Requirement**: Required, max age 1 hour
- **Key Permissions**: VPC, Transit Gateway, Network Firewall, Route 53
- **Restrictions**: specified regions only, critical network resource protection

### Developer
- **Purpose**: Development access with guardrails and cost controls
- **Session Duration**: 8 hours
- **MFA Requirement**: Required for sensitive operations, max age 2 hours
- **Key Permissions**: EC2, S3, RDS, Lambda, limited IAM
- **Restrictions**: No production access, mandatory tagging, specified regions only

### ReadOnlyViewer
- **Purpose**: Read-only access across all services for monitoring and auditing
- **Session Duration**: 8 hours
- **MFA Requirement**: Required for sensitive reads only
- **Key Permissions**: Describe/Get/List operations across all services
- **Restrictions**: specified regions only, no write permissions

### BreakGlassEmergency
- **Purpose**: Emergency access with full administrative permissions
- **Session Duration**: 1 hour (limited for emergency use)
- **MFA Requirement**: Strict - required, max age 5 minutes
- **Key Permissions**: Full administrator access
- **Restrictions**: Comprehensive auditing, audit trail protection, emergency justification required

## UK Compliance Features

### Security Standards Cloud Security Principles
- **Data Protection**: All policies enforce encryption and specified region restrictions
- **Asset Protection**: Multi-AZ requirements and backup policies
- **Separation Between Users**: Account-level and permission-based isolation
- **Governance Framework**: Automated policy enforcement and compliance monitoring
- **Operational Security**: Centralized logging and monitoring
- **Personnel Security**: Mandatory MFA and least privilege access

### GDPR Compliance
- **Data Subject Rights**: Automated data discovery and classification permissions
- **Protection by Design**: Default encryption and access controls
- **Breach Notification**: Automated security alerting capabilities
- **Data Processing Records**: Comprehensive audit logging
- **Data Minimization**: Automated lifecycle policies and retention controls

## Security Controls

### Preventive Controls
- specified region restrictions via IAM policies
- Mandatory resource tagging enforcement
- MFA requirements with time-based restrictions
- Service and action restrictions per role
- Break glass access controls with justification requirements

### Detective Controls
- CloudWatch monitoring for break glass usage
- Comprehensive audit logging for all activities
- Security Hub integration for compliance monitoring
- Automated alerting for policy violations

## Usage

```hcl
module "iam_identity_center" {
  source = "./modules/avm-foundation/iam-identity-center"
  
  common_tags = {
    Environment        = "management"
    DataClassification = "internal"
    CostCenter        = "security"
    Owner             = "security-team"
    Project           = "uk-landing-zone"
  }
  
  enable_break_glass_monitoring = true
  break_glass_alarm_actions     = [aws_sns_topic.security_alerts.arn]
  
  session_durations = {
    security_admin = "PT4H"
    network_admin  = "PT4H"
    developer      = "PT8H"
    viewer         = "PT8H"
    break_glass    = "PT1H"
  }
  
  mfa_max_age_seconds = {
    security_admin = 3600   # 1 hour
    network_admin  = 3600   # 1 hour
    developer      = 7200   # 2 hours
    viewer         = 28800  # 8 hours
    break_glass    = 300    # 5 minutes
  }
}
```

## Account Assignments

After creating permission sets, assign them to users/groups and accounts:

```hcl
# Example account assignment for Security Admin
resource "aws_ssoadmin_account_assignment" "security_admin_security_account" {
  instance_arn       = module.iam_identity_center.instance_arn
  permission_set_arn = module.iam_identity_center.security_admin_permission_set_arn
  
  principal_id   = aws_identitystore_group.security_admins.group_id
  principal_type = "GROUP"
  
  target_id   = var.security_account_id
  target_type = "AWS_ACCOUNT"
}
```

## Monitoring and Alerting

The module includes built-in monitoring for break glass access:

- **CloudWatch Log Metric Filter**: Detects break glass permission set usage
- **CloudWatch Alarm**: Triggers when break glass access is used
- **SNS Integration**: Sends alerts to specified topics for immediate notification

## File Structure

```
iam-identity-center/
├── main.tf                    # Main module configuration
├── variables.tf               # Input variables
├── outputs.tf                 # Output values
├── README.md                  # This documentation
└── permission-sets/           # Individual permission set files
    ├── security-admin.tf      # Security Administrator permission set
    ├── network-admin.tf       # Network Administrator permission set
    ├── developer.tf           # Developer permission set
    ├── viewer.tf              # Read-only Viewer permission set
    └── break-glass.tf         # Break Glass Emergency permission set
```

## Policy Files

Custom IAM policies are stored in the policies directory:

```
policies/iam-policies/
├── security-admin.json        # Security Administrator inline policy
├── network-admin.json         # Network Administrator inline policy
├── developer.json             # Developer inline policy
├── viewer.json                # Viewer inline policy
└── break-glass.json           # Break Glass inline policy
```

## Requirements

- AWS Provider >= 5.0
- IAM Identity Center must be enabled in the management account
- Appropriate permissions to create and manage SSO resources
- CloudWatch Logs group `/aws/sso/audit` for break glass monitoring

## Outputs

- `instance_arn`: IAM Identity Center instance ARN
- `identity_store_id`: Identity Store ID for user/group management
- `permission_sets`: Map of all permission set names to ARNs
- `break_glass_monitoring`: Break glass monitoring configuration (if enabled)

## Best Practices

1. **Regular Access Reviews**: Periodically review permission set assignments
2. **Break Glass Procedures**: Document and test emergency access procedures
3. **MFA Enforcement**: Ensure all users have MFA devices configured
4. **Monitoring**: Set up alerting for all permission set usage, especially break glass
5. **Least Privilege**: Regularly review and minimize permissions as needed
6. **Compliance Auditing**: Use the built-in compliance controls for regular audits