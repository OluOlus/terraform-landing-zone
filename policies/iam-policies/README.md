# IAM Policy Files - UK AWS Secure Landing Zone

This directory contains IAM policy files that support the IAM Identity Center permission sets with proper compliance controls. All policies follow least privilege principles and implement regulatory requirements.

## Policy Overview

### 1. Security Administrator Policy (`security-admin.json`)

**Purpose**: Full access to security services with compliance controls and audit capabilities.

**Key Features**:
- Full access to SecurityHub, GuardDuty, Config, Inspector, Macie, and Detective
- CloudTrail management with mandatory UK data classification tags
- IAM security management with policy restrictions
- KMS key management with specified region restrictions and key rotation
- Organizations policy management for SCPs, tag policies, and backup policies
- GDPR data discovery through Macie integration
- Security automation through SSM with purpose-based resource tagging
- Cost and compliance reporting capabilities

**UK Compliance Controls**:
- specified region restriction (us-west-2, us-east-1 only)
- Mandatory tagging enforcement for data classification
- CloudTrail and KMS key deletion protection
- Audit trail immutability controls

**Session Duration**: 4 hours with mandatory MFA

### 2. Network Administrator Policy (`network-admin.json`)

**Purpose**: Full access to networking services with specified region restrictions and infrastructure protection.

**Key Features**:
- Comprehensive EC2 networking, Transit Gateway, and Network Firewall management
- CloudFront and WAF access for global services
- VPC Flow Logs and network monitoring capabilities
- IAM role management for network-specific roles
- KMS access for network encryption
- Cost optimization and budget monitoring

**UK Compliance Controls**:
- specified region restriction with global service exceptions
- Mandatory tagging for network resources including NetworkTier classification
- Critical network infrastructure deletion protection
- Public access creation restrictions with explicit approval requirements
- Production environment protection controls

**Session Duration**: 4 hours with mandatory MFA

### 3. Developer Policy (`developer.json`)

**Purpose**: Development access with comprehensive guardrails, specified region restrictions, and mandatory security controls.

**Key Features**:
- Compute, storage, database, and application services access
- Lambda, API Gateway, DynamoDB, SQS, SNS, and CloudWatch access
- IAM role management for development-specific roles
- KMS encryption capabilities for development workloads
- Cost monitoring and budget visibility

**UK Compliance Controls**:
- specified region restriction for all development activities
- Production environment access denial
- High-risk action prevention (user management, billing, organizations)
- Mandatory tagging enforcement including Project classification
- Encryption requirements for all data storage
- Public access prevention for S3 buckets
- Non-production resource restrictions

**Session Duration**: 8 hours with MFA for sensitive operations

### 4. Viewer Policy (`viewer.json`)

**Purpose**: Comprehensive read-only access across all services with specified region restrictions.

**Key Features**:
- Read-only access to all AWS services within specified regions
- Global services read access (IAM, Organizations, Route53, CloudFront)
- Cost and billing visibility
- Compliance and security monitoring read access
- Network and database service visibility
- Safe read operations for logs and metrics

**UK Compliance Controls**:
- specified region restriction with global service exceptions
- Write operation denial with comprehensive action blocking
- Safe read operation allowances for operational visibility

**Session Duration**: 8 hours with MFA for sensitive reads

### 5. Break Glass Emergency Policy (`break-glass.json`)

**Purpose**: Emergency access with full permissions, comprehensive auditing, and time-limited access.

**Key Features**:
- Full administrative access with break glass tag requirement
- Emergency justification requirement for high-risk actions
- Comprehensive audit trail protection
- Security controls protection (SecurityHub, GuardDuty, Config)
- KMS key protection for critical infrastructure
- Organization and network infrastructure protection
- Emergency notification capabilities

**UK Compliance Controls**:
- Break glass tag requirement for all actions
- Source IP restrictions to internal networks only
- Time-based access limitations (1-hour token validity)
- specified region restriction with emergency service exceptions
- Comprehensive auditing and notification requirements
- Critical infrastructure deletion protection
- Immutable audit trail enforcement

**Session Duration**: 1 hour with strict MFA requirements (5-minute validity)

## UK Compliance Features

### Data Residency Enforcement
All policies enforce UK data residency through:
- Regional restrictions to us-west-2 and us-east-1
- Global service exceptions for IAM, Organizations, Route53, CloudFront
- Conditional access based on requested regions

### Security Standards Cloud Security Principles Implementation
- **Data Protection in Transit**: TLS enforcement through service configurations
- **Data Protection at Rest**: Mandatory encryption requirements
- **Asset Protection**: Infrastructure deletion protection and backup requirements
- **User Separation**: Role-based access with least privilege principles
- **Governance**: Automated policy enforcement and compliance monitoring
- **Operational Security**: Comprehensive logging and monitoring requirements
- **Personnel Security**: Mandatory MFA and time-limited access

### GDPR Compliance
- **Data Subject Rights**: Macie integration for data discovery and classification
- **Protection by Design**: Default encryption and access control requirements
- **Breach Notification**: Automated security alerting and audit trail protection
- **Data Processing Records**: Comprehensive audit logging requirements
- **Data Minimization**: Automated lifecycle policies and retention controls

### Mandatory Tagging Strategy
All policies enforce mandatory tags:
- **DataClassification**: public, internal, confidential, restricted
- **Environment**: production, non-production, sandbox
- **CostCenter**: Business unit identifier
- **Owner**: Resource owner identification
- **Project**: Project or application identifier
- **NetworkTier**: Network classification (network-admin only)

## Security Hardening Features

### Least Privilege Access
- Granular permissions based on job function requirements
- Resource-based restrictions using tags and conditions
- Time-limited access for sensitive operations
- MFA requirements with varying strictness levels

### Audit Trail Protection
- CloudTrail deletion and modification prevention
- Log group and stream protection
- S3 audit bucket immutability
- KMS key protection for audit encryption

### Infrastructure Protection
- Critical resource deletion prevention
- Production environment isolation
- Network infrastructure safeguards
- Organization structure protection

### Encryption Requirements
- Mandatory encryption for data at rest
- KMS key management with rotation requirements
- Encryption in transit enforcement
- Customer-managed key preferences

## Usage Guidelines

### Policy Assignment
These policies are designed to be used with AWS IAM Identity Center permission sets:
- Assign policies to appropriate permission sets in the IAM Identity Center module
- Configure account assignments based on user roles and responsibilities
- Implement group-based access management for scalability

### Monitoring and Compliance
- Monitor policy violations through CloudTrail and Config
- Set up automated alerts for break glass usage
- Regular access reviews and permission audits
- Compliance reporting through Security Hub and custom dashboards

### Emergency Procedures
- Break glass access requires proper justification and approval
- Emergency access is time-limited and heavily audited
- Incident response procedures should include access review
- Post-incident analysis and policy refinement

## Testing and Validation

### Policy Validation
All policies have been validated for:
- JSON syntax correctness
- IAM policy structure compliance
- Condition logic verification
- Resource ARN format validation

### Compliance Testing
Policies support property-based testing for:
- specified region restriction enforcement
- Mandatory tagging compliance
- Encryption requirement validation
- Audit trail protection verification

## Maintenance and Updates

### Regular Reviews
- Quarterly policy review and updates
- AWS service update integration
- Compliance requirement changes
- Security best practice evolution

### Version Control
- All policy changes tracked in version control
- Change approval process for policy modifications
- Rollback procedures for policy issues
- Documentation updates with policy changes

## Support and Troubleshooting

### Common Issues
- **Access Denied**: Check MFA status and session duration
- **Region Restrictions**: Verify operation is in allowed specified regions
- **Tagging Errors**: Ensure all mandatory tags are present
- **Break Glass Access**: Verify proper tag assignment and justification

### Contact Information
- Security Team: For policy questions and access issues
- Compliance Team: For regulatory requirement clarifications
- Platform Team: For technical implementation support

---

**Last Updated**: December 2024  
**Version**: 1.0  
**Compliance Framework**: Security Standards Cloud Security Principles, GDPR  
**Review Cycle**: Quarterly