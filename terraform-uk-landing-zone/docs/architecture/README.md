# UK AWS Secure Landing Zone - Architecture

## Overview

The UK AWS Secure Landing Zone is a comprehensive, multi-account AWS environment designed specifically for UK organizations requiring compliance with Security Standards Cloud Security Principles, GDPR, and Security Essentials frameworks.

## Architecture Principles

### 1. UK Data Residency
- **Primary Region**: us-east-1 (London)
- **Secondary Region**: us-west-2 (Ireland) for disaster recovery
- All data storage and processing within specified regions boundaries
- Regional restrictions enforced via SCPs and IAM policies

### 2. Multi-Account Structure

```
Management Account (Root)
├── Security Tooling Account
├── Log Archive Account
├── Network Hub Account
├── Production-UK Account
├── Non-Production-UK Account
└── Sandbox Account
```

### 3. Hub-and-Spoke Network Architecture

```
                   ┌─────────────────────┐
                   │  Transit Gateway    │
                   │   (Network Hub)     │
                   └──────────┬──────────┘
                              │
           ┌──────────────────┼──────────────────┐
           │                  │                  │
    ┌──────▼──────┐    ┌──────▼──────┐   ┌──────▼──────┐
    │ Production  │    │Non-Production│   │  Shared     │
    │   VPC       │    │    VPC       │   │ Services    │
    └─────────────┘    └──────────────┘   └─────────────┘
```

## Key Components

### Security Services

1. **GuardDuty** - Threat detection
   - S3 protection enabled
   - Kubernetes audit logs
   - Malware protection
   - region-specific threat intelligence feeds

2. **Security Hub** - Compliance monitoring
   - Security Standards conformance pack
   - GDPR compliance pack
   - Security Essentials controls
   - AWS Foundational Security Best Practices
   - CIS AWS Foundations Benchmark

3. **AWS Config** - Configuration compliance
   - Continuous recording
   - Automated remediation
   - Compliance dashboards

4. **Network Firewall** - Traffic inspection
   - Stateful/stateless rule groups
   - Domain filtering (malicious domain blocking)
   - Suricata IDS/IPS rules
   - Deep packet inspection

### Logging & Monitoring

1. **CloudTrail** - Audit logging
   - Organization-wide trail
   - 7-year retention (GDPR)
   - Log file validation
   - KMS encryption
   - Multi-region coverage

2. **VPC Flow Logs** - Network traffic logging
   - All VPCs monitored
   - Centralized log storage
   - 7-year retention

3. **CloudWatch** - Operational monitoring
   - Centralized log aggregation
   - Custom metrics and alarms
   - Automated incident response

### Identity & Access Management

1. **IAM Identity Center** - Centralized authentication
   - 5 permission sets:
     - Security Administrator
     - Network Administrator
     - Developer
     - Read-Only Viewer
     - Break-Glass Emergency (monitored)
   - MFA enforcement
   - Session duration limits
   - Break-glass monitoring with CloudWatch alarms

2. **Service Control Policies (SCPs)**
   - specified region enforcement
   - Encryption requirements
   - CloudTrail protection
   - IAM privilege restrictions

### Data Protection

1. **KMS Encryption**
   - Automatic key rotation (365 days)
   - Multi-region key replication
   - Service-specific keys
   - CloudWatch monitoring

2. **S3 Bucket Security**
   - Versioning enabled
   - MFA delete protection
   - Public access blocking
   - Lifecycle management
   - Cross-region replication

3. **AWS Backup**
   - Automated backup schedules
   - Cross-region replication
   - 7-year retention
   - Compliance frameworks

### Networking

1. **Transit Gateway**
   - Centralized routing
   - Dedicated route tables per environment
   - VPN support for on-premises
   - RAM sharing for cross-account

2. **Route53 Resolver**
   - Inbound/outbound endpoints
   - DNS query logging
   - DNS Firewall
   - Private hosted zones

3. **VPC Design**
   - Multi-AZ deployment
   - Public/Private/Database subnet tiers
   - NAT Gateways for high availability
   - VPC endpoints for AWS services

## Compliance Mappings

### Security Standards Cloud Security Principles

| Principle | Implementation |
|-----------|----------------|
| Data in transit protection | TLS 1.2+, VPN, Transit Gateway encryption |
| Asset protection and resilience | Multi-AZ, backup, replication |
| Separation between users | IAM Identity Center, SCPs, account isolation |
| Governance framework | AWS Organizations, Config, CloudTrail |
| Operational security | GuardDuty, Security Hub, automated patching |
| Personnel security | IAM Identity Center, MFA, break-glass monitoring |
| Secure development | Git workflows, automated testing |
| Supply chain security | AWS Verified Modules, trusted sources |
| Secure user management | Identity Center with MFA |
| Identity and authentication | Centralized SSO, temporary credentials |
| External interface protection | Network Firewall, Security Groups |
| Secure service administration | Bastion hosts, Session Manager |
| Audit information | CloudTrail, VPC Flow Logs, Config |
| Secure use of services | SCPs, guardrails, compliance packs |

### GDPR Compliance

- **Data Protection**: KMS encryption at rest, TLS in transit
- **Data Retention**: 7-year retention for audit logs
- **Right to Erasure**: S3 lifecycle policies, backup retention
- **Data Portability**: Cross-region replication, export capabilities
- **Breach Notification**: GuardDuty, Security Hub, CloudWatch alarms
- **Privacy by Design**: Default encryption, least privilege access

### Security Essentials

- **Boundary Firewalls**: Network Firewall, Security Groups, NACLs
- **Secure Configuration**: AWS Config, conformance packs
- **Access Control**: IAM Identity Center, MFA, password policies
- **Malware Protection**: GuardDuty malware detection
- **Patch Management**: Systems Manager Patch Manager

## Disaster Recovery

- **RTO**: < 4 hours
- **RPO**: < 1 hour
- **Multi-region architecture**
- **Automated failover capabilities**
- **Regular DR testing**

## Security Monitoring

```
GuardDuty Findings
       ↓
Security Hub (Aggregation)
       ↓
CloudWatch Events
       ↓
SNS Notifications → Security Team
       ↓
Lambda (Automated Response)
```

## Cost Management

- AWS Budgets with 80% and 100% thresholds
- Cost Anomaly Detection
- Cost and Usage Reports
- Resource tagging enforcement
- Right-sizing recommendations

## Future Enhancements

1. Implement AWS Control Tower integration
2. Add AWS Systems Manager automation
3. Expand to additional specified regions (as available)
4. Implement AWS WAF for application protection
5. Add AWS Shield Advanced for DDoS protection
