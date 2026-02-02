# UK AWS Secure Landing Zone - Compliance Documentation

## Compliance Frameworks

### 1. Security Standards Cloud Security Principles

This landing zone implements all 14 Security Standards Cloud Security Principles:

| ID | Principle | Implementation | Evidence |
|----|-----------|----------------|----------|
| 1 | Data in transit protection | TLS 1.2+ for all connections, VPN for on-premises | Network Firewall, Security Groups |
| 2 | Asset protection and resilience | Multi-AZ, cross-region replication, backup | AWS Backup, S3 replication |
| 3 | Separation between users | Multi-account, IAM Identity Center, SCPs | Organizations structure |
| 4 | Governance framework | AWS Organizations, Config, CloudTrail | Audit logs, Config rules |
| 5 | Operational security | GuardDuty, Security Hub, automated patching | Security findings |
| 6 | Personnel security | IAM Identity Center, MFA enforcement | Access logs |
| 7 | Secure development | Git workflows, IaC, automated testing | CI/CD pipelines |
| 8 | Supply chain security | AWS Verified Modules, trusted sources | Module sources |
| 9 | Secure user management | Identity Center, temporary credentials | Session logs |
| 10 | Identity and authentication | Centralized SSO, MFA, password policies | Identity Center config |
| 11 | External interface protection | Network Firewall, WAF, Security Groups | Network logs |
| 12 | Secure service administration | Bastion hosts, Session Manager, break-glass | Admin access logs |
| 13 | Audit information | CloudTrail, VPC Flow Logs, Config | 7-year retention |
| 14 | Secure use of services | SCPs, guardrails, conformance packs | Config compliance |

### 2. GDPR Compliance

#### Data Protection Requirements

- **Encryption at Rest**: KMS with automatic rotation
- **Encryption in Transit**: TLS 1.2+ enforced
- **Data Retention**: 7-year retention for audit logs
- **Data Residency**: specified regions regions only (us-east-1, us-west-2)
- **Access Controls**: Least privilege via IAM Identity Center
- **Audit Trail**: CloudTrail organization trail
- **Breach Notification**: GuardDuty + Security Hub alerts

#### Rights Management

- **Right to Access**: IAM policies for data access
- **Right to Erasure**: S3 lifecycle policies
- **Right to Portability**: Cross-region replication, export APIs
- **Right to Rectification**: Versioning, backup/restore

### 3. Security Essentials

| Control | Implementation | Verification |
|---------|---------------|--------------|
| Boundary Firewalls | Network Firewall, Security Groups, NACLs | Config rules |
| Secure Configuration | AWS Config, conformance packs | Compliance dashboard |
| Access Control | IAM Identity Center, MFA, SCPs | Access logs |
| Malware Protection | GuardDuty malware detection | Security findings |
| Patch Management | Systems Manager Patch Manager | Compliance reports |

## Conformance Packs

### Security Standards Pack

Located: `modules/security-services/config/conformance-packs/ncsc/`

Controls:
- IAM password policy
- MFA on root account
- CloudTrail enabled
- Encryption at rest
- VPC Flow Logs enabled
- S3 bucket public access blocked

### GDPR Pack

Located: `modules/security-services/config/conformance-packs/gdpr/`

Controls:
- KMS key rotation
- S3 versioning enabled
- Access logging enabled
- Data retention policies
- Encryption requirements

### Security Essentials Pack

Located: `modules/security-services/config/conformance-packs/cyber-essentials/`

Controls:
- Security Group restrictions
- IAM access analyzer
- GuardDuty enabled
- Patch compliance
- Password policies

## Audit Evidence

### Continuous Monitoring

1. **AWS Config** - Configuration compliance
   - Real-time compliance status
   - Historical configuration data
   - Automated remediation

2. **Security Hub** - Security posture
   - Consolidated findings
   - Compliance scores
   - Trend analysis

3. **CloudTrail** - API activity
   - Organization-wide trail
   - Log file validation
   - Multi-region coverage

### Compliance Reporting

Generate compliance reports:

```bash
# Config compliance report
aws configservice get-compliance-summary-by-config-rule

# Security Hub standards report
aws securityhub get-compliance-summary

# Custom compliance report
./scripts/reporting/generate-compliance-report.sh
```

## Risk Register

| Risk | Impact | Likelihood | Mitigation | Owner |
|------|--------|-----------|------------|-------|
| Data breach | High | Low | GuardDuty, Security Hub, encryption | Security Team |
| Account compromise | High | Low | MFA, SCPs, break-glass monitoring | Security Team |
| Data loss | High | Low | Backup, versioning, replication | Operations Team |
| Compliance violation | Medium | Low | Config rules, automated monitoring | Compliance Team |
| Service outage | Medium | Medium | Multi-AZ, DR procedures | Operations Team |

## Attestations

### Annual Reviews

- Security control effectiveness review
- Compliance framework alignment review
- Risk assessment update
- DR testing results

### External Audits

- Annual penetration testing
- Third-party compliance audit
- Security Essentials certification renewal

## Contact

- **Compliance Officer**: compliance@company.com
- **Security Team**: security@company.com
- **Data Protection Officer**: dpo@company.com
