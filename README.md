# AWS Secure Landing Zone

[![Terraform](https://img.shields.io/badge/Terraform-1.9+-623CE4?logo=terraform)](https://www.terraform.io/)
[![AWS](https://img.shields.io/badge/AWS-Landing_Zone-FF9900?logo=amazon-aws)](https://aws.amazon.com/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A production-ready, multi-account AWS environment designed for organizations requiring compliance with industry security standards and regulatory frameworks.

## Overview

This landing zone provides a complete AWS foundation implementing comprehensive cloud security principles, GDPR requirements, and security best practices. Built with Infrastructure as Code (Terraform), it delivers a secure, compliant, and scalable multi-account architecture with centralized security monitoring, logging, and networking.

### Key Highlights

- **Security First**: GuardDuty, Security Hub, Config, Network Firewall, KMS encryption
- **Compliance Ready**: Industry security standards, GDPR, regulatory frameworks fully implemented
- **Production Ready**: 17,000+ lines of Terraform, 15 modules, comprehensive testing
- **Multi-Region**: Configurable regions with cross-region disaster recovery
- **Automation**: Full IaC deployment, CI/CD workflows, automated compliance monitoring
- **Observability**: Centralized CloudWatch, configurable retention, real-time alerting

## Architecture

### Multi-Account Structure

```
Management Account (Root)
├── Security Tooling Account    - GuardDuty, Security Hub, Config aggregation
├── Log Archive Account          - CloudTrail, VPC Flow Logs, 7-year retention
├── Network Hub Account          - Transit Gateway, Network Firewall, DNS
├── Production Account           - Production workloads
├── Non-Production Account    - Development and testing
└── Sandbox Account              - Experimentation and learning
```

### Hub-and-Spoke Network Design

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

See [Architecture Documentation](docs/architecture/README.md) for detailed diagrams and component descriptions.

## Features

### Security Services

| Service | Purpose | Implementation |
|---------|---------|----------------|
| **GuardDuty** | Threat detection | S3 protection, malware detection, K8s audit logs |
| **Security Hub** | Security posture | CIS, GDPR, Security Best Practices packs |
| **AWS Config** | Configuration compliance | Continuous recording, automated remediation |
| **Network Firewall** | Traffic inspection | Suricata IDS/IPS, domain filtering |
| **IAM Identity Center** | Centralized SSO | 5 permission sets, MFA enforcement |

### Data Protection

- **KMS Encryption**: Automatic 365-day key rotation, multi-region replication
- **S3 Security**: Versioning, MFA delete, public access blocking, cross-region replication
- **AWS Backup**: Automated schedules, 7-year retention, cross-region backup
- **Log Archive**: Configurable CloudTrail retention for compliance requirements

### Networking

- **Transit Gateway**: Hub-and-spoke architecture with 4 dedicated route tables
- **Network Firewall**: Centralized traffic inspection with Suricata rules
- **Route53 Resolver**: Hybrid DNS with inbound/outbound endpoints
- **VPC Design**: Multi-AZ, public/private/database tiers, VPC endpoints

### Monitoring & Operations

- **CloudWatch**: Centralized logging with KMS encryption, 7-year retention
- **CloudTrail**: Organization-wide trail, log file validation, multi-region
- **VPC Flow Logs**: All VPCs monitored, centralized storage
- **Cost Management**: Budgets, anomaly detection, usage reports

## Compliance Frameworks

### CIS AWS Foundations Benchmark

| ID | Control | Implementation |
|----|---------|----------------|
| 1 | Identity and Access Management | IAM Identity Center, MFA, SCPs |
| 2 | Logging | CloudTrail, VPC Flow Logs, Config |
| 3 | Monitoring | GuardDuty, Security Hub, CloudWatch |
| 4 | Networking | VPC isolation, Network Firewall, Security Groups |
| 5 | Data Protection | KMS encryption, S3 versioning, backup |
| ... | | See [COMPLIANCE.md](docs/compliance/COMPLIANCE.md) for full mapping |

### GDPR Compliance

- **Encryption**: KMS at rest (365-day rotation), TLS 1.2+ in transit
- **Data Retention**: Configurable retention policies
- **Data Residency**: Configurable region restrictions via SCPs
- **Access Controls**: Least privilege via IAM Identity Center
- **Breach Notification**: GuardDuty + Security Hub real-time alerts

### AWS Security Best Practices

- **Boundary Firewalls**: Network Firewall, Security Groups, NACLs
- **Secure Configuration**: AWS Config with conformance packs
- **Access Control**: IAM Identity Center, MFA, password policies
- **Malware Protection**: GuardDuty malware detection
- **Patch Management**: Systems Manager Patch Manager

## Quick Start

### Prerequisites

- **Terraform** >= 1.9.0
- **AWS CLI** >= 2.x with administrative credentials
- **Git** for version control
- **7 unique email addresses** for AWS accounts
- **jq** for JSON processing

### Deployment Phases

```bash
# Phase 1: Bootstrap Management Account
cd environments/management
terraform init -backend-config=backend.hcl
terraform plan
terraform apply

# Phase 2: Deploy Security Services
cd ../security
terraform init -backend-config=backend.hcl
terraform apply

# Phase 3: Configure Logging
cd ../logging
terraform apply

# Phase 4: Setup Networking
cd ../networking
terraform apply

# Phase 5: Deploy Workload Accounts
cd ../production
terraform apply
```

See [Deployment Guide](docs/deployment/DEPLOYMENT_GUIDE.md) for detailed step-by-step instructions.

### Validation

Run compliance checks after deployment:

```bash
# Compliance validation
./scripts/validation/compliance-check.sh

# Terraform validation
terraform fmt -check -recursive .
terraform validate

# Security scan
tfsec .
checkov -d .
```

## Module Overview

### Foundation Modules

- **[management-account](modules/avm-foundation/management-account/)** - AWS Organizations, IAM Identity Center, SCPs
- **[security-services](modules/security-services/)** - GuardDuty, Security Hub, Config with compliance packs

### Security Modules

- **[kms](modules/security/kms/)** - KMS encryption keys with 365-day rotation, multi-region support
- **[iam](modules/security/iam/)** - IAM roles, policies, 5 permission sets with MFA

### Networking Modules

- **[vpc](modules/networking/vpc/)** - Multi-AZ VPCs with flow logs, VPC endpoints
- **[transit-gateway](modules/networking/transit-gateway/)** - Hub-and-spoke with 4 route tables
- **[network-firewall](modules/networking/network-firewall/)** - Centralized traffic inspection
- **[dns](modules/networking/dns/)** - Route53 Resolver with DNS Firewall

### Storage & Data Modules

- **[s3](modules/storage/s3/)** - Secure S3 buckets with versioning, replication, lifecycle
- **[backup](modules/management/backup/)** - AWS Backup with cross-region replication
- **[log-archive](modules/logging/log-archive/)** - Centralized logging with 7-year retention

### Management Modules

- **[cloudwatch](modules/management/cloudwatch/)** - Centralized monitoring and alerting
- **[cost-management](modules/management/cost-management/)** - Budgets, anomaly detection

## CI/CD Workflows

Automated validation and security scanning via GitHub Actions:

- **[Terraform Validation](.github/workflows/terraform-validate.yml)** - Format, init, validate, TFLint
- **[Security Scan](.github/workflows/security-scan.yml)** - TFSec, Checkov compliance scanning

Workflows run on:
- Every pull request to main
- Every push to main
- Weekly security scans (Sunday)

## Project Statistics

- **114 Terraform Files** - Comprehensive infrastructure coverage
- **17,000+ Lines of Code** - Production-ready implementation
- **15 Modules** - Reusable, tested components
- **9 IAM Policies** - Least privilege access controls
- **6 Documentation Files** - Complete operational guides

## Documentation

### Core Documentation

- **[Architecture](docs/architecture/README.md)** - Detailed architecture diagrams and component descriptions
- **[Deployment Guide](docs/deployment/DEPLOYMENT_GUIDE.md)** - Step-by-step deployment instructions
- **[Compliance](docs/compliance/COMPLIANCE.md)** - CIS, GDPR, Security Best Practices mappings
- **[Operations](docs/operations/)** - Runbooks and operational procedures (coming soon)
- **[Troubleshooting](docs/troubleshooting/)** - Common issues and solutions (coming soon)

### Module Documentation

Each module includes comprehensive README with:
- Usage examples
- Input variables reference
- Output values
- Dependencies and requirements

## Disaster Recovery

- **RTO**: < 4 hours
- **RPO**: < 1 hour
- **Multi-region**: Configurable primary and DR regions
- **Backup Strategy**: Automated cross-region replication
- **Testing**: Quarterly DR drills recommended

## Security

### Reporting Security Issues

Please report security vulnerabilities to: security@company.com

### Security Features

- All data encrypted at rest (KMS) and in transit (TLS 1.2+)
- MFA enforcement for all human access
- Automated threat detection with GuardDuty
- Real-time security alerts via Security Hub
- Continuous compliance monitoring with AWS Config
- Network traffic inspection with Network Firewall
- 7-year audit trail retention

## Cost Management

Estimated monthly costs (varies by usage):

- **Management Account**: £150-200/month
- **Security Tooling**: £200-300/month
- **Log Archive**: £100-150/month
- **Network Hub**: £250-350/month
- **Production Workload**: £500-1000/month (application dependent)
- **Total Baseline**: £1,200-2,000/month

Cost controls included:
- AWS Budgets with alerts at 80% and 100%
- Cost Anomaly Detection
- Resource tagging enforcement
- Right-sizing recommendations

## Support & Contact

- **Compliance Officer**: compliance@company.com
- **Security Team**: security@company.com
- **Data Protection Officer**: dpo@company.com

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Acknowledgments

Built with:
- [AWS Verified Modules](https://registry.terraform.io/namespaces/aws-ia)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest)
- CIS AWS Foundations Benchmark
- AWS Security Best Practices
- Industry compliance frameworks

---
