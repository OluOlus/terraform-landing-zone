# AWS Secure Landing Zone

[![Terraform](https://img.shields.io/badge/Terraform-1.9+-623CE4?logo=terraform)](https://www.terraform.io/)
[![AWS](https://img.shields.io/badge/AWS-Landing_Zone-FF9900?logo=amazon-aws)](https://aws.amazon.com/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](.github/CONTRIBUTING.md)

A production-grade, multi-account AWS foundation for organisations that need traceable compliance, hardened networking, and centralised security operations from day one.

## Quick Start for Forks

Fork this repo and run the one-shot setup script to adapt it for your organisation and preferred AWS region:

```bash
git clone https://github.com/YOUR_USERNAME/terraform-landing-zone.git
cd terraform-landing-zone
chmod +x scripts/fork-setup.sh
./scripts/fork-setup.sh
```

The script interactively replaces the `uk-` naming prefix, AWS regions (`eu-west-2` / `eu-west-1`), placeholder email addresses, and GitHub owner references throughout the codebase. Follow the **Next steps** printed at the end to bootstrap remote Terraform state, fill in real AWS account IDs, and deploy environments in dependency order.

See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for the full development workflow, coding standards, and pull request process.

## Overview

This landing zone stands up a complete AWS account hierarchy using Terraform, wiring in security tooling, centralised logging, network segmentation, and compliance controls out of the box. It is built to satisfy GDPR data-residency requirements and widely-used cloud security benchmarks, while remaining fully customisable for teams that need to adapt it to their own regulatory context.

### What's included

- **Threat detection and posture management** — GuardDuty (including S3 protection and malware scanning), Security Hub with multiple compliance packs, and AWS Config continuous recording
- **Encrypted, immutable logging** — organisation-wide CloudTrail, VPC Flow Logs, and a dedicated Log Archive account with configurable long-term retention
- **Segmented networking** — Transit Gateway hub-and-spoke layout, centralised Network Firewall with Suricata rules, and Route 53 Resolver for hybrid DNS
- **Access management** — IAM Identity Center with five predefined permission sets and enforced MFA for all human access
- **Data protection** — KMS keys on annual rotation, S3 versioning with MFA delete, and automated cross-region backups
- **Cost controls** — AWS Budgets with threshold alerts, anomaly detection, and tagging enforcement

## Architecture

### Account layout

```
Management Account (Root)
├── Security Tooling    — GuardDuty delegated admin, Security Hub aggregator, Config aggregator
├── Log Archive         — CloudTrail destination, VPC Flow Logs, long-term retention
├── Network Hub         — Transit Gateway, Network Firewall, Route 53 Resolver
├── Production          — Live workloads
├── Non-Production      — Development and test
└── Sandbox             — Experimentation
```

### Hub-and-spoke network

```
                   ┌─────────────────────┐
                   │   Transit Gateway   │
                   │    (Network Hub)    │
                   └──────────┬──────────┘
                              │
           ┌──────────────────┼──────────────────┐
           │                  │                  │
    ┌──────▼──────┐    ┌──────▼──────┐   ┌──────▼──────┐
    │ Production  │    │Non-Production│   │   Shared    │
    │    VPC      │    │    VPC       │   │  Services   │
    └─────────────┘    └─────────────┘   └─────────────┘
```

See [Architecture Documentation](docs/architecture/README.md) for detailed diagrams and component descriptions.

## Security Controls

### Detection and monitoring

| Component | Role in this deployment |
|-----------|------------------------|
| GuardDuty | Org-wide threat detection — S3 data events, EC2 malware scanning, EKS audit log analysis, delegated to Security account |
| Security Hub | Aggregates findings from GuardDuty, Config, and Inspector; runs CIS, NIST, and AWS Best Practices packs |
| AWS Config | Records every configuration change across all accounts; triggers remediation rules on drift |
| Network Firewall | Stateful traffic inspection at the egress point; blocks known-bad domains and enforces allowlists |
| IAM Identity Center | Single sign-on for all accounts; MFA required; session policies limit blast radius |

### Data protection

- **KMS** — separate keys per service, 365-day automatic rotation, multi-region replication for DR accounts
- **S3** — versioning and MFA delete on all logging buckets; public-access block enforced org-wide via SCP
- **Backup** — AWS Backup plans with cross-region vaults and configurable retention windows
- **Transit encryption** — TLS 1.2 minimum enforced on ALBs and API Gateway via policy

## Compliance Coverage

This deployment is designed around three reference frameworks. Full control mappings are in [COMPLIANCE.md](docs/compliance/COMPLIANCE.md).

### CIS AWS Foundations Benchmark

Controls from all five CIS benchmark sections are implemented:

- **Identity** — MFA enforcement, no long-lived root credentials, password policy via SCP
- **Logging** — CloudTrail enabled org-wide with log file validation, Config enabled in all regions
- **Monitoring** — CloudWatch metric filters and alarms for the benchmark's required event patterns
- **Networking** — default VPCs removed in all accounts, security groups restricted by policy
- **Data protection** — encryption at rest and in transit enforced, key rotation configured

### GDPR

- Data stays in configurable regions — SCPs block resource creation outside the nominated regions
- Encryption at rest and in transit is on by default, not opt-in
- Retention policies are parameterised so they can be tuned to meet your controller/processor obligations
- GuardDuty and Security Hub provide the near-real-time alerting needed for 72-hour breach notification timelines
- Least-privilege access is enforced through IAM Identity Center permission sets, not ad-hoc IAM users

### AWS Security Best Practices

- Centralised egress via Network Firewall with deny-by-default stance
- Config conformance packs continuously validate resource configuration
- Systems Manager Patch Manager handles OS patching for managed instances
- No SSH key pairs — all instance access goes through Session Manager

## Prerequisites and Deployment

### Requirements

- Terraform >= 1.9.0
- AWS CLI v2 with management-account admin credentials
- Seven unique email addresses (one per account)
- `jq` installed locally

### Deployment sequence

```bash
# 1 — Management account (Organizations, Identity Center, SCPs)
cd environments/management
terraform init -backend-config=backend.hcl
terraform apply

# 2 — Security tooling (GuardDuty, Security Hub, Config)
cd ../security
terraform init -backend-config=backend.hcl
terraform apply

# 3 — Logging infrastructure
cd ../logging
terraform apply

# 4 — Networking (Transit Gateway, Firewall, DNS)
cd ../networking
terraform apply

# 5 — Workload accounts
cd ../production
terraform apply
```

See [Deployment Guide](docs/deployment/DEPLOYMENT_GUIDE.md) for the full step-by-step walkthrough.

### Post-deployment validation

```bash
# Check compliance posture
./scripts/validation/compliance-check.sh

# Terraform hygiene
terraform fmt -check -recursive .
terraform validate

# Static security analysis
tfsec .
checkov -d .
```

## Module Reference

### Foundation

- **[management-account](modules/avm-foundation/management-account/)** — AWS Organizations structure, IAM Identity Center configuration, and Service Control Policies
- **[control-tower](modules/avm-foundation/control-tower/)** — Optional AWS Control Tower landing zone and control enablement for teams that want Control Tower to own baseline governance
- **[security-services](modules/security-services/)** — GuardDuty organisation-wide enablement, Security Hub aggregation, Config recorder and delivery channel

### Security

- **[kms](modules/security/kms/)** — KMS key creation with annual rotation and optional multi-region replication
- **[iam](modules/security/iam/)** — IAM roles, policy documents, and the five Identity Center permission sets

### Networking

- **[vpc](modules/networking/vpc/)** — Multi-AZ VPCs with flow log delivery, Interface and Gateway endpoints
- **[transit-gateway](modules/networking/transit-gateway/)** — Centralised TGW with four route tables (prod, non-prod, shared, inspection)
- **[network-firewall](modules/networking/network-firewall/)** — Stateful and stateless rule groups, domain allowlists, Suricata-compatible IDS rules
- **[dns](modules/networking/dns/)** — Route 53 Resolver inbound/outbound endpoints and DNS Firewall rule groups

### Storage and logging

- **[s3](modules/storage/s3/)** — Hardened S3 bucket template — versioning, replication, lifecycle, and access logging pre-wired
- **[backup](modules/management/backup/)** — AWS Backup vaults, plans, and cross-region copy rules
- **[log-archive](modules/logging/log-archive/)** — Centralised log ingestion with configurable retention and KMS encryption

### Management

- **[cloudwatch](modules/management/cloudwatch/)** — Log groups, metric filters, alarms, and a baseline dashboard
- **[cost-management](modules/management/cost-management/)** — Budget resources, anomaly detection monitors, and tagging policies

## CI/CD

All pull requests run automated checks before merge:

| Workflow | Trigger | What it checks |
|----------|---------|----------------|
| [Terraform Validation](.github/workflows/terraform-validate.yml) | PR / push to main | `fmt`, `init`, `validate`, TFLint rules |
| [Security Scan](.github/workflows/security-scan.yml) | PR / push / weekly | TFSec and Checkov — blocks merge on HIGH or CRITICAL findings |
| [PR Plan](.github/workflows/pr-plan.yml) | PR to main | Posts the full `terraform plan` output as a PR comment |

## Disaster Recovery

| Target | Value |
|--------|-------|
| RTO | < 4 hours |
| RPO | < 1 hour |

DR relies on cross-region replication for S3 buckets and KMS keys, automated AWS Backup cross-region vaults, and Terraform state that can be re-applied from source control. Quarterly DR drills are recommended.

## Statistics

- **114 Terraform files** across environments and modules
- **17,000+ lines** of production-ready infrastructure code
- **15 reusable modules** with consistent interfaces
- **9 IAM policy documents** following least-privilege principles
- **6 documentation files** covering architecture, deployment, and operations

## Documentation

- [Architecture](docs/architecture/README.md) — diagrams and component descriptions
- [Deployment Guide](docs/deployment/DEPLOYMENT_GUIDE.md) — step-by-step instructions
- [Compliance](docs/compliance/COMPLIANCE.md) — full CIS, GDPR, and best-practice control mappings
- [Disaster Recovery Runbook](docs/operations/runbooks/disaster-recovery.md)
- [Security Incident Response](docs/operations/runbooks/security-incident-response.md)

Each module also ships its own README. To regenerate a module README after changing variables or outputs:

```bash
terraform-docs markdown . > README.md
```

## Contributing

See [CONTRIBUTING.md](.github/CONTRIBUTING.md). Use the [bug report](.github/ISSUE_TEMPLATE/bug_report.yml) or [feature request](.github/ISSUE_TEMPLATE/feature_request.yml) templates for issues, and [SECURITY.md](.github/SECURITY.md) for privately disclosing vulnerabilities.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
