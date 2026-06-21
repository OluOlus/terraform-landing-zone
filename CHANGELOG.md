# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CloudWatch Errors alarm for GuardDuty threat intel updater Lambda
- DLQ (dead-letter queue) support for threat intel Lambda via `threat_intel_dlq_arn` variable
- `threat_intel_dlq_arn` and `enable_publishing_destination` variables to GuardDuty module
- Community health files: LICENSE, CONTRIBUTING, SECURITY, issue templates, PR template
- Fork setup script (`scripts/fork-setup.sh`) for adapting to any region/organisation
- Terraform plan workflow for pull requests (`.github/workflows/pr-plan.yml`)
- `.terraform-docs.yml` and `.tflint.hcl` configuration files

### Changed
- GuardDuty `enable_publishing_destination` default changed `false` → `true` for compliance retention
- Log-archive account `enable_security_monitoring` changed `false` → `true`
- GuardDuty threat intel Lambda runtime upgraded `python3.9` → `python3.12`
- Checkov CI: removed `soft_fail: true`; violations now block PRs
- `codeql-action/upload-sarif` pinned to `@v3` (v4 does not exist)
- Terraform module init in CI: replaced `|| true` with subshell to surface init errors
- Removed deprecated `hashicorp/template` provider from `shared/versions.tf`
- Removed unused provider aliases `aws.secondary` and `aws.us_east_1`

### Fixed
- EventBridge `input_template` was using `jsonencode()` which Unicode-escapes `<variable>` placeholders, breaking Lambda event delivery
- `remediation_bucket_arn` was not passed to the remediation module, producing an invalid IAM ARN `"/*"`
- `remediation_dry_run` variable was declared but never wired to Lambda `DRY_RUN` environment variables
- IAM tagging policy conditions hardcoded to US regions (`us-east-1`, `us-west-2`) — corrected to UK regions
- Config remediation SSM document was `AWSConfigRemediation-RemoveUnrestrictedSourceInSecurityGroup` (security group rule removal) instead of the tagging document `AWS-SetRequiredTags`
- All 6 remediation Lambda functions were missing `dead_letter_config`
- Management environment providers pointed to `us-east-1` and `us-west-2` instead of `eu-west-2` and `eu-west-1`
- GuardDuty `enable_publishing_destination` variable duplicated in variables.tf

## [1.0.0] - 2024-01-01

### Added
- Initial release of the AWS Secure Landing Zone
- Multi-account AWS organization structure (management, security, logging, networking, production, non-production, sandbox)
- GuardDuty with S3, Kubernetes audit logs, malware protection, and UK threat intelligence feeds
- Security Hub with NCSC Cloud Security Principles, CIS AWS Foundations, and AWS Foundational Security standards
- AWS Config with conformance packs for Cyber Essentials, NCSC, and UK GDPR
- CloudTrail with multi-region logging and 7-year S3 retention
- KMS encryption for all services with 30-day key deletion window
- Network Firewall with domain-based filtering
- Transit Gateway hub-and-spoke networking
- IAM Identity Center with five permission sets (SecurityAdmin, NetworkAdmin, Developer, ReadOnly, BreakGlass)
- Automated security remediation (S3 public access, unencrypted volumes, untagged resources)
- CI/CD pipeline with CodePipeline, CodeBuild, and GitHub integration
- AWS Backup with cross-region replication
- Cost management with AWS Budgets and anomaly detection
- Comprehensive CloudWatch dashboards, alarms, and SNS notifications
- Pre-commit hooks for Terraform formatting, validation, security scanning
- GitHub Actions for Terraform validation, security scanning, and compliance checking
- Bootstrap script for Terraform state infrastructure
- Deployment guide, architecture documentation, and compliance mapping

[Unreleased]: https://github.com/OluOlus/terraform-landing-zone/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/OluOlus/terraform-landing-zone/releases/tag/v1.0.0
