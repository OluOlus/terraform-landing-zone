# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest (main) | ✅ |
| older releases | ❌ |

We only maintain the `main` branch. Please always use the latest code.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in this landing zone — including misconfigured IAM policies, exposed secrets, insecure defaults, or bypasses of the compliance controls — please report it privately:

1. **Email**: Send details to the repository owner via the email on their [GitHub profile](https://github.com/OluOlus).
2. **GitHub Private Vulnerability Reporting**: Use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) if enabled on this repo.

### What to Include

- A clear description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (Terraform snippet, policy JSON, etc.)
- Which module, environment, or resource is affected
- Your suggested fix (optional but appreciated)

### Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix or mitigation | Within 30 days for critical issues |
| Public disclosure | After a fix is available and merged |

We will credit reporters in the `CHANGELOG.md` unless you prefer to remain anonymous.

---

## Security Controls in This Landing Zone

This repository is itself infrastructure-as-code for a secure AWS environment. The following controls are implemented:

| Control | Implementation |
|---------|---------------|
| Encryption at rest | KMS CMK on all S3, CloudWatch, SNS, Lambda |
| Encryption in transit | TLS enforced via S3 bucket policies |
| Least-privilege IAM | Scoped permission sets; no wildcard resources on destructive actions |
| MFA enforcement | IAM Identity Center with MFA deny policy |
| Audit logging | CloudTrail multi-region, 7-year S3 retention |
| Threat detection | GuardDuty with malware protection and threat intel feeds |
| Compliance monitoring | Security Hub, AWS Config conformance packs |
| Network segmentation | Network Firewall, Transit Gateway, VPC flow logs |
| Automated remediation | Lambda-based response to Security Hub and GuardDuty findings |
| Secret management | No secrets in code; SSM Parameter Store references only |
| Branch protection | Main branch requires PR review and passing CI |

---

## Hardening Checklist for Forks

If you fork this repository for your own organisation, review and complete the following before deploying to production:

- [ ] Replace all `example.com` email addresses in `*.tfvars.example` files
- [ ] Change `organization_name` in management tfvars to your organisation
- [ ] Set `enable_publishing_destination = true` for GuardDuty (already default in this repo)
- [ ] Configure `notification_email` in security-automation variables
- [ ] Review and tighten SCPs in `policies/scps/` for your allowed services
- [ ] Rotate all IAM Identity Center permission sets to match your org's job functions
- [ ] Enable MFA on the management account root user before running bootstrap
- [ ] Review `monthly_budget_limit` in management tfvars
- [ ] Enable AWS Macie if you handle personally identifiable information
- [ ] Pin GitHub Actions workflow action versions after verifying them
