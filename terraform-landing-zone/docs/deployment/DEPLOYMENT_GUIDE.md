# UK AWS Secure Landing Zone - Deployment Guide

## Prerequisites

### Required Tools

- **Terraform** >= 1.9.0
- **AWS CLI** >= 2.x
- **Git**
- **jq** (for JSON processing)

### AWS Requirements

1. **AWS Account** - Root account access for initial setup
2. **IAM Permissions** - Administrative access
3. **Email Addresses** - 7 unique email addresses for accounts

## Deployment Phases

### Phase 1: Bootstrap Management Account

```bash
cd environments/management
terraform init -backend-config=backend.hcl
terraform plan
terraform apply
```

### Phase 2: Deploy Security Services

```bash
cd ../security-tooling
terraform init -backend-config=backend.hcl
terraform apply
```

### Phase 3: Configure Logging

```bash
cd ../log-archive
terraform apply
```

### Phase 4: Setup Networking

```bash
cd ../network-hub
terraform apply
```

### Phase 5: Deploy Workload Accounts

```bash
cd ../production-uk
terraform apply

cd ../non-production-uk
terraform apply

cd ../sandbox
terraform apply
```

## Validation

Run compliance checks:
```bash
./scripts/validation/uk-compliance-check.sh
```

## Support

See docs/ for detailed guides and runbooks.
