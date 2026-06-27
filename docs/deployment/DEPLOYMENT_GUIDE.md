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
4. **Control Tower accounts** - If enabling Control Tower, provide existing or vendable Log Archive and Audit/Security account IDs

## Deployment Phases

### Phase 1: Bootstrap Management Account

```bash
cd environments/management
terraform init -backend-config=backend.hcl
terraform plan
terraform apply
```

To enable AWS Control Tower, set these management variables before the Phase 1 plan:

```hcl
enable_control_tower               = true
control_tower_landing_zone_version = "<SUPPORTED_CONTROL_TOWER_VERSION>"
control_tower_log_archive_account_id = "<LOG_ARCHIVE_ACCOUNT_ID>"
control_tower_audit_account_id       = "<AUDIT_ACCOUNT_ID>"
```

When Control Tower is enabled, the management environment skips the custom Organizations OU/SCP module so Control Tower can own baseline OUs and guardrails.

### Phase 2: Deploy Security Services

```bash
cd ../security
terraform init -backend-config=backend.hcl
terraform apply
```

### Phase 3: Configure Logging

```bash
cd ../logging
terraform apply
```

### Phase 4: Setup Networking

```bash
cd ../networking
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
