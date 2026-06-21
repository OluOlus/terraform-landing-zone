# Security Hub Module - UK Compliance Monitoring
# This module provides centralized security monitoring and compliance frameworks
# for the UK AWS Secure Landing Zone

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Enable Security Hub account
resource "aws_securityhub_account" "main" {
  enable_default_standards = var.enable_default_standards
}

# Configure Security Hub as organization admin (for Security Tooling Account)
resource "aws_securityhub_organization_admin_account" "main" {
  count = var.is_delegated_admin ? 1 : 0

  admin_account_id = var.admin_account_id
  depends_on       = [aws_securityhub_account.main]
}

# Configure organization-wide Security Hub settings
resource "aws_securityhub_organization_configuration" "main" {
  count = var.is_delegated_admin ? 1 : 0

  auto_enable           = var.auto_enable_new_accounts
  auto_enable_standards = var.auto_enable_standards

  organization_configuration {
    configuration_type = "CENTRAL"
  }

  depends_on = [aws_securityhub_organization_admin_account.main]
}

# Configure finding aggregation for cross-region findings
resource "aws_securityhub_finding_aggregator" "main" {
  count = var.enable_finding_aggregation ? 1 : 0

  linking_mode      = var.finding_aggregation_linking_mode
  specified_regions = var.finding_aggregation_linking_mode == "SPECIFIED_REGIONS" ? var.finding_aggregation_regions : null

  depends_on = [aws_securityhub_account.main]
}

# Create a master insight for compliance overview
resource "aws_securityhub_insight" "uk_compliance_master" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }

    # Filter for specified regions only
    resource_region {
      comparison = "EQUALS"
      value      = var.aws_region
    }
  }

  group_by_attribute = "ComplianceStatus"
  name               = "UK Landing Zone Compliance Master View"
}

# Create action target for compliance remediation
resource "aws_securityhub_action_target" "uk_compliance_remediation" {
  name        = "UK Compliance"
  identifier  = "ukCompliance"
  description = "Trigger automated remediation for compliance violations across all frameworks"
}
