# GuardDuty Detectors - UK Threat Detection Configuration
# This module configures GuardDuty detectors with region-specific threat intelligence
# and cross-region capabilities for comprehensive threat detection

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Primary GuardDuty detector for specified regions
resource "aws_guardduty_detector" "uk_primary" {
  enable                       = var.enable_detector
  finding_publishing_frequency = var.finding_publishing_frequency

  # Enable all data sources for comprehensive threat detection
  datasources {
    s3_logs {
      enable = var.enable_s3_logs
    }
    kubernetes {
      audit_logs {
        enable = var.enable_kubernetes_audit_logs
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = var.enable_malware_protection
        }
      }
    }
  }

  tags = merge(var.common_tags, {
    Name                = "uk-guardduty-detector-primary"
    DataClassification  = "confidential"
    Environment         = var.environment
    ComplianceFramework = "Security Standards"
    Region              = "primary"
  })
}

# Configure GuardDuty organization settings (for Security Tooling Account)
resource "aws_guardduty_organization_admin_account" "uk_admin" {
  count = var.is_organization_admin ? 1 : 0

  admin_account_id = var.organization_admin_account_id
  depends_on       = [aws_guardduty_detector.uk_primary]
}

# Organization-wide GuardDuty configuration
resource "aws_guardduty_organization_configuration" "uk_org" {
  count = var.is_organization_admin ? 1 : 0

  auto_enable                      = var.auto_enable_organization
  detector_id                      = aws_guardduty_detector.uk_primary.id
  auto_enable_organization_members = var.auto_enable_organization_members

  # Enable all data sources organization-wide
  datasources {
    s3_logs {
      auto_enable = var.auto_enable_s3_logs
    }
    kubernetes {
      audit_logs {
        enable = var.auto_enable_kubernetes_audit_logs
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          auto_enable = var.auto_enable_malware_protection
        }
      }
    }
  }

  depends_on = [aws_guardduty_organization_admin_account.uk_admin]
}

# Configure GuardDuty publishing destination for centralized findings
resource "aws_guardduty_publishing_destination" "uk_findings" {
  count = var.enable_publishing_destination ? 1 : 0

  detector_id     = aws_guardduty_detector.uk_primary.id
  destination_arn = var.findings_destination_arn
  kms_key_arn     = var.findings_kms_key_arn

  destination_type = "S3"

  depends_on = [aws_guardduty_detector.uk_primary]
}

# Configure GuardDuty member accounts (for organization setup)
resource "aws_guardduty_member" "uk_members" {
  for_each = var.member_accounts

  account_id                 = each.value.account_id
  detector_id                = aws_guardduty_detector.uk_primary.id
  email                      = each.value.email
  invite                     = each.value.invite
  invitation_message         = "Please accept GuardDuty invitation for UK Landing Zone security monitoring"
  disable_email_notification = each.value.disable_email_notification

  depends_on = [aws_guardduty_detector.uk_primary]
}

# Configure GuardDuty filter for region-specific findings
resource "aws_guardduty_filter" "uk_high_severity" {
  name        = "uk-high-severity-findings"
  action      = "ARCHIVE"
  detector_id = aws_guardduty_detector.uk_primary.id
  rank        = 1

  finding_criteria {
    criterion {
      field  = "severity"
      equals = ["8.0", "8.1", "8.2", "8.3", "8.4", "8.5", "8.6", "8.7", "8.8", "8.9"]
    }

    criterion {
      field      = "region"
      not_equals = var.uk_regions
    }
  }

  tags = merge(var.common_tags, {
    Name    = "uk-high-severity-filter"
    Purpose = "Filter non-specified region high severity findings"
  })
}

# Configure GuardDuty filter for compliance violations
resource "aws_guardduty_filter" "uk_compliance_violations" {
  name        = "uk-compliance-violations"
  action      = "NOOP"
  detector_id = aws_guardduty_detector.uk_primary.id
  rank        = 2

  finding_criteria {
    criterion {
      field = "type"
      equals = [
        "Policy:IAMUser/RootCredentialUsage",
        "UnauthorizedAPICall:IAMUser/InstanceCredentialExfiltration",
        "Stealth:IAMUser/CloudTrailLoggingDisabled",
        "Policy:S3/BucketPublicReadWrite",
        "Policy:S3/BucketPublicWrite"
      ]
    }
  }

  tags = merge(var.common_tags, {
    Name    = "uk-compliance-violations-filter"
    Purpose = "Highlight compliance-related security findings"
  })
}