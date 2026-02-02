# GuardDuty Module - UK Threat Detection
# This module provides comprehensive threat detection for the UK AWS Secure Landing Zone
# with region-specific threat intelligence, cross-region capabilities, and Security Standards compliance

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
      configuration_aliases = [
        aws.alternate,
        aws.disaster_recovery
      ]
    }
  }
}

# Primary GuardDuty detector
resource "aws_guardduty_detector" "main" {
  enable                       = var.enable_detector
  finding_publishing_frequency = var.finding_publishing_frequency

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
    Name                = "uk-guardduty-detector-main"
    DataClassification  = "confidential"
    Environment         = var.environment
    ComplianceFramework = "Security Standards"
    Region              = "primary"
  })
}

# Organization admin account configuration
resource "aws_guardduty_organization_admin_account" "main" {
  count = var.is_delegated_admin ? 1 : 0

  admin_account_id = var.admin_account_id
  depends_on       = [aws_guardduty_detector.main]
}

# Organization-wide GuardDuty configuration
resource "aws_guardduty_organization_configuration" "main" {
  count = var.is_delegated_admin ? 1 : 0

  auto_enable                      = var.auto_enable_organization
  detector_id                      = aws_guardduty_detector.main.id
  auto_enable_organization_members = var.auto_enable_organization_members

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

  depends_on = [aws_guardduty_organization_admin_account.main]
}

# Include detectors module
module "detectors" {
  source = "./detectors"

  # Pass through all relevant variables
  enable_detector                   = var.enable_detector
  finding_publishing_frequency      = var.finding_publishing_frequency
  enable_s3_logs                    = var.enable_s3_logs
  enable_kubernetes_audit_logs      = var.enable_kubernetes_audit_logs
  enable_malware_protection         = var.enable_malware_protection
  is_organization_admin             = var.is_delegated_admin
  organization_admin_account_id     = var.admin_account_id
  auto_enable_organization          = var.auto_enable_organization
  auto_enable_organization_members  = var.auto_enable_organization_members
  auto_enable_s3_logs               = var.auto_enable_s3_logs
  auto_enable_kubernetes_audit_logs = var.auto_enable_kubernetes_audit_logs
  auto_enable_malware_protection    = var.auto_enable_malware_protection
  enable_publishing_destination     = var.enable_publishing_destination
  findings_destination_arn          = var.findings_destination_arn
  findings_kms_key_arn              = var.findings_kms_key_arn
  member_accounts                   = var.member_accounts
  uk_regions                        = var.uk_regions
  environment                       = var.environment
  common_tags                       = var.common_tags
}
