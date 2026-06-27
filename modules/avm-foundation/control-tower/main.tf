# AWS Control Tower Landing Zone Module
# Creates an optional AWS Control Tower managed landing zone from the management account.

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  landing_zone_manifest = {
    governedRegions       = var.governed_regions
    organizationStructure = var.organization_structure

    centralizedLogging = {
      accountId = var.log_archive_account_id
      enabled   = var.enable_centralized_logging
      configurations = {
        loggingBucket = {
          retentionDays = var.logging_bucket_retention_days
        }
        accessLoggingBucket = {
          retentionDays = var.access_logging_bucket_retention_days
        }
      }
    }

    securityRoles = {
      accountId = var.audit_account_id
    }

    accessManagement = {
      enabled = var.enable_iam_identity_center
    }
  }
}

resource "aws_controltower_landing_zone" "this" {
  count = var.enabled ? 1 : 0

  version           = var.landing_zone_version
  manifest_json     = jsonencode(local.landing_zone_manifest)
  remediation_types = var.remediation_types

  tags = merge(var.common_tags, {
    ManagedBy = "AWS-Control-Tower"
    Purpose   = "Landing Zone Governance"
  })
}

resource "aws_controltower_control" "this" {
  for_each = var.enabled ? var.enabled_controls : {}

  control_identifier = each.value.control_identifier
  target_identifier  = each.value.target_identifier

  dynamic "parameters" {
    for_each = each.value.parameters

    content {
      key   = parameters.key
      value = parameters.value
    }
  }

  depends_on = [aws_controltower_landing_zone.this]
}
