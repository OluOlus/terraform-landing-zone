# Cross-Region GuardDuty Configuration for UK Landing Zone
# This configuration enables GuardDuty across specified regions with centralized management
# and cross-region finding aggregation for comprehensive threat detection

# Data source for alternate specified region
data "aws_region" "alternate" {
  provider = aws.alternate
}

# GuardDuty detector in alternate specified region (us-west-2 if primary is us-east-1)
resource "aws_guardduty_detector" "uk_alternate" {
  count    = var.enable_cross_region ? 1 : 0
  provider = aws.alternate

  enable                       = true
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
    Name                = "uk-guardduty-detector-alternate"
    DataClassification  = "confidential"
    Environment         = var.environment
    ComplianceFramework = "Security Standards"
    Region              = "alternate"
  })
}

# Cross-region GuardDuty member invitation (from primary to alternate region)
resource "aws_guardduty_member" "cross_region_member" {
  count    = var.enable_cross_region && var.is_organization_admin ? 1 : 0
  provider = aws.alternate

  account_id                 = data.aws_caller_identity.current.account_id
  detector_id                = aws_guardduty_detector.uk_alternate[0].id
  email                      = var.cross_region_member_email
  invite                     = true
  invitation_message         = "Cross-region GuardDuty invitation for UK Landing Zone"
  disable_email_notification = true

  depends_on = [aws_guardduty_detector.uk_alternate]
}

# Cross-region threat intelligence replication
resource "aws_guardduty_threatintelset" "uk_government_threats_alternate" {
  count    = var.enable_cross_region && var.enable_uk_threat_intelligence ? 1 : 0
  provider = aws.alternate

  activate    = true
  detector_id = aws_guardduty_detector.uk_alternate[0].id
  format      = "TXT"
  location    = var.uk_government_threat_list_location_alternate
  name        = "UK-Government-Threat-Intelligence-Alternate"

  tags = merge(var.common_tags, {
    Name                = "uk-government-threat-intel-alternate"
    DataClassification  = "confidential"
    Source              = "UK-Government"
    ComplianceFramework = "Security Standards"
    ThreatIntelType     = "Government"
    Region              = "alternate"
  })
}

# Cross-region Security Standards threat intelligence
resource "aws_guardduty_threatintelset" "ncsc_critical_infrastructure_alternate" {
  count    = var.enable_cross_region && var.enable_ncsc_threat_intelligence ? 1 : 0
  provider = aws.alternate

  activate    = true
  detector_id = aws_guardduty_detector.uk_alternate[0].id
  format      = "TXT"
  location    = var.ncsc_threat_list_location_alternate
  name        = "Security Standards-Critical-Infrastructure-Threats-Alternate"

  tags = merge(var.common_tags, {
    Name                = "ncsc-critical-infrastructure-threats-alternate"
    DataClassification  = "confidential"
    Source              = "Security Standards"
    ComplianceFramework = "Security Standards"
    ThreatIntelType     = "CriticalInfrastructure"
    Region              = "alternate"
  })
}

# Cross-region IP allowlist for UK government networks
resource "aws_guardduty_ipset" "uk_government_allowlist_alternate" {
  count    = var.enable_cross_region && var.enable_uk_government_allowlist ? 1 : 0
  provider = aws.alternate

  activate    = true
  detector_id = aws_guardduty_detector.uk_alternate[0].id
  format      = "TXT"
  location    = var.uk_government_allowlist_location_alternate
  name        = "UK-Government-IP-Allowlist-Alternate"

  tags = merge(var.common_tags, {
    Name                = "uk-government-allowlist-alternate"
    DataClassification  = "internal"
    Source              = "UK-Government"
    ComplianceFramework = "Security Standards"
    ListType            = "Allowlist"
    Region              = "alternate"
  })
}

# Cross-region publishing destination for centralized findings
resource "aws_guardduty_publishing_destination" "uk_findings_alternate" {
  count    = var.enable_cross_region && var.enable_publishing_destination ? 1 : 0
  provider = aws.alternate

  detector_id     = aws_guardduty_detector.uk_alternate[0].id
  destination_arn = var.findings_destination_arn_alternate
  kms_key_arn     = var.findings_kms_key_arn_alternate

  destination_type = "S3"

  depends_on = [aws_guardduty_detector.uk_alternate]
}

# Cross-region GuardDuty filter for high severity findings
resource "aws_guardduty_filter" "uk_high_severity_alternate" {
  count    = var.enable_cross_region ? 1 : 0
  provider = aws.alternate

  name        = "uk-high-severity-findings-alternate"
  action      = "ARCHIVE"
  detector_id = aws_guardduty_detector.uk_alternate[0].id
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
    Name    = "uk-high-severity-filter-alternate"
    Purpose = "Filter non-specified region high severity findings"
    Region  = "alternate"
  })
}

# Cross-region compliance violations filter
resource "aws_guardduty_filter" "uk_compliance_violations_alternate" {
  count    = var.enable_cross_region ? 1 : 0
  provider = aws.alternate

  name        = "uk-compliance-violations-alternate"
  action      = "NOOP"
  detector_id = aws_guardduty_detector.uk_alternate[0].id
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
    Name    = "uk-compliance-violations-filter-alternate"
    Purpose = "Highlight compliance-related security findings"
    Region  = "alternate"
  })
}

# Cross-region findings aggregation (EventBridge rule)
resource "aws_cloudwatch_event_rule" "cross_region_findings" {
  count    = var.enable_cross_region && var.enable_cross_region_aggregation ? 1 : 0
  provider = aws.alternate

  name        = "uk-guardduty-cross-region-findings"
  description = "Aggregate GuardDuty findings across specified regions"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      region = [data.aws_region.alternate.name]
    }
  })

  tags = merge(var.common_tags, {
    Name    = "uk-guardduty-cross-region-findings"
    Purpose = "CrossRegionFindingsAggregation"
    Region  = "alternate"
  })
}

# Cross-region findings aggregation target (SNS topic in primary region)
resource "aws_cloudwatch_event_target" "cross_region_findings_target" {
  count    = var.enable_cross_region && var.enable_cross_region_aggregation ? 1 : 0
  provider = aws.alternate

  rule      = aws_cloudwatch_event_rule.cross_region_findings[0].name
  target_id = "CrossRegionFindingsTarget"
  arn       = var.cross_region_findings_topic_arn

  input_transformer {
    input_paths = {
      account     = "$.detail.accountId"
      region      = "$.detail.region"
      type        = "$.detail.type"
      severity    = "$.detail.severity"
      title       = "$.detail.title"
      description = "$.detail.description"
    }

    input_template = jsonencode({
      source_region = "<region>"
      account_id    = "<account>"
      finding_type  = "<type>"
      severity      = "<severity>"
      title         = "<title>"
      description   = "<description>"
      timestamp     = "$${aws.events.event.ingestion-time}"
    })
  }
}

# Cross-region disaster recovery configuration
resource "aws_guardduty_detector" "uk_dr" {
  count    = var.enable_disaster_recovery ? 1 : 0
  provider = aws.disaster_recovery

  enable                       = false # Disabled by default, enabled during DR
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
    Name                = "uk-guardduty-detector-dr"
    DataClassification  = "confidential"
    Environment         = var.environment
    ComplianceFramework = "Security Standards"
    Region              = "disaster-recovery"
    Purpose             = "DisasterRecovery"
  })
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# Data source for current AWS region
data "aws_region" "current" {}