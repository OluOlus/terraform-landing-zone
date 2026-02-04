# Security Environment Configuration
# Configures the Security Tooling Account with Security Hub, GuardDuty, Config, and security automation

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    # Backend configuration via backend config file
  }
}

# Primary Provider (eu-west-2 - London)
provider "aws" {
  region = "eu-west-2"

  default_tags {
    tags = local.common_tags
  }
}

# Replica Provider (eu-west-1 - Ireland) for cross-region
provider "aws" {
  alias  = "replica"
  region = "eu-west-1"

  default_tags {
    tags = local.common_tags
  }
}

# Alias for alternate region (same as replica)
provider "aws" {
  alias  = "alternate"
  region = "eu-west-1"

  default_tags {
    tags = local.common_tags
  }
}

# Alias for disaster recovery (same as replica for UK)
provider "aws" {
  alias  = "disaster_recovery"
  region = "eu-west-1"

  default_tags {
    tags = local.common_tags
  }
}

locals {
  environment = "security"
  project     = "uk-landing-zone"

  common_tags = {
    Environment        = "security"
    Project            = "uk-landing-zone"
    ManagedBy          = "Terraform"
    DataClassification = "restricted"
    CostCenter         = "security-operations"
    Owner              = var.owner_email
    Compliance         = "NCSC-UK-GDPR-CyberEssentials"
  }
}

# Data Sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# KMS Key for Security Services
module "kms_security" {
  source = "../../modules/security/kms"

  providers = {
    aws         = aws
    aws.replica = aws.replica
  }

  key_name            = "security-services"
  key_alias           = "security-services"
  key_description     = "KMS key for security services encryption"
  key_purpose         = "Security services encryption"
  enable_key_rotation = true
  common_tags         = local.common_tags
}

module "kms_logs" {
  source = "../../modules/security/kms"

  providers = {
    aws         = aws
    aws.replica = aws.replica
  }

  key_name                     = "security-logs"
  key_alias                    = "security-logs"
  key_description              = "KMS key for security log encryption"
  key_purpose                  = "Security log encryption"
  allow_cloudwatch_logs_access = true
  enable_key_rotation          = true
  common_tags                  = local.common_tags
}

# Security Hub - Delegated Administrator
module "security_hub" {
  source = "../../modules/security-services/security-hub"

  providers = {
    aws = aws
  }

  aws_region                       = "eu-west-2"
  is_delegated_admin               = true
  admin_account_id                 = data.aws_caller_identity.current.account_id
  enable_cis_standard              = true
  enable_default_standards         = true
  auto_enable_new_accounts         = true
  auto_enable_standards            = "DEFAULT"
  enable_finding_aggregation       = true
  finding_aggregation_linking_mode = "SPECIFIED_REGIONS"
  finding_aggregation_regions      = ["eu-west-1", "eu-west-2"]

  common_tags = local.common_tags
}

# GuardDuty - Delegated Administrator
module "guardduty" {
  source = "../../modules/security-services/guardduty"

  providers = {
    aws                   = aws
    aws.alternate         = aws.alternate
    aws.disaster_recovery = aws.disaster_recovery
  }

  enable_detector              = true
  enable_s3_logs               = true
  enable_kubernetes_audit_logs = true
  enable_malware_protection    = true

  finding_publishing_frequency = "FIFTEEN_MINUTES"

  # Delegated admin settings
  is_delegated_admin                = true
  admin_account_id                  = data.aws_caller_identity.current.account_id
  auto_enable_organization_members  = "ALL"
  auto_enable_s3_logs               = true
  auto_enable_kubernetes_audit_logs = true
  auto_enable_malware_protection    = true

  # UK threat intelligence
  enable_uk_threat_intelligence   = true
  enable_ncsc_threat_intelligence = true

  # Cross-region settings
  enable_cross_region = true
  uk_regions          = ["eu-west-1", "eu-west-2"]

  environment = "production"
  common_tags = local.common_tags
}

# IAM Role for AWS Config
resource "aws_iam_role" "config_role" {
  name = "uk-config-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_s3_policy" {
  name = "config-s3-delivery"
  role = aws_iam_role.config_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = "arn:aws:s3:::${var.config_s3_bucket_name}/*"
        Condition = {
          StringLike = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws:s3:::${var.config_s3_bucket_name}"
      }
    ]
  })
}

# AWS Config - Delegated Administrator
module "config" {
  source = "../../modules/security-services/config"

  enable_config_recorder  = true
  config_recorder_name    = "uk-security-config-recorder"
  config_service_role_arn = aws_iam_role.config_role.arn

  # Delivery channel
  config_s3_bucket_name = var.config_s3_bucket_name
  config_s3_key_prefix  = "config"

  # Organization aggregator
  aggregator_name    = "uk-landing-zone-aggregator"
  is_delegated_admin = true

  # Enable UK compliance conformance packs
  enable_ncsc_pack             = true
  enable_gdpr_pack             = true
  enable_cyber_essentials_pack = true

  # UK-specific rules
  enable_uk_data_residency_rule    = true
  enable_uk_mandatory_tagging_rule = true

  common_tags = local.common_tags
}

# Security Automation - Auto-remediation
module "security_automation" {
  source = "../../modules/security-services/security-automation"

  aws_region = "eu-west-2"

  # Remediation settings
  enable_s3_public_access_remediation    = true
  enable_unencrypted_volumes_remediation = true
  enable_untagged_resources_remediation  = true

  # Severity levels
  remediation_severity_levels      = ["HIGH", "CRITICAL"]
  guardduty_remediation_severities = [7.0, 8.0, 9.0, 10.0]

  # Notifications
  notification_email = var.security_team_email

  # Compliance modes
  ncsc_compliance_mode             = true
  uk_gdpr_compliance_mode          = true
  cyber_essentials_compliance_mode = true

  # Safety settings
  remediation_dry_run    = !var.enable_auto_remediation
  enable_manual_approval = true

  common_tags = local.common_tags
}

# CloudWatch for Security Monitoring
module "cloudwatch" {
  source = "../../modules/management/cloudwatch"

  log_groups = {
    security_hub = {
      name           = "/aws/securityhub/findings"
      retention_days = 2555 # 7 years
      kms_key_id     = module.kms_logs.key_arn
      purpose        = "Security Hub findings"
    }
    guardduty = {
      name           = "/aws/guardduty/findings"
      retention_days = 2555
      kms_key_id     = module.kms_logs.key_arn
      purpose        = "GuardDuty findings"
    }
    config = {
      name           = "/aws/config/compliance"
      retention_days = 2555
      kms_key_id     = module.kms_logs.key_arn
      purpose        = "AWS Config compliance logs"
    }
  }

  create_sns_topic = true
  sns_topic_name   = "security-alerts"
  sns_kms_key_id   = module.kms_logs.key_arn

  sns_subscriptions = {
    security_team = {
      protocol = "email"
      endpoint = var.security_team_email
    }
  }

  common_tags = local.common_tags
}

# Security Monitoring Dashboard
module "monitoring" {
  source = "../../modules/management/monitoring"

  environment = local.environment

  enable_security_monitoring   = true
  enable_compliance_monitoring = true
  enable_cost_monitoring       = false

  notification_email = var.security_team_email

  alarm_threshold_critical_findings  = 1
  alarm_threshold_guardduty_findings = 0

  tags = local.common_tags
}

# IAM Access Analyzer
resource "aws_accessanalyzer_analyzer" "organization" {
  analyzer_name = "uk-landing-zone-analyzer"
  type          = "ORGANIZATION"

  tags = local.common_tags
}

# EventBridge Rules for Security Events
resource "aws_cloudwatch_event_rule" "security_hub_findings" {
  name        = "capture-security-hub-findings"
  description = "Capture Security Hub findings for alerting"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["CRITICAL", "HIGH"]
        }
      }
    }
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "security_hub_to_sns" {
  rule      = aws_cloudwatch_event_rule.security_hub_findings.name
  target_id = "SendToSNS"
  arn       = module.cloudwatch.sns_topic_arn
}

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "capture-guardduty-findings"
  description = "Capture GuardDuty findings for alerting"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
    }
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "guardduty_to_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "SendToSNS"
  arn       = module.cloudwatch.sns_topic_arn
}
