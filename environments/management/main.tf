# Management Environment Configuration
# Configures the Management Account with Organizations, Identity Center, and centralized services

terraform {
  required_version = "~> 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    # Backend configuration should be provided via backend config file
    # terraform init -backend-config=backend.hcl
  }
}

# Primary Provider (uk-west-2 - London)
provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = local.common_tags
  }
}

# Replica Provider (us-west-2 - Ireland) for DR
provider "aws" {
  alias  = "replica"
  region = "us-west-2"

  default_tags {
    tags = local.common_tags
  }
}

# Local Variables
locals {
  environment = "management"
  project     = "uk-landing-zone"

  common_tags = {
    Environment        = "management"
    Project            = "uk-landing-zone"
    ManagedBy          = "Terraform"
    DataClassification = "confidential"
    CostCenter         = "infrastructure"
    Owner              = var.owner_email
    Compliance         = "Security Standards-UK-GDPR"
  }
}

# Data Sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Management Account Module
module "management_account" {
  source = "../../modules/avm-foundation/management-account"

  organization_name = var.organization_name
  common_tags       = local.common_tags
}

# Organization Module
module "organization" {
  source = "../../modules/avm-foundation/organization"

  organization_id = module.management_account.organization_id
  common_tags     = local.common_tags
}

# IAM Identity Center
module "identity_center" {
  source = "../../modules/avm-foundation/iam-identity-center"

  enable_break_glass_monitoring = true
  alarm_sns_topic_arns          = [module.cloudwatch.sns_topic_arn]
  common_tags                   = local.common_tags
}

# KMS Keys for Management Account
module "kms_cloudtrail" {
  source = "../../modules/security/kms"

  key_name                = "cloudtrail-management"
  key_alias               = "cloudtrail-management"
  key_description         = "KMS key for CloudTrail encryption in management account"
  key_purpose             = "CloudTrail log encryption"
  allow_cloudtrail_access = true
  organization_id         = module.management_account.organization_id
  enable_key_rotation     = true
  deletion_window_in_days = 30
  enable_key_monitoring   = true
  alarm_sns_topic_arns    = [module.cloudwatch.sns_topic_arn]
  common_tags             = local.common_tags
}

module "kms_logs" {
  source = "../../modules/security/kms"

  key_name                     = "cloudwatch-logs-management"
  key_alias                    = "cloudwatch-logs-management"
  key_description              = "KMS key for CloudWatch Logs encryption"
  key_purpose                  = "CloudWatch Logs encryption"
  allow_cloudwatch_logs_access = true
  organization_id              = module.management_account.organization_id
  enable_key_rotation          = true
  deletion_window_in_days      = 30
  common_tags                  = local.common_tags
}

# CloudWatch Monitoring
module "cloudwatch" {
  source = "../../modules/management/cloudwatch"

  log_groups = {
    cloudtrail = {
      name           = "/aws/cloudtrail/management"
      retention_days = 2555 # 7 years
      kms_key_id     = module.kms_logs.key_arn
      purpose        = "CloudTrail logs for management account"
    }
    organizations = {
      name           = "/aws/organizations/management"
      retention_days = 2555
      kms_key_id     = module.kms_logs.key_arn
      purpose        = "AWS Organizations logs"
    }
  }

  create_sns_topic = true
  sns_topic_name   = "management-cloudwatch-alarms"
  sns_kms_key_id   = module.kms_logs.key_arn

  sns_subscriptions = {
    ops_team = {
      protocol = "email"
      endpoint = var.ops_team_email
    }
  }

  common_tags = local.common_tags
}

# Cost Management
module "cost_management" {
  source = "../../modules/management/cost-management"

  budgets = {
    monthly_total = {
      budget_type       = "COST"
      limit_amount      = var.monthly_budget_limit
      limit_unit        = "USD"
      time_unit         = "MONTHLY"
      time_period_start = "2026-02-01_00:00"
      time_period_end   = null
      cost_filters      = {}
      notifications = [
        {
          comparison_operator        = "GREATER_THAN"
          threshold                  = 80
          threshold_type             = "PERCENTAGE"
          notification_type          = "ACTUAL"
          subscriber_email_addresses = [var.ops_team_email]
          subscriber_sns_topic_arns  = []
        },
        {
          comparison_operator        = "GREATER_THAN"
          threshold                  = 100
          threshold_type             = "PERCENTAGE"
          notification_type          = "ACTUAL"
          subscriber_email_addresses = [var.ops_team_email]
          subscriber_sns_topic_arns  = []
        }
      ]
    }
  }

  enable_anomaly_detection       = true
  anomaly_monitor_name           = "management-cost-anomalies"
  anomaly_subscription_frequency = "DAILY"
  anomaly_threshold_amount       = 100
  anomaly_subscriber_emails      = [var.ops_team_email]

  common_tags = local.common_tags
}
