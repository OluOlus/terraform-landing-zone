# Sandbox Environment Configuration
# Configures the Sandbox Account for experimentation and proof-of-concept work
# Minimal security controls with cost optimization

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

# Alias for disaster recovery
provider "aws" {
  alias  = "disaster_recovery"
  region = "eu-west-1"

  default_tags {
    tags = local.common_tags
  }
}

locals {
  environment = "sandbox"
  project     = "uk-landing-zone"

  common_tags = {
    Environment        = "sandbox"
    Project            = "uk-landing-zone"
    ManagedBy          = "Terraform"
    DataClassification = "internal"
    CostCenter         = "sandbox"
    Owner              = var.owner_email
    Compliance         = "NCSC"
  }
}

# Data Sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# KMS Key for logs (minimal, shared)
module "kms_logs" {
  source = "../../modules/security/kms"

  providers = {
    aws         = aws
    aws.replica = aws.replica
  }

  key_name                     = "sandbox-logs"
  key_alias                    = "sandbox-logs"
  key_description              = "KMS key for sandbox environment logs"
  key_purpose                  = "Sandbox log encryption"
  allow_cloudwatch_logs_access = true
  allow_vpc_flow_logs_access   = true
  enable_key_rotation          = true
  common_tags                  = local.common_tags
}

# VPC for Sandbox Workloads (minimal, cost-optimized)
module "vpc" {
  source = "../../modules/networking/vpc"

  vpc_name              = "sandbox-vpc"
  vpc_cidr              = var.vpc_cidr
  public_subnet_cidrs   = var.public_subnet_cidrs
  private_subnet_cidrs  = var.private_subnet_cidrs
  database_subnet_cidrs = var.database_subnet_cidrs

  # Cost optimization: single NAT gateway
  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_flow_logs     = true
  flow_logs_kms_key_id = module.kms_logs.key_arn

  common_tags = local.common_tags
}

# GuardDuty (minimal for sandbox)
module "guardduty" {
  source = "../../modules/security-services/guardduty"

  providers = {
    aws                   = aws
    aws.alternate         = aws.alternate
    aws.disaster_recovery = aws.disaster_recovery
  }

  enable_detector              = true
  enable_s3_logs               = false # Disabled for cost savings
  enable_kubernetes_audit_logs = false # Disabled for cost savings
  enable_malware_protection    = false # Disabled for cost savings

  finding_publishing_frequency = "SIX_HOURS" # Less frequent

  environment = "sandbox"
  common_tags = local.common_tags
}

# Security Hub (basic only)
module "security_hub" {
  source = "../../modules/security-services/security-hub"

  providers = {
    aws = aws
  }

  aws_region               = "eu-west-2"
  enable_cis_standard      = false # Disabled for sandbox
  enable_default_standards = true
  auto_enable_new_accounts = false

  common_tags = local.common_tags
}

# CloudWatch Monitoring (minimal)
module "cloudwatch" {
  source = "../../modules/management/cloudwatch"

  log_groups = {
    sandbox = {
      name           = "/aws/sandbox/application"
      retention_days = 30 # Short retention for sandbox
      kms_key_id     = module.kms_logs.key_arn
      purpose        = "Sandbox application logs"
    }
  }

  create_sns_topic = true
  sns_topic_name   = "sandbox-alerts"
  sns_kms_key_id   = module.kms_logs.key_arn

  sns_subscriptions = {
    sandbox_team = {
      protocol = "email"
      endpoint = var.sandbox_team_email
    }
  }

  common_tags = local.common_tags
}

# Cost Management (strict limits for sandbox)
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
          threshold                  = 50
          threshold_type             = "PERCENTAGE"
          notification_type          = "ACTUAL"
          subscriber_email_addresses = [var.sandbox_team_email]
          subscriber_sns_topic_arns  = []
        },
        {
          comparison_operator        = "GREATER_THAN"
          threshold                  = 80
          threshold_type             = "PERCENTAGE"
          notification_type          = "ACTUAL"
          subscriber_email_addresses = [var.sandbox_team_email]
          subscriber_sns_topic_arns  = []
        },
        {
          comparison_operator        = "GREATER_THAN"
          threshold                  = 100
          threshold_type             = "PERCENTAGE"
          notification_type          = "ACTUAL"
          subscriber_email_addresses = [var.sandbox_team_email]
          subscriber_sns_topic_arns  = []
        }
      ]
    }
  }

  enable_anomaly_detection       = true
  anomaly_monitor_name           = "sandbox-cost-anomalies"
  anomaly_subscription_frequency = "DAILY" # Daily for sandbox to catch runaway costs
  anomaly_threshold_amount       = 20
  anomaly_subscriber_emails      = [var.sandbox_team_email]

  common_tags = local.common_tags
}

# Monitoring Dashboard (minimal)
module "monitoring" {
  source = "../../modules/management/monitoring"

  environment = local.environment

  enable_security_monitoring   = false # Minimal for sandbox
  enable_compliance_monitoring = false # Minimal for sandbox
  enable_cost_monitoring       = true  # Important for sandbox

  notification_email = var.sandbox_team_email

  tags = local.common_tags
}

# Auto-cleanup for sandbox resources (optional Lambda for resource expiry)
resource "aws_cloudwatch_event_rule" "sandbox_cleanup_reminder" {
  name                = "sandbox-cleanup-reminder"
  description         = "Weekly reminder to clean up sandbox resources"
  schedule_expression = "cron(0 9 ? * MON *)" # Every Monday at 9 AM

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "sandbox_cleanup_sns" {
  rule      = aws_cloudwatch_event_rule.sandbox_cleanup_reminder.name
  target_id = "SendCleanupReminder"
  arn       = module.cloudwatch.sns_topic_arn

  input = jsonencode({
    message = "Weekly Sandbox Cleanup Reminder: Please review and delete unused resources in the sandbox environment to optimize costs."
  })
}
