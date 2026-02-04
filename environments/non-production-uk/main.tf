# Non-Production UK Environment Configuration
# Configures the Non-Production Account for development and testing workloads

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
  environment = "non-production"
  project     = "uk-landing-zone"

  common_tags = {
    Environment        = "non-production"
    Project            = "uk-landing-zone"
    ManagedBy          = "Terraform"
    DataClassification = "internal"
    CostCenter         = "development"
    Owner              = var.owner_email
    Compliance         = "NCSC-UK-GDPR"
  }
}

# Data Sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# KMS Keys
module "kms_logs" {
  source = "../../modules/security/kms"

  providers = {
    aws         = aws
    aws.replica = aws.replica
  }

  key_name                     = "cloudwatch-logs-nonprod"
  key_alias                    = "cloudwatch-logs-nonprod"
  key_description              = "KMS key for CloudWatch Logs encryption in non-production"
  key_purpose                  = "CloudWatch Logs encryption"
  allow_cloudwatch_logs_access = true
  allow_vpc_flow_logs_access   = true
  enable_key_rotation          = true
  common_tags                  = local.common_tags
}

module "kms_s3" {
  source = "../../modules/security/kms"

  providers = {
    aws         = aws
    aws.replica = aws.replica
  }

  key_name            = "s3-nonprod"
  key_alias           = "s3-nonprod"
  key_description     = "KMS key for S3 bucket encryption in non-production"
  key_purpose         = "S3 bucket encryption"
  allow_s3_access     = true
  enable_key_rotation = true
  common_tags         = local.common_tags
}

# VPC for Non-Production Workloads
module "vpc" {
  source = "../../modules/networking/vpc"

  vpc_name              = "non-production-uk-vpc"
  vpc_cidr              = var.vpc_cidr
  public_subnet_cidrs   = var.public_subnet_cidrs
  private_subnet_cidrs  = var.private_subnet_cidrs
  database_subnet_cidrs = var.database_subnet_cidrs

  # Cost optimization: use single NAT gateway for non-prod
  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_flow_logs     = true
  flow_logs_kms_key_id = module.kms_logs.key_arn

  common_tags = local.common_tags
}

# GuardDuty (enabled but with lower frequency for cost savings)
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
  enable_malware_protection    = false # Disabled for cost savings in non-prod

  finding_publishing_frequency = "SIX_HOURS" # Less frequent for non-prod

  environment = "non-production"
  common_tags = local.common_tags
}

# Security Hub
module "security_hub" {
  source = "../../modules/security-services/security-hub"

  providers = {
    aws = aws
  }

  aws_region               = "eu-west-2"
  enable_cis_standard      = true
  enable_default_standards = true
  auto_enable_new_accounts = false # Don't auto-enable for non-prod

  common_tags = local.common_tags
}

# AWS Config
module "config" {
  source = "../../modules/security-services/config"

  enable_config_recorder  = true
  config_recorder_name    = "uk-nonprod-config-recorder"
  config_service_role_arn = aws_iam_role.config_role.arn
  config_s3_bucket_name   = var.config_s3_bucket_name

  # Enable UK compliance packs
  enable_ncsc_pack             = true
  enable_gdpr_pack             = true
  enable_cyber_essentials_pack = true

  common_tags = local.common_tags
}

# IAM Role for AWS Config
resource "aws_iam_role" "config_role" {
  name = "uk-nonprod-config-service-role"

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

# CloudWatch Monitoring
module "cloudwatch" {
  source = "../../modules/management/cloudwatch"

  log_groups = {
    application = {
      name           = "/aws/application/nonprod"
      retention_days = 90 # Shorter retention for non-prod
      kms_key_id     = module.kms_logs.key_arn
      purpose        = "Application logs for non-production"
    }
    vpc_flow = {
      name           = "/aws/vpc/nonprod"
      retention_days = 90
      kms_key_id     = module.kms_logs.key_arn
      purpose        = "VPC flow logs for non-production"
    }
  }

  create_sns_topic = true
  sns_topic_name   = "nonprod-cloudwatch-alarms"
  sns_kms_key_id   = module.kms_logs.key_arn

  sns_subscriptions = {
    dev_team = {
      protocol = "email"
      endpoint = var.dev_team_email
    }
  }

  common_tags = local.common_tags
}

# Cost Management (with lower thresholds)
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
          subscriber_email_addresses = [var.dev_team_email]
          subscriber_sns_topic_arns  = []
        },
        {
          comparison_operator        = "GREATER_THAN"
          threshold                  = 80
          threshold_type             = "PERCENTAGE"
          notification_type          = "ACTUAL"
          subscriber_email_addresses = [var.dev_team_email]
          subscriber_sns_topic_arns  = []
        }
      ]
    }
  }

  enable_anomaly_detection       = true
  anomaly_monitor_name           = "nonprod-cost-anomalies"
  anomaly_subscription_frequency = "WEEKLY" # Less frequent for non-prod
  anomaly_threshold_amount       = 50
  anomaly_subscriber_emails      = [var.dev_team_email]

  common_tags = local.common_tags
}

# Monitoring Dashboard
module "monitoring" {
  source = "../../modules/management/monitoring"

  environment = local.environment

  enable_security_monitoring   = true
  enable_compliance_monitoring = true
  enable_cost_monitoring       = true

  notification_email = var.dev_team_email

  tags = local.common_tags
}
