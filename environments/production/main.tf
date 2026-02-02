# Production-UK Environment Configuration
# Configures the Production workload account for UK operations

terraform {
  required_version = "~> 1.9"

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

provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = local.common_tags
  }
}

provider "aws" {
  alias  = "replica"
  region = "us-west-2"
  default_tags {
    tags = local.common_tags
  }
}

locals {
  environment = "production"
  project     = "uk-landing-zone"

  common_tags = {
    Environment        = "production"
    Project            = "uk-landing-zone"
    ManagedBy          = "Terraform"
    DataClassification = "confidential"
    CostCenter         = "production-workloads"
    Owner              = var.owner_email
    Compliance         = "Security Standards-UK-GDPR"
  }
}

# VPC for Production Workloads
module "vpc" {
  source = "../../modules/networking/vpc"

  vpc_name              = "production-uk-vpc"
  vpc_cidr              = var.vpc_cidr
  public_subnet_cidrs   = var.public_subnet_cidrs
  private_subnet_cidrs  = var.private_subnet_cidrs
  database_subnet_cidrs = var.database_subnet_cidrs
  enable_nat_gateway    = true
  single_nat_gateway    = false
  enable_flow_logs      = true
  flow_logs_kms_key_id  = module.kms_logs.key_arn
  common_tags           = local.common_tags
}

# KMS Keys
module "kms_logs" {
  source = "../../modules/security/kms"

  key_name                     = "cloudwatch-logs-production"
  key_alias                    = "cloudwatch-logs-production"
  key_description              = "KMS key for CloudWatch Logs encryption in production"
  allow_cloudwatch_logs_access = true
  allow_vpc_flow_logs_access   = true
  enable_key_rotation          = true
  common_tags                  = local.common_tags
}

module "kms_s3" {
  source = "../../modules/security/kms"

  key_name            = "s3-production"
  key_alias           = "s3-production"
  key_description     = "KMS key for S3 bucket encryption in production"
  allow_s3_access     = true
  enable_key_rotation = true
  common_tags         = local.common_tags
}

# GuardDuty
module "guardduty" {
  source = "../../modules/security-services/guardduty"

  enable_guardduty             = true
  enable_s3_logs               = true
  enable_kubernetes_audit_logs = true
  enable_malware_protection    = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  common_tags                  = local.common_tags
}

# Security Hub
module "security_hub" {
  source = "../../modules/security-services/security-hub"

  enable_security_hub        = true
  enable_finding_aggregation = false
  enable_aws_foundational    = true
  enable_cis_benchmark       = true
  common_tags                = local.common_tags
}

# AWS Config
module "config" {
  source = "../../modules/security-services/config"

  enable_config_recorder       = true
  config_service_role_arn      = var.config_service_role_arn
  config_s3_bucket_name        = var.config_s3_bucket_name
  enable_ncsc_pack             = true
  enable_gdpr_pack             = true
  enable_cyber_essentials_pack = true
  common_tags                  = local.common_tags
}
