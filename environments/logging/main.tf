# Logging Environment Configuration
# Configures the Log Archive Account with CloudTrail, centralized log storage, and 7-year retention

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

# Replica Provider (eu-west-1 - Ireland) for cross-region replication
provider "aws" {
  alias  = "replica"
  region = "eu-west-1"

  default_tags {
    tags = local.common_tags
  }
}

locals {
  environment = "logging"
  project     = "uk-landing-zone"

  common_tags = {
    Environment        = "logging"
    Project            = "uk-landing-zone"
    ManagedBy          = "Terraform"
    DataClassification = "restricted"
    CostCenter         = "logging-operations"
    Owner              = var.owner_email
    Compliance         = "NCSC-UK-GDPR"
  }
}

# Data Sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_organizations_organization" "current" {}

# KMS Keys for Log Encryption
module "kms_cloudtrail" {
  source = "../../modules/security/kms"

  providers = {
    aws         = aws
    aws.replica = aws.replica
  }

  key_name                = "cloudtrail-logs"
  key_alias               = "cloudtrail-logs"
  key_description         = "KMS key for CloudTrail log encryption"
  key_purpose             = "CloudTrail log encryption"
  allow_cloudtrail_access = true
  organization_id         = data.aws_organizations_organization.current.id
  enable_key_rotation     = true
  common_tags             = local.common_tags
}

module "kms_logs" {
  source = "../../modules/security/kms"

  providers = {
    aws         = aws
    aws.replica = aws.replica
  }

  key_name                     = "log-archive"
  key_alias                    = "log-archive"
  key_description              = "KMS key for log archive encryption"
  key_purpose                  = "Log archive encryption"
  allow_s3_access              = true
  allow_cloudwatch_logs_access = true
  organization_id              = data.aws_organizations_organization.current.id
  enable_key_rotation          = true
  common_tags                  = local.common_tags
}

module "kms_replica" {
  source = "../../modules/security/kms"

  providers = {
    aws         = aws.replica
    aws.replica = aws.replica
  }

  key_name            = "log-archive-replica"
  key_alias           = "log-archive-replica"
  key_description     = "KMS key for log archive replica encryption"
  key_purpose         = "Log archive replica encryption"
  allow_s3_access     = true
  organization_id     = data.aws_organizations_organization.current.id
  enable_key_rotation = true
  common_tags         = local.common_tags
}

# Log Archive S3 Buckets
module "log_archive" {
  source = "../../modules/logging/log-archive"

  providers = {
    aws         = aws
    aws.replica = aws.replica
  }

  primary_bucket_name = var.log_archive_bucket_name
  replica_bucket_name = "${var.log_archive_bucket_name}-replica"

  primary_kms_key_id = module.kms_logs.key_id
  replica_kms_key_id = module.kms_replica.key_id

  organization_id = data.aws_organizations_organization.current.id

  # 7-year retention for UK compliance
  cloudtrail_expiration_days            = 2555
  flow_logs_expiration_days             = 2555
  config_logs_expiration_days           = 2555
  guardduty_findings_expiration_days    = 2555
  securityhub_findings_expiration_days  = 2555
  network_firewall_logs_expiration_days = 2555

  # Lifecycle transitions for cost optimization
  cloudtrail_transition_to_ia_days           = 90
  cloudtrail_transition_to_glacier_days      = 180
  cloudtrail_transition_to_deep_archive_days = 365

  flow_logs_transition_to_ia_days      = 90
  flow_logs_transition_to_glacier_days = 180

  # Cross-region replication for DR
  enable_cross_region_replication = true
  replication_role_arn            = aws_iam_role.replication_role.arn

  # Monitoring
  enable_replication_alarms = true
  alarm_sns_topic_arns      = [module.cloudwatch.sns_topic_arn]

  common_tags = local.common_tags
}

# Organization CloudTrail
module "cloudtrail" {
  source = "../../modules/logging/cloudtrail"

  trail_name             = "uk-organization-trail"
  s3_bucket_name         = module.log_archive.primary_bucket_id
  kms_key_arn            = module.kms_cloudtrail.key_arn
  is_multi_region_trail  = true
  is_organization_trail  = true
  enable_cloudwatch_logs = true
  log_retention_days     = 2555 # 7 years

  common_tags = local.common_tags
}

# IAM Role for S3 Replication
resource "aws_iam_role" "replication_role" {
  name = "uk-log-archive-replication-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "replication_policy" {
  name = "replication-policy"
  role = aws_iam_role.replication_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket"
        ]
        Resource = "arn:aws:s3:::${var.log_archive_bucket_name}"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging"
        ]
        Resource = "arn:aws:s3:::${var.log_archive_bucket_name}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags"
        ]
        Resource = "arn:aws:s3:::${var.log_archive_bucket_name}-replica/*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = module.kms_logs.key_arn
        Condition = {
          StringLike = {
            "kms:ViaService"                   = "s3.eu-west-2.amazonaws.com"
            "kms:EncryptionContext:aws:s3:arn" = "arn:aws:s3:::${var.log_archive_bucket_name}/*"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt"
        ]
        Resource = module.kms_replica.key_arn
        Condition = {
          StringLike = {
            "kms:ViaService"                   = "s3.eu-west-1.amazonaws.com"
            "kms:EncryptionContext:aws:s3:arn" = "arn:aws:s3:::${var.log_archive_bucket_name}-replica/*"
          }
        }
      }
    ]
  })
}

# CloudWatch for Log Archive Monitoring
module "cloudwatch" {
  source = "../../modules/management/cloudwatch"

  log_groups = {
    cloudtrail = {
      name           = "/aws/cloudtrail/organization"
      retention_days = 2555 # 7 years
      kms_key_id     = module.kms_logs.key_arn
      purpose        = "Organization CloudTrail logs"
    }
    replication = {
      name           = "/aws/s3/replication"
      retention_days = 90
      kms_key_id     = module.kms_logs.key_arn
      purpose        = "S3 replication monitoring"
    }
  }

  create_sns_topic = true
  sns_topic_name   = "log-archive-alerts"
  sns_kms_key_id   = module.kms_logs.key_arn

  sns_subscriptions = {
    ops_team = {
      protocol = "email"
      endpoint = var.ops_team_email
    }
  }

  common_tags = local.common_tags
}

# Monitoring Dashboard
module "monitoring" {
  source = "../../modules/management/monitoring"

  environment = local.environment

  enable_security_monitoring   = false
  enable_compliance_monitoring = true
  enable_cost_monitoring       = true

  notification_email = var.ops_team_email

  tags = local.common_tags
}

# S3 Access Logging Bucket
resource "aws_s3_bucket" "access_logs" {
  bucket = "${var.log_archive_bucket_name}-access-logs"

  tags = merge(local.common_tags, {
    Name    = "${var.log_archive_bucket_name}-access-logs"
    Purpose = "S3 access logging"
  })
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = module.kms_logs.key_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555 # 7 years
    }
  }
}
