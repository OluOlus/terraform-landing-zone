# Management Account Module
# Configures the AWS Organizations root account with consolidated billing and region-specific settings

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.4"
    }
  }
}

# Get current account information
data "aws_caller_identity" "current" {}

# AWS Organizations configuration
resource "aws_organizations_organization" "main" {
  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "sso.amazonaws.com",
    "account.amazonaws.com",
    "backup.amazonaws.com",
    "compute-optimizer.amazonaws.com",
    "cost-optimization-hub.amazonaws.com",
    "fms.amazonaws.com",
    "inspector2.amazonaws.com",
    "macie.amazonaws.com",
    "ram.amazonaws.com",
    "servicecatalog.amazonaws.com",
    "tagpolicies.tag.amazonaws.com"
  ]

  feature_set = "ALL"

  enabled_policy_types = [
    "SERVICE_CONTROL_POLICY",
    "TAG_POLICY",
    "BACKUP_POLICY",
    "AISERVICES_OPT_OUT_POLICY"
  ]
}

# Note: Organizational units and SCPs are managed by the organization module
# This module only creates the organization itself and configures the management account baseline

# Account baseline configuration for Management Account
resource "aws_config_configuration_recorder" "management" {
  name     = "uk-landing-zone-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  depends_on = [aws_config_delivery_channel.management]
}

resource "aws_config_delivery_channel" "management" {
  name           = "uk-landing-zone-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config.bucket
  s3_key_prefix  = "config"

  snapshot_delivery_properties {
    delivery_frequency = var.config_delivery_frequency
  }
}

# S3 bucket for Config with region-specific encryption and compliance
resource "aws_s3_bucket" "config" {
  bucket        = "uk-landing-zone-config-${random_id.bucket_suffix.hex}"
  force_destroy = var.force_destroy_buckets

  tags = merge(var.common_tags, {
    Purpose            = "AWS Config Storage"
    DataClassification = "Internal"
    RetentionPeriod    = "7-years"
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.config.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    id     = "config_lifecycle"
    status = "Enabled"

    filter {
      prefix = "config/"
    }

    expiration {
      days = 2555 # 7 years
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_transition {
      noncurrent_days = 60
      storage_class   = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket = aws_s3_bucket.config.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# KMS key for Config encryption with region-specific settings
resource "aws_kms_key" "config" {
  description             = "KMS key for Config encryption in UK Landing Zone"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Config Service"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.common_tags, {
    Purpose = "AWS Config Encryption"
  })
}

resource "aws_kms_alias" "config" {
  name          = "alias/uk-landing-zone-config"
  target_key_id = aws_kms_key.config.key_id
}

# IAM role for Config with region-specific permissions
resource "aws_iam_role" "config" {
  name = "uk-landing-zone-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = merge(var.common_tags, {
    Purpose = "AWS Config Service Role"
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

# Additional IAM policy for S3 bucket access
resource "aws_iam_role_policy" "config_s3" {
  name = "uk-landing-zone-config-s3-policy"
  role = aws_iam_role.config.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.config.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.config.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# Random ID for unique resource naming
resource "random_id" "bucket_suffix" {
  byte_length = 8
}