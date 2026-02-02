# Log Archive S3 Module - UK Centralized Logging
# This module implements centralized log storage for the UK AWS Secure Landing Zone
# with support for Security Standards Cloud Security Principles, GDPR compliance, and 7-year retention

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Primary Log Archive S3 Bucket (us-east-1)
resource "aws_s3_bucket" "log_archive_primary" {
  bucket        = var.primary_bucket_name
  force_destroy = var.force_destroy

  tags = merge(var.common_tags, {
    Name               = var.primary_bucket_name
    Purpose            = "Centralized log archive - Primary"
    DataClassification = "confidential"
    Compliance         = "Security Standards-UK-GDPR"
    Region             = "us-east-1"
  })
}

# Bucket Versioning - Primary
resource "aws_s3_bucket_versioning" "log_archive_primary" {
  bucket = aws_s3_bucket.log_archive_primary.id

  versioning_configuration {
    status     = "Enabled"
    mfa_delete = var.enable_mfa_delete ? "Enabled" : "Disabled"
  }
}

# Bucket Encryption - Primary
resource "aws_s3_bucket_server_side_encryption_configuration" "log_archive_primary" {
  bucket = aws_s3_bucket.log_archive_primary.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.primary_kms_key_id
    }
    bucket_key_enabled = true
  }
}

# Block Public Access - Primary
resource "aws_s3_bucket_public_access_block" "log_archive_primary" {
  bucket = aws_s3_bucket.log_archive_primary.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Bucket Logging - Primary
resource "aws_s3_bucket_logging" "log_archive_primary" {
  count  = var.enable_access_logging ? 1 : 0
  bucket = aws_s3_bucket.log_archive_primary.id

  target_bucket = var.access_logging_bucket_name
  target_prefix = "log-archive-primary-access-logs/"
}

# Lifecycle Policy - Primary
resource "aws_s3_bucket_lifecycle_configuration" "log_archive_primary" {
  bucket = aws_s3_bucket.log_archive_primary.id

  # CloudTrail logs - 7 year retention
  rule {
    id     = "cloudtrail-retention"
    status = "Enabled"

    filter {
      prefix = "cloudtrail/"
    }

    transition {
      days          = var.cloudtrail_transition_to_ia_days
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = var.cloudtrail_transition_to_glacier_days
      storage_class = "GLACIER"
    }

    transition {
      days          = var.cloudtrail_transition_to_deep_archive_days
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = var.cloudtrail_expiration_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }

  # VPC Flow Logs - 7 year retention
  rule {
    id     = "vpc-flow-logs-retention"
    status = "Enabled"

    filter {
      prefix = "vpc-flow-logs/"
    }

    transition {
      days          = var.flow_logs_transition_to_ia_days
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = var.flow_logs_transition_to_glacier_days
      storage_class = "GLACIER"
    }

    expiration {
      days = var.flow_logs_expiration_days
    }
  }

  # Config Logs
  rule {
    id     = "config-logs-retention"
    status = "Enabled"

    filter {
      prefix = "config/"
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }

    expiration {
      days = var.config_logs_expiration_days
    }
  }

  # GuardDuty Findings
  rule {
    id     = "guardduty-findings-retention"
    status = "Enabled"

    filter {
      prefix = "guardduty/"
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = var.guardduty_findings_expiration_days
    }
  }

  # Security Hub Findings
  rule {
    id     = "securityhub-findings-retention"
    status = "Enabled"

    filter {
      prefix = "securityhub/"
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = var.securityhub_findings_expiration_days
    }
  }

  # Network Firewall Logs
  rule {
    id     = "network-firewall-logs-retention"
    status = "Enabled"

    filter {
      prefix = "network-firewall/"
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = var.network_firewall_logs_expiration_days
    }
  }
}

# Bucket Policy - Primary
resource "aws_s3_bucket_policy" "log_archive_primary" {
  bucket = aws_s3_bucket.log_archive_primary.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # CloudTrail write access
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.log_archive_primary.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.log_archive_primary.arn}/cloudtrail/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      # Config write access
      {
        Sid    = "AWSConfigAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.log_archive_primary.arn
      },
      {
        Sid    = "AWSConfigWrite"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.log_archive_primary.arn}/config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      # VPC Flow Logs write access
      {
        Sid    = "AWSLogDeliveryAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.log_archive_primary.arn
      },
      {
        Sid    = "AWSLogDeliveryWrite"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.log_archive_primary.arn}/vpc-flow-logs/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      # Deny insecure transport
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.log_archive_primary.arn,
          "${aws_s3_bucket.log_archive_primary.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      # Deny unencrypted object uploads
      {
        Sid       = "DenyUnencryptedObjectUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.log_archive_primary.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      # Organization accounts read access
      {
        Sid       = "OrganizationAccountsRead"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.log_archive_primary.arn,
          "${aws_s3_bucket.log_archive_primary.arn}/*"
        ]
        Condition = {
          StringEquals = {
            "aws:PrincipalOrgID" = var.organization_id
          }
        }
      }
    ]
  })
}

# Replication Bucket (us-west-2) - for DR
resource "aws_s3_bucket" "log_archive_replica" {
  count         = var.enable_cross_region_replication ? 1 : 0
  provider      = aws.replica
  bucket        = var.replica_bucket_name
  force_destroy = var.force_destroy

  tags = merge(var.common_tags, {
    Name               = var.replica_bucket_name
    Purpose            = "Centralized log archive - Replica"
    DataClassification = "confidential"
    Compliance         = "Security Standards-UK-GDPR"
    Region             = "us-west-2"
  })
}

# Bucket Versioning - Replica
resource "aws_s3_bucket_versioning" "log_archive_replica" {
  count    = var.enable_cross_region_replication ? 1 : 0
  provider = aws.replica
  bucket   = aws_s3_bucket.log_archive_replica[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

# Bucket Encryption - Replica
resource "aws_s3_bucket_server_side_encryption_configuration" "log_archive_replica" {
  count    = var.enable_cross_region_replication ? 1 : 0
  provider = aws.replica
  bucket   = aws_s3_bucket.log_archive_replica[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.replica_kms_key_id
    }
    bucket_key_enabled = true
  }
}

# Block Public Access - Replica
resource "aws_s3_bucket_public_access_block" "log_archive_replica" {
  count    = var.enable_cross_region_replication ? 1 : 0
  provider = aws.replica
  bucket   = aws_s3_bucket.log_archive_replica[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Replication Configuration
resource "aws_s3_bucket_replication_configuration" "log_archive" {
  count  = var.enable_cross_region_replication ? 1 : 0
  bucket = aws_s3_bucket.log_archive_primary.id
  role   = var.replication_role_arn

  rule {
    id     = "replicate-all-logs"
    status = "Enabled"

    filter {}

    destination {
      bucket        = aws_s3_bucket.log_archive_replica[0].arn
      storage_class = "STANDARD_IA"

      encryption_configuration {
        replica_kms_key_id = var.replica_kms_key_id
      }

      replication_time {
        status = "Enabled"
        time {
          minutes = 15
        }
      }

      metrics {
        status = "Enabled"
        event_threshold {
          minutes = 15
        }
      }
    }

    delete_marker_replication {
      status = "Enabled"
    }
  }

  depends_on = [aws_s3_bucket_versioning.log_archive_primary]
}

# CloudWatch Metric Alarm for Replication
resource "aws_cloudwatch_metric_alarm" "replication_latency" {
  count               = var.enable_cross_region_replication && var.enable_replication_alarms ? 1 : 0
  alarm_name          = "${var.primary_bucket_name}-replication-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ReplicationLatency"
  namespace           = "AWS/S3"
  period              = 300
  statistic           = "Maximum"
  threshold           = 900 # 15 minutes
  alarm_description   = "S3 replication latency is high"
  alarm_actions       = var.alarm_sns_topic_arns

  dimensions = {
    SourceBucket      = aws_s3_bucket.log_archive_primary.id
    DestinationBucket = aws_s3_bucket.log_archive_replica[0].id
    RuleId            = "replicate-all-logs"
  }

  tags = var.common_tags
}

# S3 Bucket Notifications (optional)
resource "aws_s3_bucket_notification" "log_archive_notifications" {
  count  = var.enable_bucket_notifications ? 1 : 0
  bucket = aws_s3_bucket.log_archive_primary.id

  dynamic "lambda_function" {
    for_each = var.notification_lambda_arns
    content {
      lambda_function_arn = lambda_function.value
      events              = ["s3:ObjectCreated:*"]
      filter_prefix       = var.notification_filter_prefix
      filter_suffix       = var.notification_filter_suffix
    }
  }

  dynamic "topic" {
    for_each = var.notification_sns_topic_arns
    content {
      topic_arn     = topic.value
      events        = ["s3:ObjectCreated:*"]
      filter_prefix = var.notification_filter_prefix
    }
  }
}
