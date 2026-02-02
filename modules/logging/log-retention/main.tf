# Log Retention Module - UK Compliance Log Lifecycle Management
# This module implements log retention policies for the UK AWS Secure Landing Zone
# with support for Security Standards Cloud Security Principles and 7-year retention requirements

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# CloudWatch Log Group Retention Policies
resource "aws_cloudwatch_log_group" "retention_managed_groups" {
  for_each = var.cloudwatch_log_groups

  name              = each.value.name
  retention_in_days = each.value.retention_days
  kms_key_id        = each.value.kms_key_id

  tags = merge(var.common_tags, {
    Name               = each.key
    Purpose            = each.value.purpose
    DataClassification = "confidential"
    RetentionPeriod    = "${each.value.retention_days} days"
  })
}

# S3 Bucket Lifecycle Policies for Log Archives
resource "aws_s3_bucket_lifecycle_configuration" "log_retention" {
  for_each = var.s3_log_buckets

  bucket = each.value.bucket_name

  # CloudTrail logs - 7 year retention
  rule {
    id     = "cloudtrail-7year-retention"
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
      days = var.cloudtrail_retention_days # 2555 days = 7 years
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }

  # VPC Flow Logs - 7 year retention
  rule {
    id     = "vpc-flow-logs-7year-retention"
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
      days = var.flow_logs_retention_days # 2555 days = 7 years
    }
  }

  # Config Logs - 7 year retention
  rule {
    id     = "config-logs-7year-retention"
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
      days = var.config_logs_retention_days # 2555 days = 7 years
    }
  }

  # Security Hub Findings - 3 year retention
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
      days = var.securityhub_findings_retention_days # 1095 days = 3 years
    }
  }

  # GuardDuty Findings - 3 year retention
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
      days = var.guardduty_findings_retention_days # 1095 days = 3 years
    }
  }

  # Network Firewall Logs - 1 year retention
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
      days = var.network_firewall_logs_retention_days # 365 days = 1 year
    }
  }

  # Application Logs - configurable retention
  dynamic "rule" {
    for_each = var.application_log_retention_rules
    content {
      id     = "application-logs-${rule.key}"
      status = "Enabled"

      filter {
        prefix = rule.value.prefix
      }

      dynamic "transition" {
        for_each = rule.value.transitions
        content {
          days          = transition.value.days
          storage_class = transition.value.storage_class
        }
      }

      expiration {
        days = rule.value.expiration_days
      }
    }
  }
}

# Cross-Region Replication for Critical Logs
resource "aws_s3_bucket_replication_configuration" "log_replication" {
  for_each = var.enable_cross_region_replication ? var.s3_log_buckets : {}

  bucket = each.value.bucket_name
  role   = var.replication_role_arn

  rule {
    id     = "replicate-critical-logs"
    status = "Enabled"

    filter {
      prefix = "critical/"
    }

    destination {
      bucket        = each.value.replica_bucket_arn
      storage_class = "STANDARD_IA"

      encryption_configuration {
        replica_kms_key_id = each.value.replica_kms_key_id
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
}

# CloudWatch Metric Filters for Log Monitoring
resource "aws_cloudwatch_log_metric_filter" "retention_monitoring" {
  for_each = var.log_metric_filters

  name           = each.key
  log_group_name = each.value.log_group_name
  pattern        = each.value.pattern

  metric_transformation {
    name      = each.value.metric_name
    namespace = each.value.metric_namespace
    value     = each.value.metric_value
  }
}

# CloudWatch Alarms for Retention Compliance
resource "aws_cloudwatch_metric_alarm" "retention_compliance" {
  for_each = var.retention_compliance_alarms

  alarm_name          = each.key
  comparison_operator = each.value.comparison_operator
  evaluation_periods  = each.value.evaluation_periods
  metric_name         = each.value.metric_name
  namespace           = each.value.namespace
  period              = each.value.period
  statistic           = each.value.statistic
  threshold           = each.value.threshold
  alarm_description   = each.value.description
  alarm_actions       = each.value.alarm_actions
  treat_missing_data  = "notBreaching"

  tags = var.common_tags
}

# Lambda Function for Automated Log Cleanup (optional)
resource "aws_lambda_function" "log_cleanup" {
  count = var.enable_automated_cleanup ? 1 : 0

  filename         = data.archive_file.log_cleanup_zip[0].output_path
  function_name    = "${var.project_name}-log-cleanup"
  role             = aws_iam_role.log_cleanup[0].arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.log_cleanup_zip[0].output_base64sha256
  runtime          = "python3.9"
  timeout          = 300

  environment {
    variables = {
      LOG_RETENTION_DAYS = var.default_log_retention_days
      DRY_RUN            = var.cleanup_dry_run
    }
  }

  tags = merge(var.common_tags, {
    Name    = "${var.project_name}-log-cleanup"
    Purpose = "Automated log cleanup"
  })
}

# Lambda Function Code
data "archive_file" "log_cleanup_zip" {
  count = var.enable_automated_cleanup ? 1 : 0

  type        = "zip"
  output_path = "/tmp/log_cleanup.zip"
  source {
    content = templatefile("${path.module}/lambda_code/log_cleanup.py", {
      retention_days = var.default_log_retention_days
    })
    filename = "index.py"
  }
}

# IAM Role for Lambda
resource "aws_iam_role" "log_cleanup" {
  count = var.enable_automated_cleanup ? 1 : 0
  name  = "${var.project_name}-log-cleanup-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.common_tags
}

# IAM Policy for Lambda
resource "aws_iam_role_policy" "log_cleanup" {
  count = var.enable_automated_cleanup ? 1 : 0
  name  = "${var.project_name}-log-cleanup-policy"
  role  = aws_iam_role.log_cleanup[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:DeleteLogGroup",
          "logs:DeleteLogStream"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:GetBucketLifecycleConfiguration",
          "s3:PutBucketLifecycleConfiguration"
        ]
        Resource = [
          "arn:aws:s3:::*log*",
          "arn:aws:s3:::*log*/*"
        ]
      }
    ]
  })
}

# EventBridge Rule for Scheduled Cleanup
resource "aws_cloudwatch_event_rule" "log_cleanup_schedule" {
  count               = var.enable_automated_cleanup ? 1 : 0
  name                = "${var.project_name}-log-cleanup-schedule"
  description         = "Trigger log cleanup Lambda function"
  schedule_expression = var.cleanup_schedule_expression

  tags = var.common_tags
}

# EventBridge Target
resource "aws_cloudwatch_event_target" "log_cleanup_target" {
  count     = var.enable_automated_cleanup ? 1 : 0
  rule      = aws_cloudwatch_event_rule.log_cleanup_schedule[0].name
  target_id = "LogCleanupLambdaTarget"
  arn       = aws_lambda_function.log_cleanup[0].arn
}

# Lambda Permission for EventBridge
resource "aws_lambda_permission" "allow_eventbridge" {
  count         = var.enable_automated_cleanup ? 1 : 0
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.log_cleanup[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.log_cleanup_schedule[0].arn
}