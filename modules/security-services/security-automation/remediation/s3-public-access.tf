# S3 Public Access Remediation
# This file contains resources for automated remediation of S3 public access violations

# Lambda function code for S3 public access remediation
data "archive_file" "s3_public_access_zip" {
  count = var.enable_s3_public_access_remediation ? 1 : 0

  type        = "zip"
  output_path = "${path.module}/lambda_packages/s3_public_access_remediation.zip"

  source {
    content = templatefile("${path.module}/lambda_code/s3_public_access_remediation.py", {
      sns_topic_arn      = var.sns_topic_arn
      remediation_bucket = var.remediation_bucket_name
      kms_key_arn        = var.kms_key_arn
    })
    filename = "index.py"
  }
}

# CloudWatch alarm for S3 public access remediation failures
resource "aws_cloudwatch_metric_alarm" "s3_remediation_failures" {
  count = var.enable_s3_public_access_remediation ? 1 : 0

  alarm_name          = "uk-s3-public-access-remediation-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This metric monitors S3 public access remediation function failures"
  alarm_actions       = [var.sns_topic_arn]

  dimensions = {
    FunctionName = aws_lambda_function.s3_public_access_remediation[0].function_name
  }

  tags = merge(var.common_tags, {
    Name       = "s3-remediation-failures-alarm"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })
}

# CloudWatch alarm for S3 public access remediation duration
resource "aws_cloudwatch_metric_alarm" "s3_remediation_duration" {
  count = var.enable_s3_public_access_remediation ? 1 : 0

  alarm_name          = "uk-s3-public-access-remediation-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Average"
  threshold           = "240000" # 4 minutes in milliseconds
  alarm_description   = "This metric monitors S3 public access remediation function duration"
  alarm_actions       = [var.sns_topic_arn]

  dimensions = {
    FunctionName = aws_lambda_function.s3_public_access_remediation[0].function_name
  }

  tags = merge(var.common_tags, {
    Name       = "s3-remediation-duration-alarm"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })
}

# Custom CloudWatch metric for S3 remediation success rate
resource "aws_cloudwatch_log_metric_filter" "s3_remediation_success" {
  count = var.enable_s3_public_access_remediation ? 1 : 0

  name           = "S3RemediationSuccess"
  log_group_name = var.cloudwatch_log_group_name
  pattern        = "[timestamp, request_id, level=\"INFO\", message=\"S3 public access remediation completed successfully\"]"

  metric_transformation {
    name      = "S3RemediationSuccessCount"
    namespace = "UK/SecurityAutomation"
    value     = "1"
  }
}

# Custom CloudWatch metric for S3 remediation failures
resource "aws_cloudwatch_log_metric_filter" "s3_remediation_failure" {
  count = var.enable_s3_public_access_remediation ? 1 : 0

  name           = "S3RemediationFailure"
  log_group_name = var.cloudwatch_log_group_name
  pattern        = "[timestamp, request_id, level=\"ERROR\", message=\"S3 public access remediation failed\"]"

  metric_transformation {
    name      = "S3RemediationFailureCount"
    namespace = "UK/SecurityAutomation"
    value     = "1"
  }
}

# CloudWatch dashboard widget for S3 remediation metrics
locals {
  s3_remediation_dashboard_widget = var.enable_s3_public_access_remediation ? {
    type   = "metric"
    x      = 0
    y      = 0
    width  = 12
    height = 6

    properties = {
      metrics = [
        ["UK/SecurityAutomation", "S3RemediationSuccessCount"],
        [".", "S3RemediationFailureCount"],
        ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.s3_public_access_remediation[0].function_name],
        [".", "Errors", ".", "."],
        [".", "Duration", ".", "."]
      ]
      view    = "timeSeries"
      stacked = false
      region  = data.aws_region.current.name
      title   = "S3 Public Access Remediation Metrics"
      period  = 300
    }
  } : null
}

# Output the dashboard widget configuration
output "s3_remediation_dashboard_widget" {
  description = "CloudWatch dashboard widget configuration for S3 remediation"
  value       = local.s3_remediation_dashboard_widget
}