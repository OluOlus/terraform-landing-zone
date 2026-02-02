# Unencrypted Volumes Remediation
# This file contains resources for automated remediation of unencrypted EBS volumes

# Lambda function code for unencrypted volumes remediation
data "archive_file" "unencrypted_volumes_zip" {
  count = var.enable_unencrypted_volumes_remediation ? 1 : 0

  type        = "zip"
  output_path = "${path.module}/lambda_packages/unencrypted_volumes_remediation.zip"

  source {
    content = templatefile("${path.module}/lambda_code/unencrypted_volumes_remediation.py", {
      sns_topic_arn      = var.sns_topic_arn
      remediation_bucket = var.remediation_bucket_name
      kms_key_arn        = var.kms_key_arn
    })
    filename = "index.py"
  }
}

# CloudWatch alarm for unencrypted volumes remediation failures
resource "aws_cloudwatch_metric_alarm" "volumes_remediation_failures" {
  count = var.enable_unencrypted_volumes_remediation ? 1 : 0

  alarm_name          = "uk-unencrypted-volumes-remediation-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This metric monitors unencrypted volumes remediation function failures"
  alarm_actions       = [var.sns_topic_arn]

  dimensions = {
    FunctionName = aws_lambda_function.unencrypted_volumes_remediation[0].function_name
  }

  tags = merge(var.common_tags, {
    Name       = "volumes-remediation-failures-alarm"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })
}

# CloudWatch alarm for unencrypted volumes remediation duration
resource "aws_cloudwatch_metric_alarm" "volumes_remediation_duration" {
  count = var.enable_unencrypted_volumes_remediation ? 1 : 0

  alarm_name          = "uk-unencrypted-volumes-remediation-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Average"
  threshold           = "240000" # 4 minutes in milliseconds
  alarm_description   = "This metric monitors unencrypted volumes remediation function duration"
  alarm_actions       = [var.sns_topic_arn]

  dimensions = {
    FunctionName = aws_lambda_function.unencrypted_volumes_remediation[0].function_name
  }

  tags = merge(var.common_tags, {
    Name       = "volumes-remediation-duration-alarm"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })
}

# Custom CloudWatch metric for volumes remediation success rate
resource "aws_cloudwatch_log_metric_filter" "volumes_remediation_success" {
  count = var.enable_unencrypted_volumes_remediation ? 1 : 0

  name           = "VolumesRemediationSuccess"
  log_group_name = var.cloudwatch_log_group_name
  pattern        = "[timestamp, request_id, level=\"INFO\", message=\"Unencrypted volume remediation completed successfully\"]"

  metric_transformation {
    name      = "VolumesRemediationSuccessCount"
    namespace = "UK/SecurityAutomation"
    value     = "1"
  }
}

# Custom CloudWatch metric for volumes remediation failures
resource "aws_cloudwatch_log_metric_filter" "volumes_remediation_failure" {
  count = var.enable_unencrypted_volumes_remediation ? 1 : 0

  name           = "VolumesRemediationFailure"
  log_group_name = var.cloudwatch_log_group_name
  pattern        = "[timestamp, request_id, level=\"ERROR\", message=\"Unencrypted volume remediation failed\"]"

  metric_transformation {
    name      = "VolumesRemediationFailureCount"
    namespace = "UK/SecurityAutomation"
    value     = "1"
  }
}

# Custom CloudWatch metric for volume encryption operations
resource "aws_cloudwatch_log_metric_filter" "volume_encryption_operations" {
  count = var.enable_unencrypted_volumes_remediation ? 1 : 0

  name           = "VolumeEncryptionOperations"
  log_group_name = var.cloudwatch_log_group_name
  pattern        = "[timestamp, request_id, level=\"INFO\", message=\"Volume encrypted\", volume_id]"

  metric_transformation {
    name      = "VolumeEncryptionCount"
    namespace = "UK/SecurityAutomation"
    value     = "1"
  }
}

# CloudWatch dashboard widget for volumes remediation metrics
locals {
  volumes_remediation_dashboard_widget = var.enable_unencrypted_volumes_remediation ? {
    type   = "metric"
    x      = 12
    y      = 0
    width  = 12
    height = 6

    properties = {
      metrics = [
        ["UK/SecurityAutomation", "VolumesRemediationSuccessCount"],
        [".", "VolumesRemediationFailureCount"],
        [".", "VolumeEncryptionCount"],
        ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.unencrypted_volumes_remediation[0].function_name],
        [".", "Errors", ".", "."],
        [".", "Duration", ".", "."]
      ]
      view    = "timeSeries"
      stacked = false
      region  = data.aws_region.current.name
      title   = "Unencrypted Volumes Remediation Metrics"
      period  = 300
    }
  } : null
}

# IAM policy for volume encryption operations
resource "aws_iam_role_policy" "volume_encryption_policy" {
  count = var.enable_unencrypted_volumes_remediation ? 1 : 0

  name = "uk-volume-encryption-policy"
  role = aws_iam_role.remediation_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "VolumeEncryptionPermissions"
        Effect = "Allow"
        Action = [
          "ec2:CreateVolume",
          "ec2:CopySnapshot",
          "ec2:AttachVolume",
          "ec2:DetachVolume",
          "ec2:DeleteVolume",
          "ec2:ModifyInstanceAttribute"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = ["us-west-2", "us-east-1"]
          }
        }
      },
      {
        Sid    = "VolumeSnapshotPermissions"
        Effect = "Allow"
        Action = [
          "ec2:CreateSnapshot",
          "ec2:DeleteSnapshot",
          "ec2:CopySnapshot"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = ["us-west-2", "us-east-1"]
          }
        }
      }
    ]
  })
}

# Output the dashboard widget configuration
output "volumes_remediation_dashboard_widget" {
  description = "CloudWatch dashboard widget configuration for volumes remediation"
  value       = local.volumes_remediation_dashboard_widget
}