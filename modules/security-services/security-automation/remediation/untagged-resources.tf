# Untagged Resources Remediation
# This file contains resources for automated remediation of untagged resources

# Lambda function code for untagged resources remediation
data "archive_file" "untagged_resources_zip" {
  count = var.enable_untagged_resources_remediation ? 1 : 0

  type        = "zip"
  output_path = "${path.module}/lambda_packages/untagged_resources_remediation.zip"

  source {
    content = templatefile("${path.module}/lambda_code/untagged_resources_remediation.py", {
      sns_topic_arn      = var.sns_topic_arn
      remediation_bucket = var.remediation_bucket_name
      kms_key_arn        = var.kms_key_arn
    })
    filename = "index.py"
  }
}

# CloudWatch alarm for untagged resources remediation failures
resource "aws_cloudwatch_metric_alarm" "tagging_remediation_failures" {
  count = var.enable_untagged_resources_remediation ? 1 : 0

  alarm_name          = "uk-untagged-resources-remediation-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This metric monitors untagged resources remediation function failures"
  alarm_actions       = [var.sns_topic_arn]

  dimensions = {
    FunctionName = aws_lambda_function.untagged_resources_remediation[0].function_name
  }

  tags = merge(var.common_tags, {
    Name       = "tagging-remediation-failures-alarm"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })
}

# CloudWatch alarm for untagged resources remediation duration
resource "aws_cloudwatch_metric_alarm" "tagging_remediation_duration" {
  count = var.enable_untagged_resources_remediation ? 1 : 0

  alarm_name          = "uk-untagged-resources-remediation-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Average"
  threshold           = "240000" # 4 minutes in milliseconds
  alarm_description   = "This metric monitors untagged resources remediation function duration"
  alarm_actions       = [var.sns_topic_arn]

  dimensions = {
    FunctionName = aws_lambda_function.untagged_resources_remediation[0].function_name
  }

  tags = merge(var.common_tags, {
    Name       = "tagging-remediation-duration-alarm"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })
}

# Custom CloudWatch metric for tagging remediation success rate
resource "aws_cloudwatch_log_metric_filter" "tagging_remediation_success" {
  count = var.enable_untagged_resources_remediation ? 1 : 0

  name           = "TaggingRemediationSuccess"
  log_group_name = var.cloudwatch_log_group_name
  pattern        = "[timestamp, request_id, level=\"INFO\", message=\"Untagged resource remediation completed successfully\"]"

  metric_transformation {
    name      = "TaggingRemediationSuccessCount"
    namespace = "UK/SecurityAutomation"
    value     = "1"
  }
}

# Custom CloudWatch metric for tagging remediation failures
resource "aws_cloudwatch_log_metric_filter" "tagging_remediation_failure" {
  count = var.enable_untagged_resources_remediation ? 1 : 0

  name           = "TaggingRemediationFailure"
  log_group_name = var.cloudwatch_log_group_name
  pattern        = "[timestamp, request_id, level=\"ERROR\", message=\"Untagged resource remediation failed\"]"

  metric_transformation {
    name      = "TaggingRemediationFailureCount"
    namespace = "UK/SecurityAutomation"
    value     = "1"
  }
}

# Custom CloudWatch metric for resource tagging operations
resource "aws_cloudwatch_log_metric_filter" "resource_tagging_operations" {
  count = var.enable_untagged_resources_remediation ? 1 : 0

  name           = "ResourceTaggingOperations"
  log_group_name = var.cloudwatch_log_group_name
  pattern        = "[timestamp, request_id, level=\"INFO\", message=\"Resource tagged\", resource_arn]"

  metric_transformation {
    name      = "ResourceTaggingCount"
    namespace = "UK/SecurityAutomation"
    value     = "1"
  }
}

# Custom CloudWatch metric for compliance tagging
resource "aws_cloudwatch_log_metric_filter" "uk_compliance_tagging" {
  count = var.enable_untagged_resources_remediation ? 1 : 0

  name           = "UKComplianceTagging"
  log_group_name = var.cloudwatch_log_group_name
  pattern        = "[timestamp, request_id, level=\"INFO\", message=\"compliance tags applied\", resource_arn]"

  metric_transformation {
    name      = "UKComplianceTaggingCount"
    namespace = "UK/SecurityAutomation"
    value     = "1"
  }
}

# CloudWatch dashboard widget for tagging remediation metrics
locals {
  tagging_remediation_dashboard_widget = var.enable_untagged_resources_remediation ? {
    type   = "metric"
    x      = 0
    y      = 6
    width  = 12
    height = 6

    properties = {
      metrics = [
        ["UK/SecurityAutomation", "TaggingRemediationSuccessCount"],
        [".", "TaggingRemediationFailureCount"],
        [".", "ResourceTaggingCount"],
        [".", "UKComplianceTaggingCount"],
        ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.untagged_resources_remediation[0].function_name],
        [".", "Errors", ".", "."],
        [".", "Duration", ".", "."]
      ]
      view    = "timeSeries"
      stacked = false
      region  = data.aws_region.current.name
      title   = "Untagged Resources Remediation Metrics"
      period  = 300
    }
  } : null
}

# IAM policy for resource tagging operations
resource "aws_iam_role_policy" "resource_tagging_policy" {
  count = var.enable_untagged_resources_remediation ? 1 : 0

  name = "uk-resource-tagging-policy"
  role = aws_iam_role.remediation_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ResourceTaggingPermissions"
        Effect = "Allow"
        Action = [
          "tag:TagResources",
          "tag:UntagResources",
          "tag:GetResources",
          "tag:GetTagKeys",
          "tag:GetTagValues"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = ["us-west-2", "us-east-1"]
          }
        }
      },
      {
        Sid    = "ServiceSpecificTaggingPermissions"
        Effect = "Allow"
        Action = [
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "s3:PutBucketTagging",
          "s3:GetBucketTagging",
          "rds:AddTagsToResource",
          "rds:RemoveTagsFromResource",
          "rds:ListTagsForResource",
          "lambda:TagResource",
          "lambda:UntagResource",
          "lambda:ListTags",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:TagUser",
          "iam:UntagUser",
          "iam:TagPolicy",
          "iam:UntagPolicy"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = ["us-west-2", "us-east-1"]
          }
        }
      },
      {
        Sid    = "UKComplianceTagValidation"
        Effect = "Allow"
        Action = [
          "organizations:DescribeAccount",
          "organizations:ListTagsForResource"
        ]
        Resource = "*"
      }
    ]
  })
}

# compliance tag validation rules
locals {
  uk_mandatory_tags = [
    "DataClassification",
    "Environment",
    "CostCenter",
    "Owner",
    "Project"
  ]

  uk_data_classification_values = [
    "public",
    "internal",
    "confidential",
    "restricted"
  ]

  uk_environment_values = [
    "production",
    "non-production",
    "sandbox",
    "development",
    "testing",
    "staging"
  ]
}

# Config rule for UK mandatory tagging compliance
resource "aws_config_config_rule" "uk_mandatory_tagging" {
  count = var.enable_untagged_resources_remediation ? 1 : 0

  name = "uk-mandatory-tagging-compliance"

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  input_parameters = jsonencode({
    requiredTagKeys = join(",", local.uk_mandatory_tags)
  })

  depends_on = [aws_lambda_function.untagged_resources_remediation]

  tags = merge(var.common_tags, {
    Name       = "uk-mandatory-tagging-rule"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })
}

# Config remediation configuration for UK tagging
resource "aws_config_remediation_configuration" "uk_tagging_remediation" {
  count = var.enable_untagged_resources_remediation ? 1 : 0

  config_rule_name = aws_config_config_rule.uk_mandatory_tagging[0].name

  resource_type              = "AWS::EC2::Instance"
  target_type                = "SSM_DOCUMENT"
  target_id                  = "AWSConfigRemediation-RemoveUnrestrictedSourceInSecurityGroup"
  target_version             = "1"
  automatic                  = false
  maximum_automatic_attempts = 3

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.remediation_lambda_role.arn
  }

  tags = merge(var.common_tags, {
    Name       = "uk-tagging-remediation-config"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })
}

# Output the dashboard widget configuration
output "tagging_remediation_dashboard_widget" {
  description = "CloudWatch dashboard widget configuration for tagging remediation"
  value       = local.tagging_remediation_dashboard_widget
}

# Output compliance tag configuration
output "uk_compliance_tag_configuration" {
  description = "compliance tag configuration"
  value = {
    mandatory_tags             = local.uk_mandatory_tags
    data_classification_values = local.uk_data_classification_values
    environment_values         = local.uk_environment_values
  }
}