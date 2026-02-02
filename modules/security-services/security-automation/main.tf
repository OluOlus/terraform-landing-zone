# Security Automation Module - UK Compliance Automated Remediation
# This module provides automated security remediation capabilities for the UK AWS Secure Landing Zone
# Integrates with Security Hub, GuardDuty, and Config for automated response to security violations

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# Data source for current AWS region
data "aws_region" "current" {}

# KMS key for encrypting Lambda function environment variables and logs
resource "aws_kms_key" "security_automation" {
  description             = "KMS key for Security Automation module encryption"
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
        Sid    = "Allow Lambda service to use the key"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs to use the key"
        Effect = "Allow"
        Principal = {
          Service = "logs.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.common_tags, {
    Name       = "security-automation-kms-key"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })
}

# KMS key alias
resource "aws_kms_alias" "security_automation" {
  name          = "alias/uk-landing-zone-security-automation"
  target_key_id = aws_kms_key.security_automation.key_id
}

# S3 bucket for storing remediation artifacts and logs
resource "aws_s3_bucket" "remediation_artifacts" {
  bucket = "${var.remediation_bucket_prefix}-${random_id.bucket_suffix.hex}"

  tags = merge(var.common_tags, {
    Name       = "security-automation-artifacts"
    Purpose    = "remediation-artifacts"
    Compliance = "Security Standards,UK-GDPR"
  })
}

# Random ID for bucket suffix
resource "random_id" "bucket_suffix" {
  byte_length = 8
}

# S3 bucket versioning
resource "aws_s3_bucket_versioning" "remediation_artifacts" {
  bucket = aws_s3_bucket.remediation_artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 bucket encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "remediation_artifacts" {
  bucket = aws_s3_bucket.remediation_artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.security_automation.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# S3 bucket public access block
resource "aws_s3_bucket_public_access_block" "remediation_artifacts" {
  bucket = aws_s3_bucket.remediation_artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 bucket lifecycle configuration
resource "aws_s3_bucket_lifecycle_configuration" "remediation_artifacts" {
  bucket = aws_s3_bucket.remediation_artifacts.id

  rule {
    id     = "remediation_logs_lifecycle"
    status = "Enabled"

    expiration {
      days = var.remediation_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# CloudWatch Log Group for security automation
resource "aws_cloudwatch_log_group" "security_automation" {
  name              = "/aws/lambda/uk-security-automation"
  retention_in_days = var.cloudwatch_log_retention_days
  kms_key_id        = aws_kms_key.security_automation.arn

  tags = merge(var.common_tags, {
    Name       = "security-automation-logs"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })
}

# SNS topic for security automation notifications
resource "aws_sns_topic" "security_automation_notifications" {
  name              = "uk-security-automation-notifications"
  kms_master_key_id = aws_kms_key.security_automation.arn

  tags = merge(var.common_tags, {
    Name       = "security-automation-notifications"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })
}

# EventBridge rule for Security Hub findings
resource "aws_cloudwatch_event_rule" "security_hub_findings" {
  name        = "uk-security-hub-findings"
  description = "Capture Security Hub findings for automated remediation"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Compliance = {
          Status = ["FAILED"]
        }
        Severity = {
          Label = var.remediation_severity_levels
        }
        RecordState   = ["ACTIVE"]
        WorkflowState = ["NEW"]
      }
    }
  })

  tags = merge(var.common_tags, {
    Name       = "security-hub-findings-rule"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })
}

# EventBridge rule for GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "uk-guardduty-findings"
  description = "Capture GuardDuty findings for automated remediation"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = var.guardduty_remediation_severities
    }
  })

  tags = merge(var.common_tags, {
    Name       = "guardduty-findings-rule"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })
}

# EventBridge rule for Config compliance changes
resource "aws_cloudwatch_event_rule" "config_compliance" {
  name        = "uk-config-compliance-changes"
  description = "Capture Config compliance changes for automated remediation"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })

  tags = merge(var.common_tags, {
    Name       = "config-compliance-rule"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })
}

# Include remediation functions
module "remediation_functions" {
  source = "./remediation"

  # Pass through variables
  kms_key_arn                            = aws_kms_key.security_automation.arn
  remediation_bucket_name                = aws_s3_bucket.remediation_artifacts.bucket
  sns_topic_arn                          = aws_sns_topic.security_automation_notifications.arn
  cloudwatch_log_group_name              = aws_cloudwatch_log_group.security_automation.name
  enable_s3_public_access_remediation    = var.enable_s3_public_access_remediation
  enable_unencrypted_volumes_remediation = var.enable_unencrypted_volumes_remediation
  enable_untagged_resources_remediation  = var.enable_untagged_resources_remediation
  lambda_timeout                         = var.lambda_timeout
  lambda_memory_size                     = var.lambda_memory_size
  common_tags                            = var.common_tags

  # Dependencies
  depends_on = [
    aws_kms_key.security_automation,
    aws_s3_bucket.remediation_artifacts,
    aws_sns_topic.security_automation_notifications,
    aws_cloudwatch_log_group.security_automation
  ]
}

# EventBridge targets for remediation functions
resource "aws_cloudwatch_event_target" "security_hub_remediation" {
  rule      = aws_cloudwatch_event_rule.security_hub_findings.name
  target_id = "SecurityHubRemediationTarget"
  arn       = module.remediation_functions.security_hub_orchestrator_arn

  input_transformer {
    input_paths = {
      findings = "$.detail.findings"
      account  = "$.account"
      region   = "$.region"
    }
    input_template = jsonencode({
      source   = "security-hub"
      findings = "<findings>"
      account  = "<account>"
      region   = "<region>"
    })
  }
}

resource "aws_cloudwatch_event_target" "guardduty_remediation" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "GuardDutyRemediationTarget"
  arn       = module.remediation_functions.guardduty_orchestrator_arn

  input_transformer {
    input_paths = {
      finding = "$.detail"
      account = "$.account"
      region  = "$.region"
    }
    input_template = jsonencode({
      source  = "guardduty"
      finding = "<finding>"
      account = "<account>"
      region  = "<region>"
    })
  }
}

resource "aws_cloudwatch_event_target" "config_remediation" {
  rule      = aws_cloudwatch_event_rule.config_compliance.name
  target_id = "ConfigRemediationTarget"
  arn       = module.remediation_functions.config_orchestrator_arn

  input_transformer {
    input_paths = {
      configRuleName      = "$.detail.configRuleName"
      resourceType        = "$.detail.resourceType"
      resourceId          = "$.detail.resourceId"
      newEvaluationResult = "$.detail.newEvaluationResult"
      account             = "$.account"
      region              = "$.region"
    }
    input_template = jsonencode({
      source           = "config"
      configRuleName   = "<configRuleName>"
      resourceType     = "<resourceType>"
      resourceId       = "<resourceId>"
      evaluationResult = "<newEvaluationResult>"
      account          = "<account>"
      region           = "<region>"
    })
  }
}

# Lambda permissions for EventBridge
resource "aws_lambda_permission" "allow_eventbridge_security_hub" {
  statement_id  = "AllowExecutionFromEventBridgeSecurityHub"
  action        = "lambda:InvokeFunction"
  function_name = module.remediation_functions.security_hub_orchestrator_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.security_hub_findings.arn
}

resource "aws_lambda_permission" "allow_eventbridge_guardduty" {
  statement_id  = "AllowExecutionFromEventBridgeGuardDuty"
  action        = "lambda:InvokeFunction"
  function_name = module.remediation_functions.guardduty_orchestrator_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
}

resource "aws_lambda_permission" "allow_eventbridge_config" {
  statement_id  = "AllowExecutionFromEventBridgeConfig"
  action        = "lambda:InvokeFunction"
  function_name = module.remediation_functions.config_orchestrator_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.config_compliance.arn
}