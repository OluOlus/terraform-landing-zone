# KMS Encryption Module - Data Protection
# This module implements encryption key management with support for industry security standards and compliance requirements

# KMS Key for general encryption
resource "aws_kms_key" "main" {
  description              = var.key_description
  key_usage                = var.key_usage
  customer_master_key_spec = var.customer_master_key_spec
  deletion_window_in_days  = var.deletion_window_in_days
  is_enabled               = var.is_enabled
  enable_key_rotation      = var.enable_key_rotation
  multi_region             = var.multi_region

  policy = var.key_policy != null ? var.key_policy : data.aws_iam_policy_document.kms_key_policy.json

  tags = merge(var.common_tags, {
    Name               = var.key_name
    Purpose            = var.key_purpose
    DataClassification = "confidential"
    Compliance         = "Security Standards-UK-GDPR"
  })
}

# KMS Key Alias
resource "aws_kms_alias" "main" {
  name          = "alias/${var.key_alias}"
  target_key_id = aws_kms_key.main.key_id
}

# Default KMS Key Policy (if not provided)
data "aws_iam_policy_document" "kms_key_policy" {
  # Enable IAM policies
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # CloudTrail access
  dynamic "statement" {
    for_each = var.allow_cloudtrail_access ? [1] : []
    content {
      sid    = "Allow CloudTrail to encrypt logs"
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
      actions = [
        "kms:GenerateDataKey*",
        "kms:DecryptDataKey"
      ]
      resources = ["*"]
      condition {
        test     = "StringLike"
        variable = "kms:EncryptionContext:aws:cloudtrail:arn"
        values   = ["arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"]
      }
    }
  }

  # CloudWatch Logs access
  dynamic "statement" {
    for_each = var.allow_cloudwatch_logs_access ? [1] : []
    content {
      sid    = "Allow CloudWatch Logs to use the key"
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
      }
      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:CreateGrant",
        "kms:DescribeKey"
      ]
      resources = ["*"]
      condition {
        test     = "ArnLike"
        variable = "kms:EncryptionContext:aws:logs:arn"
        values   = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"]
      }
    }
  }

  # S3 access
  dynamic "statement" {
    for_each = var.allow_s3_access ? [1] : []
    content {
      sid    = "Allow S3 to use the key"
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = ["s3.amazonaws.com"]
      }
      actions = [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ]
      resources = ["*"]
    }
  }

  # Config access
  dynamic "statement" {
    for_each = var.allow_config_access ? [1] : []
    content {
      sid    = "Allow AWS Config to use the key"
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = ["config.amazonaws.com"]
      }
      actions = [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ]
      resources = ["*"]
    }
  }

  # SNS access
  dynamic "statement" {
    for_each = var.allow_sns_access ? [1] : []
    content {
      sid    = "Allow SNS to use the key"
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = ["sns.amazonaws.com"]
      }
      actions = [
        "kms:Decrypt",
        "kms:GenerateDataKey*"
      ]
      resources = ["*"]
    }
  }

  # Organization access
  dynamic "statement" {
    for_each = var.organization_id != null ? [1] : []
    content {
      sid    = "Allow organization accounts to use the key"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = ["*"]
      }
      actions = [
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:CreateGrant"
      ]
      resources = ["*"]
      condition {
        test     = "StringEquals"
        variable = "aws:PrincipalOrgID"
        values   = [var.organization_id]
      }
    }
  }

  # Additional principals
  dynamic "statement" {
    for_each = length(var.additional_key_users) > 0 ? [1] : []
    content {
      sid    = "Allow additional principals to use the key"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = var.additional_key_users
      }
      actions = [
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:CreateGrant",
        "kms:GenerateDataKey*"
      ]
      resources = ["*"]
    }
  }

  # VPC Flow Logs access
  dynamic "statement" {
    for_each = var.allow_vpc_flow_logs_access ? [1] : []
    content {
      sid    = "Allow VPC Flow Logs to use the key"
      effect = "Allow"
      principals {
        type        = "Service"
        identifiers = ["delivery.logs.amazonaws.com"]
      }
      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:CreateGrant",
        "kms:DescribeKey"
      ]
      resources = ["*"]
    }
  }
}

# CloudWatch Alarm for key usage
resource "aws_cloudwatch_metric_alarm" "kms_key_disabled" {
  count               = var.enable_key_monitoring ? 1 : 0
  alarm_name          = "${var.key_name}-key-disabled"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "KeyState"
  namespace           = "AWS/KMS"
  period              = 300
  statistic           = "Minimum"
  threshold           = 1
  alarm_description   = "KMS key has been disabled"
  alarm_actions       = var.alarm_sns_topic_arns
  treat_missing_data  = "notBreaching"

  dimensions = {
    KeyId = aws_kms_key.main.key_id
  }

  tags = var.common_tags
}

# CloudWatch Alarm for key pending deletion
resource "aws_cloudwatch_metric_alarm" "kms_key_pending_deletion" {
  count               = var.enable_key_monitoring ? 1 : 0
  alarm_name          = "${var.key_name}-pending-deletion"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ScheduledDeletionDate"
  namespace           = "AWS/KMS"
  period              = 300
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "KMS key is scheduled for deletion"
  alarm_actions       = var.alarm_sns_topic_arns
  treat_missing_data  = "notBreaching"

  dimensions = {
    KeyId = aws_kms_key.main.key_id
  }

  tags = var.common_tags
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# KMS Grant for specific services (if needed)
resource "aws_kms_grant" "service_grants" {
  for_each = var.service_grants

  name              = each.key
  key_id            = aws_kms_key.main.key_id
  grantee_principal = each.value.grantee_principal
  operations        = each.value.operations

  dynamic "constraints" {
    for_each = each.value.constraints != null ? [each.value.constraints] : []
    content {
      encryption_context_equals = constraints.value.encryption_context_equals
      encryption_context_subset = constraints.value.encryption_context_subset
    }
  }
}

# Replica key for multi-region setup
resource "aws_kms_replica_key" "replica" {
  count                   = var.create_replica_key ? 1 : 0
  provider                = aws.replica
  description             = "${var.key_description} - Replica in ${var.replica_region}"
  primary_key_arn         = aws_kms_key.main.arn
  deletion_window_in_days = var.deletion_window_in_days
  enabled                 = var.is_enabled

  tags = merge(var.common_tags, {
    Name               = "${var.key_name}-replica"
    Purpose            = "${var.key_purpose} - Replica"
    DataClassification = "confidential"
    Compliance         = "Security Standards-UK-GDPR"
    Region             = var.replica_region
  })
}

# Replica key alias
resource "aws_kms_alias" "replica" {
  count         = var.create_replica_key ? 1 : 0
  provider      = aws.replica
  name          = "alias/${var.key_alias}-replica"
  target_key_id = aws_kms_replica_key.replica[0].key_id
}
