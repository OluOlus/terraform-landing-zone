# Security Automation Remediation Functions
# This module contains Lambda functions for automated security remediation

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# Data source for current AWS region
data "aws_region" "current" {}

# Archive files for Lambda functions
data "archive_file" "security_hub_orchestrator_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_packages/security_hub_orchestrator.zip"

  source {
    content = templatefile("${path.module}/lambda_code/security_hub_orchestrator.py", {
      sns_topic_arn      = var.sns_topic_arn
      remediation_bucket = var.remediation_bucket_name
    })
    filename = "index.py"
  }
}

data "archive_file" "guardduty_orchestrator_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_packages/guardduty_orchestrator.zip"

  source {
    content = templatefile("${path.module}/lambda_code/guardduty_orchestrator.py", {
      sns_topic_arn      = var.sns_topic_arn
      remediation_bucket = var.remediation_bucket_name
    })
    filename = "index.py"
  }
}

data "archive_file" "config_orchestrator_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_packages/config_orchestrator.zip"

  source {
    content = templatefile("${path.module}/lambda_code/config_orchestrator.py", {
      sns_topic_arn      = var.sns_topic_arn
      remediation_bucket = var.remediation_bucket_name
    })
    filename = "index.py"
  }
}

# IAM role for Lambda functions
resource "aws_iam_role" "remediation_lambda_role" {
  name = "uk-security-automation-lambda-role"

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

  tags = merge(var.common_tags, {
    Name       = "security-automation-lambda-role"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })
}

# IAM policy for Lambda basic execution
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.remediation_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# IAM policy for remediation actions
resource "aws_iam_role_policy" "remediation_policy" {
  name = "uk-security-automation-remediation-policy"
  role = aws_iam_role.remediation_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3RemediationPermissions"
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketPolicy",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketAcl",
          "s3:PutBucketPolicy",
          "s3:PutBucketPublicAccessBlock",
          "s3:DeleteBucketPolicy",
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = [
          "arn:aws:s3:::*",
          "arn:aws:s3:::*/*"
        ]
      },
      {
        Sid    = "EC2RemediationPermissions"
        Effect = "Allow"
        Action = [
          "ec2:DescribeVolumes",
          "ec2:DescribeSnapshots",
          "ec2:DescribeInstances",
          "ec2:CreateSnapshot",
          "ec2:ModifyVolumeAttribute",
          "ec2:CreateTags",
          "ec2:DescribeTags",
          "ec2:StopInstances",
          "ec2:StartInstances"
        ]
        Resource = "*"
      },
      {
        Sid    = "KMSPermissions"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:ReEncrypt*"
        ]
        Resource = [
          var.kms_key_arn,
          "arn:aws:kms:*:${data.aws_caller_identity.current.account_id}:key/*"
        ]
      },
      {
        Sid    = "SNSNotificationPermissions"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = var.sns_topic_arn
      },
      {
        Sid    = "CloudWatchLogsPermissions"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Sid    = "SecurityHubPermissions"
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:BatchUpdateFindings"
        ]
        Resource = "*"
      },
      {
        Sid    = "ConfigPermissions"
        Effect = "Allow"
        Action = [
          "config:GetResourceConfigHistory",
          "config:GetComplianceDetailsByResource",
          "config:PutEvaluations"
        ]
        Resource = "*"
      },
      {
        Sid    = "LambdaInvocationPermissions"
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = [
          "arn:aws:lambda:*:${data.aws_caller_identity.current.account_id}:function:uk-*"
        ]
      },
      {
        Sid    = "ResourceGroupsTaggingPermissions"
        Effect = "Allow"
        Action = [
          "tag:GetResources",
          "tag:TagResources",
          "tag:UntagResources",
          "tag:GetTagKeys",
          "tag:GetTagValues"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3ArtifactsBucketPermissions"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${var.remediation_bucket_arn}/*"
      }
    ]
  })
}

# Lambda function for S3 public access remediation
resource "aws_lambda_function" "s3_public_access_remediation" {
  count = var.enable_s3_public_access_remediation ? 1 : 0

  filename         = data.archive_file.s3_public_access_zip[0].output_path
  function_name    = "uk-s3-public-access-remediation"
  role             = aws_iam_role.remediation_lambda_role.arn
  handler          = "index.lambda_handler"
  source_code_hash = data.archive_file.s3_public_access_zip[0].output_base64sha256
  runtime          = "python3.11"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size

  environment {
    variables = {
      SNS_TOPIC_ARN      = var.sns_topic_arn
      REMEDIATION_BUCKET = var.remediation_bucket_name
      DRY_RUN            = "false"
      UK_COMPLIANCE_MODE = "true"
      LOG_LEVEL          = "INFO"
    }
  }

  kms_key_arn = var.kms_key_arn

  tags = merge(var.common_tags, {
    Name       = "s3-public-access-remediation"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })

  depends_on = [aws_iam_role_policy.remediation_policy]
}

# Lambda function for unencrypted volumes remediation
resource "aws_lambda_function" "unencrypted_volumes_remediation" {
  count = var.enable_unencrypted_volumes_remediation ? 1 : 0

  filename         = data.archive_file.unencrypted_volumes_zip[0].output_path
  function_name    = "uk-unencrypted-volumes-remediation"
  role             = aws_iam_role.remediation_lambda_role.arn
  handler          = "index.lambda_handler"
  source_code_hash = data.archive_file.unencrypted_volumes_zip[0].output_base64sha256
  runtime          = "python3.11"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size

  environment {
    variables = {
      SNS_TOPIC_ARN      = var.sns_topic_arn
      REMEDIATION_BUCKET = var.remediation_bucket_name
      DRY_RUN            = "false"
      UK_COMPLIANCE_MODE = "true"
      LOG_LEVEL          = "INFO"
      KMS_KEY_ID         = var.kms_key_arn
    }
  }

  kms_key_arn = var.kms_key_arn

  tags = merge(var.common_tags, {
    Name       = "unencrypted-volumes-remediation"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })

  depends_on = [aws_iam_role_policy.remediation_policy]
}

# Lambda function for untagged resources remediation
resource "aws_lambda_function" "untagged_resources_remediation" {
  count = var.enable_untagged_resources_remediation ? 1 : 0

  filename         = data.archive_file.untagged_resources_zip[0].output_path
  function_name    = "uk-untagged-resources-remediation"
  role             = aws_iam_role.remediation_lambda_role.arn
  handler          = "index.lambda_handler"
  source_code_hash = data.archive_file.untagged_resources_zip[0].output_base64sha256
  runtime          = "python3.11"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size

  environment {
    variables = {
      SNS_TOPIC_ARN      = var.sns_topic_arn
      REMEDIATION_BUCKET = var.remediation_bucket_name
      DRY_RUN            = "false"
      UK_COMPLIANCE_MODE = "true"
      LOG_LEVEL          = "INFO"
      MANDATORY_TAGS     = jsonencode(["DataClassification", "Environment", "CostCenter", "Owner", "Project"])
      DEFAULT_TAGS = jsonencode({
        DataClassification = "internal"
        Environment        = "unknown"
        CostCenter         = "unassigned"
        Owner              = "security-team"
        Project            = "uk-landing-zone"
      })
    }
  }

  kms_key_arn = var.kms_key_arn

  tags = merge(var.common_tags, {
    Name       = "untagged-resources-remediation"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })

  depends_on = [aws_iam_role_policy.remediation_policy]
}

# Orchestrator Lambda functions
resource "aws_lambda_function" "security_hub_orchestrator" {
  filename         = data.archive_file.security_hub_orchestrator_zip.output_path
  function_name    = "uk-security-hub-orchestrator"
  role             = aws_iam_role.remediation_lambda_role.arn
  handler          = "index.lambda_handler"
  source_code_hash = data.archive_file.security_hub_orchestrator_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size

  environment {
    variables = {
      SNS_TOPIC_ARN                = var.sns_topic_arn
      REMEDIATION_BUCKET           = var.remediation_bucket_name
      S3_REMEDIATION_FUNCTION      = var.enable_s3_public_access_remediation ? aws_lambda_function.s3_public_access_remediation[0].function_name : ""
      VOLUMES_REMEDIATION_FUNCTION = var.enable_unencrypted_volumes_remediation ? aws_lambda_function.unencrypted_volumes_remediation[0].function_name : ""
      TAGGING_REMEDIATION_FUNCTION = var.enable_untagged_resources_remediation ? aws_lambda_function.untagged_resources_remediation[0].function_name : ""
      LOG_LEVEL                    = "INFO"
    }
  }

  kms_key_arn = var.kms_key_arn

  tags = merge(var.common_tags, {
    Name       = "security-hub-orchestrator"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })

  depends_on = [aws_iam_role_policy.remediation_policy]
}

resource "aws_lambda_function" "guardduty_orchestrator" {
  filename         = data.archive_file.guardduty_orchestrator_zip.output_path
  function_name    = "uk-guardduty-orchestrator"
  role             = aws_iam_role.remediation_lambda_role.arn
  handler          = "index.lambda_handler"
  source_code_hash = data.archive_file.guardduty_orchestrator_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size

  environment {
    variables = {
      SNS_TOPIC_ARN      = var.sns_topic_arn
      REMEDIATION_BUCKET = var.remediation_bucket_name
      LOG_LEVEL          = "INFO"
    }
  }

  kms_key_arn = var.kms_key_arn

  tags = merge(var.common_tags, {
    Name       = "guardduty-orchestrator"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })

  depends_on = [aws_iam_role_policy.remediation_policy]
}

resource "aws_lambda_function" "config_orchestrator" {
  filename         = data.archive_file.config_orchestrator_zip.output_path
  function_name    = "uk-config-orchestrator"
  role             = aws_iam_role.remediation_lambda_role.arn
  handler          = "index.lambda_handler"
  source_code_hash = data.archive_file.config_orchestrator_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size

  environment {
    variables = {
      SNS_TOPIC_ARN                = var.sns_topic_arn
      REMEDIATION_BUCKET           = var.remediation_bucket_name
      S3_REMEDIATION_FUNCTION      = var.enable_s3_public_access_remediation ? aws_lambda_function.s3_public_access_remediation[0].function_name : ""
      VOLUMES_REMEDIATION_FUNCTION = var.enable_unencrypted_volumes_remediation ? aws_lambda_function.unencrypted_volumes_remediation[0].function_name : ""
      TAGGING_REMEDIATION_FUNCTION = var.enable_untagged_resources_remediation ? aws_lambda_function.untagged_resources_remediation[0].function_name : ""
      LOG_LEVEL                    = "INFO"
    }
  }

  kms_key_arn = var.kms_key_arn

  tags = merge(var.common_tags, {
    Name       = "config-orchestrator"
    Purpose    = "security-automation"
    Compliance = "Security Standards,UK-GDPR"
  })

  depends_on = [aws_iam_role_policy.remediation_policy]
}

# Lambda permissions for cross-function invocation
resource "aws_lambda_permission" "orchestrator_invoke_s3_remediation" {
  count = var.enable_s3_public_access_remediation ? 3 : 0

  statement_id  = "AllowOrchestrator${count.index}InvokeS3Remediation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_public_access_remediation[0].function_name
  principal     = "lambda.amazonaws.com"
  source_arn    = count.index == 0 ? aws_lambda_function.security_hub_orchestrator.arn : (count.index == 1 ? aws_lambda_function.guardduty_orchestrator.arn : aws_lambda_function.config_orchestrator.arn)
}

resource "aws_lambda_permission" "orchestrator_invoke_volumes_remediation" {
  count = var.enable_unencrypted_volumes_remediation ? 3 : 0

  statement_id  = "AllowOrchestrator${count.index}InvokeVolumesRemediation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.unencrypted_volumes_remediation[0].function_name
  principal     = "lambda.amazonaws.com"
  source_arn    = count.index == 0 ? aws_lambda_function.security_hub_orchestrator.arn : (count.index == 1 ? aws_lambda_function.guardduty_orchestrator.arn : aws_lambda_function.config_orchestrator.arn)
}

resource "aws_lambda_permission" "orchestrator_invoke_tagging_remediation" {
  count = var.enable_untagged_resources_remediation ? 3 : 0

  statement_id  = "AllowOrchestrator${count.index}InvokeTaggingRemediation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.untagged_resources_remediation[0].function_name
  principal     = "lambda.amazonaws.com"
  source_arn    = count.index == 0 ? aws_lambda_function.security_hub_orchestrator.arn : (count.index == 1 ? aws_lambda_function.guardduty_orchestrator.arn : aws_lambda_function.config_orchestrator.arn)
}