# Account Vending Module
# Implements automated account provisioning with UK tags and baseline configurations
# Requirements: 1.3, 2.2

terraform {
  required_version = ">= 1.5.0"

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

# Data source to get the current organization
data "aws_organizations_organization" "current" {}

# Data source to get caller identity for account ID
data "aws_caller_identity" "current" {}

# Create accounts using AWS Organizations
resource "aws_organizations_account" "workload_accounts" {
  for_each = var.workload_accounts

  name                       = each.value.name
  email                      = each.value.email
  parent_id                  = each.value.organizational_unit_id
  role_name                  = var.account_access_role_name
  iam_user_access_to_billing = var.iam_user_access_to_billing
  close_on_deletion          = var.close_on_deletion

  tags = merge(var.common_tags, each.value.tags, {
    AccountType         = each.value.account_type
    DataClassification  = each.value.data_classification
    Environment         = each.value.environment
    CostCenter          = each.value.cost_center
    Owner               = each.value.owner
    Project             = each.value.project
    BackupSchedule      = each.value.backup_schedule
    MaintenanceWindow   = each.value.maintenance_window
    ComplianceFramework = "Security Standards-UK-GDPR"
    DataResidency       = "UK"
    CreatedBy           = "Account-Vending-Module"
    CreatedDate         = formatdate("YYYY-MM-DD", timestamp())
  })

  lifecycle {
    ignore_changes = [
      tags["CreatedDate"]
    ]
  }
}

# Create baseline IAM roles for cross-account access
resource "aws_iam_role" "cross_account_access" {
  for_each = var.workload_accounts

  name = "${each.value.name}-CrossAccountAccess"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
            "arn:aws:iam::${var.security_account_id}:root",
            "arn:aws:iam::${var.logging_account_id}:root"
          ]
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = each.value.external_id
          }
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  tags = merge(var.common_tags, {
    Purpose     = "Cross-account access for ${each.value.name}"
    AccountType = each.value.account_type
  })
}

# Attach baseline policies to cross-account access roles
resource "aws_iam_role_policy_attachment" "cross_account_readonly" {
  for_each = var.workload_accounts

  role       = aws_iam_role.cross_account_access[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Create account-specific KMS keys for encryption
resource "aws_kms_key" "account_keys" {
  for_each = var.enable_account_kms_keys ? var.workload_accounts : {}

  description             = "KMS key for ${each.value.name} account encryption"
  deletion_window_in_days = var.kms_key_deletion_window
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${aws_organizations_account.workload_accounts[each.key].id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Management Account Access"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "kms:Describe*",
          "kms:List*",
          "kms:Get*"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow Security Account Access"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.security_account_id}:root"
        }
        Action = [
          "kms:Describe*",
          "kms:List*",
          "kms:Get*",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.common_tags, {
    Purpose     = "Account encryption for ${each.value.name}"
    AccountType = each.value.account_type
  })
}

# Create KMS key aliases
resource "aws_kms_alias" "account_key_aliases" {
  for_each = var.enable_account_kms_keys ? var.workload_accounts : {}

  name          = "alias/${lower(replace(each.value.name, " ", "-"))}-account-key"
  target_key_id = aws_kms_key.account_keys[each.key].key_id
}

# Create baseline S3 buckets for account logging and configuration
resource "aws_s3_bucket" "account_baseline_buckets" {
  for_each = var.create_baseline_s3_buckets ? var.workload_accounts : {}

  bucket        = "${lower(replace(each.value.name, " ", "-"))}-baseline-${random_id.bucket_suffix[each.key].hex}"
  force_destroy = var.force_destroy_buckets

  tags = merge(var.common_tags, {
    Purpose            = "Baseline configuration storage for ${each.value.name}"
    AccountType        = each.value.account_type
    DataClassification = each.value.data_classification
  })
}

# Configure S3 bucket encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "account_baseline_encryption" {
  for_each = var.create_baseline_s3_buckets ? var.workload_accounts : {}

  bucket = aws_s3_bucket.account_baseline_buckets[each.key].id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.enable_account_kms_keys ? aws_kms_key.account_keys[each.key].arn : null
      sse_algorithm     = var.enable_account_kms_keys ? "aws:kms" : "AES256"
    }
    bucket_key_enabled = var.enable_account_kms_keys
  }
}

# Configure S3 bucket versioning
resource "aws_s3_bucket_versioning" "account_baseline_versioning" {
  for_each = var.create_baseline_s3_buckets ? var.workload_accounts : {}

  bucket = aws_s3_bucket.account_baseline_buckets[each.key].id
  versioning_configuration {
    status = "Enabled"
  }
}

# Configure S3 bucket public access block
resource "aws_s3_bucket_public_access_block" "account_baseline_public_access_block" {
  for_each = var.create_baseline_s3_buckets ? var.workload_accounts : {}

  bucket = aws_s3_bucket.account_baseline_buckets[each.key].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Configure S3 bucket lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "account_baseline_lifecycle" {
  for_each = var.create_baseline_s3_buckets ? var.workload_accounts : {}

  bucket = aws_s3_bucket.account_baseline_buckets[each.key].id

  rule {
    id     = "baseline_lifecycle"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = var.s3_lifecycle_expiration_days
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

# Random ID for unique resource naming
resource "random_id" "bucket_suffix" {
  for_each = var.create_baseline_s3_buckets ? var.workload_accounts : {}

  byte_length = 8
}

# Create account-specific budgets for cost management
resource "aws_budgets_budget" "account_budgets" {
  for_each = var.create_account_budgets ? var.workload_accounts : {}

  name              = "${each.value.name}-Monthly-Budget"
  budget_type       = "COST"
  limit_amount      = each.value.monthly_budget_limit
  limit_unit        = "USD"
  time_unit         = "MONTHLY"
  time_period_start = formatdate("YYYY-MM-01_00:00", timestamp())

  cost_filter {
    name   = "LinkedAccount"
    values = [aws_organizations_account.workload_accounts[each.key].id]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [each.value.budget_notification_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [each.value.budget_notification_email]
  }

  tags = merge(var.common_tags, {
    Purpose     = "Cost management for ${each.value.name}"
    AccountType = each.value.account_type
  })
}

# Create CloudFormation StackSets for baseline configuration deployment
resource "aws_cloudformation_stack_set" "account_baseline" {
  count = var.deploy_baseline_stackset ? 1 : 0

  name             = "UK-Landing-Zone-Account-Baseline"
  description      = "Baseline configuration for UK Landing Zone accounts"
  permission_model = "SERVICE_MANAGED"
  capabilities     = ["CAPABILITY_NAMED_IAM"]

  auto_deployment {
    enabled                          = true
    retain_stacks_on_account_removal = false
  }

  operation_preferences {
    failure_tolerance_count = 1
    max_concurrent_count    = 5
    region_concurrency_type = "PARALLEL"
    region_order            = ["us-east-1", "us-west-2"]
  }

  template_body = jsonencode({
    AWSTemplateFormatVersion = "2010-09-09"
    Description              = "AWS Landing Zone Account Baseline Configuration"

    Resources = {
      BaselineConfigRecorder = {
        Type = "AWS::Config::ConfigurationRecorder"
        Properties = {
          Name    = "uk-landing-zone-baseline-recorder"
          RoleARN = { "Fn::GetAtt" = ["BaselineConfigRole", "Arn"] }
          RecordingGroup = {
            AllSupported               = true
            IncludeGlobalResourceTypes = true
          }
        }
      }

      BaselineConfigRole = {
        Type = "AWS::IAM::Role"
        Properties = {
          RoleName = "uk-landing-zone-baseline-config-role"
          AssumeRolePolicyDocument = {
            Version = "2012-10-17"
            Statement = [{
              Effect    = "Allow"
              Principal = { Service = "config.amazonaws.com" }
              Action    = "sts:AssumeRole"
            }]
          }
          ManagedPolicyArns = [
            "arn:aws:iam::aws:policy/service-role/ConfigRole"
          ]
          Tags = [
            { Key = "Purpose", Value = "UK Landing Zone Baseline Config" },
            { Key = "ManagedBy", Value = "CloudFormation-StackSet" }
          ]
        }
      }
    }
  })

  tags = merge(var.common_tags, {
    Purpose = "Account baseline configuration deployment"
  })
}

# Deploy StackSet to organizational units
resource "aws_cloudformation_stack_set_instance" "account_baseline_instances" {
  for_each = var.deploy_baseline_stackset ? var.organizational_unit_deployments : {}

  stack_set_name = aws_cloudformation_stack_set.account_baseline[0].name
  deployment_targets {
    organizational_unit_ids = [each.value.ou_id]
  }
  region = each.value.region

  operation_preferences {
    failure_tolerance_count = 1
    max_concurrent_count    = 5
    region_concurrency_type = "PARALLEL"
  }

  depends_on = [aws_cloudformation_stack_set.account_baseline]
}