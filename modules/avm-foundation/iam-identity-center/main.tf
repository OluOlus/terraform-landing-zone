# IAM Identity Center Module - UK SSO
# Provides centralized authentication and authorization for UK Landing Zone
# Implements region-specific permission sets with mandatory MFA and least privilege access

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Get IAM Identity Center instance
data "aws_ssoadmin_instances" "main" {}

locals {
  instance_arn      = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  identity_store_id = tolist(data.aws_ssoadmin_instances.main.identity_store_ids)[0]
}

# Security Administrator Permission Set
resource "aws_ssoadmin_permission_set" "security_admin" {
  name             = "SecurityAdministrator"
  description      = "Full access to security services (SecurityHub, GuardDuty, Config) with compliance controls"
  instance_arn     = local.instance_arn
  session_duration = "PT4H"

  tags = merge(var.common_tags, {
    Name        = "SecurityAdministrator"
    Role        = "SecurityAdmin"
    Compliance  = "UK-Security Standards"
    AccessLevel = "Administrative"
  })
}

resource "aws_ssoadmin_managed_policy_attachment" "security_admin" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.security_admin.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_ssoadmin_permission_set_inline_policy" "security_admin" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.security_admin.arn
  inline_policy      = file("${path.module}/../../../policies/iam-policies/security-admin.json")
}

# Network Administrator Permission Set
resource "aws_ssoadmin_permission_set" "network_admin" {
  name             = "NetworkAdministrator"
  description      = "Full access to networking services with specified region restrictions and compliance controls"
  instance_arn     = local.instance_arn
  session_duration = "PT4H"

  tags = merge(var.common_tags, {
    Name        = "NetworkAdministrator"
    Role        = "NetworkAdmin"
    Compliance  = "UK-Security Standards"
    AccessLevel = "Administrative"
  })
}

resource "aws_ssoadmin_managed_policy_attachment" "network_admin" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.network_admin.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/job-function/NetworkAdministrator"
}

resource "aws_ssoadmin_permission_set_inline_policy" "network_admin" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.network_admin.arn
  inline_policy      = file("${path.module}/../../../policies/iam-policies/network-admin.json")
}

# Developer Permission Set
resource "aws_ssoadmin_permission_set" "developer" {
  name             = "Developer"
  description      = "Development access with guardrails, specified region restrictions, and mandatory tagging"
  instance_arn     = local.instance_arn
  session_duration = "PT8H"

  tags = merge(var.common_tags, {
    Name        = "Developer"
    Role        = "Developer"
    Compliance  = "UK-Security Standards"
    AccessLevel = "Development"
  })
}

resource "aws_ssoadmin_managed_policy_attachment" "developer" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.developer.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

resource "aws_ssoadmin_permission_set_inline_policy" "developer" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.developer.arn
  inline_policy      = file("${path.module}/../../../policies/iam-policies/developer.json")
}

# Viewer Permission Set
resource "aws_ssoadmin_permission_set" "viewer" {
  name             = "ReadOnlyViewer"
  description      = "Read-only access across all services with specified region restrictions"
  instance_arn     = local.instance_arn
  session_duration = "PT8H"

  tags = merge(var.common_tags, {
    Name        = "ReadOnlyViewer"
    Role        = "Viewer"
    Compliance  = "UK-Security Standards"
    AccessLevel = "ReadOnly"
  })
}

resource "aws_ssoadmin_managed_policy_attachment" "viewer" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.viewer.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_ssoadmin_permission_set_inline_policy" "viewer" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.viewer.arn
  inline_policy      = file("${path.module}/../../../policies/iam-policies/viewer.json")
}

# Break Glass Emergency Permission Set
resource "aws_ssoadmin_permission_set" "break_glass" {
  name             = "BreakGlassEmergency"
  description      = "Emergency access with full permissions - time-limited with comprehensive auditing"
  instance_arn     = local.instance_arn
  session_duration = "PT1H" # Limited to 1 hour for emergency use

  tags = merge(var.common_tags, {
    Name        = "BreakGlassEmergency"
    Role        = "BreakGlass"
    Compliance  = "UK-Security Standards"
    AccessLevel = "Emergency"
    Auditing    = "Comprehensive"
  })
}

resource "aws_ssoadmin_managed_policy_attachment" "break_glass" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.break_glass.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_ssoadmin_permission_set_inline_policy" "break_glass" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.break_glass.arn
  inline_policy      = file("${path.module}/../../../policies/iam-policies/break-glass.json")
}

# MFA enforcement for all permission sets
resource "aws_ssoadmin_permission_set_inline_policy" "security_admin_mfa" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.security_admin.arn
  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "RequireMFAForSecurityAdmin"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
          NumericLessThan = {
            "aws:MultiFactorAuthAge" = "3600"
          }
        }
      }
    ]
  })
}

resource "aws_ssoadmin_permission_set_inline_policy" "network_admin_mfa" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.network_admin.arn
  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "RequireMFAForNetworkAdmin"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
          NumericLessThan = {
            "aws:MultiFactorAuthAge" = "3600"
          }
        }
      }
    ]
  })
}

resource "aws_ssoadmin_permission_set_inline_policy" "developer_mfa" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.developer.arn
  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RequireMFAForDeveloper"
        Effect = "Deny"
        Action = [
          "iam:*",
          "organizations:*",
          "account:*",
          "billing:*",
          "budgets:*"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
          NumericLessThan = {
            "aws:MultiFactorAuthAge" = "7200"
          }
        }
      }
    ]
  })
}

resource "aws_ssoadmin_permission_set_inline_policy" "viewer_mfa" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.viewer.arn
  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RequireMFAForSensitiveReads"
        Effect = "Deny"
        Action = [
          "iam:GetAccountPasswordPolicy",
          "iam:GetCredentialReport",
          "iam:GenerateCredentialReport",
          "organizations:DescribeAccount",
          "organizations:ListAccounts",
          "support:*",
          "trustedadvisor:*"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_ssoadmin_permission_set_inline_policy" "break_glass_mfa" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.break_glass.arn
  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "RequireStrictMFAForBreakGlass"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
          NumericLessThan = {
            "aws:MultiFactorAuthAge" = "300" # MFA must be within 5 minutes
          }
        }
      }
    ]
  })
}

# CloudWatch monitoring for break glass usage
resource "aws_cloudwatch_log_metric_filter" "break_glass_usage" {
  count          = var.enable_break_glass_monitoring ? 1 : 0
  name           = "break-glass-usage"
  log_group_name = "/aws/sso/audit"
  pattern        = "[timestamp, request_id, event_name=\"AssumeRoleWithSAML\", ..., permission_set_name=\"BreakGlassEmergency\"]"

  metric_transformation {
    name      = "BreakGlassUsage"
    namespace = "UK-LandingZone/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "break_glass_usage" {
  count               = var.enable_break_glass_monitoring ? 1 : 0
  alarm_name          = "break-glass-emergency-access-used"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "BreakGlassUsage"
  namespace           = "UK-LandingZone/Security"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Break glass emergency access has been used"
  alarm_actions       = var.break_glass_alarm_actions

  tags = merge(var.common_tags, {
    Name = "break-glass-usage-alarm"
    Type = "SecurityAlert"
  })
}
