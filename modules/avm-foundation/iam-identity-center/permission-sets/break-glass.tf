# Break Glass Permission Set
# Provides emergency access with full permissions and comprehensive auditing

resource "aws_ssoadmin_permission_set" "break_glass" {
  name             = "BreakGlassEmergency"
  description      = "Emergency access with full permissions - time-limited with comprehensive auditing"
  instance_arn     = var.instance_arn
  session_duration = "PT1H" # Limited to 1 hour for emergency use

  tags = merge(var.common_tags, {
    Name        = "BreakGlassEmergency"
    Role        = "BreakGlass"
    Compliance  = "UK-Security Standards"
    AccessLevel = "Emergency"
    Auditing    = "Comprehensive"
  })
}

# Attach AWS managed policy for administrator access
resource "aws_ssoadmin_managed_policy_attachment" "break_glass_admin" {
  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.break_glass.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Attach custom inline policy for break glass controls and audit protection
resource "aws_ssoadmin_permission_set_inline_policy" "break_glass" {
  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.break_glass.arn
  inline_policy      = file("${path.root}/policies/iam-policies/break-glass.json")
}

# Configure strict MFA requirement for break glass access
resource "aws_ssoadmin_permission_set_inline_policy" "break_glass_mfa" {
  instance_arn       = var.instance_arn
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
      },
      {
        Sid      = "RequireBreakGlassJustification"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
        Condition = {
          "Null" : {
            "aws:RequestTag/EmergencyJustification" : "true"
          }
        }
      }
    ]
  })
}

# CloudWatch alarm for break glass usage
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