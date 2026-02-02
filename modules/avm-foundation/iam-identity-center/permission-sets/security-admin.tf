# Security Administrator Permission Set
# Provides comprehensive access to security services with compliance controls

resource "aws_ssoadmin_permission_set" "security_admin" {
  name             = "SecurityAdministrator"
  description      = "Full access to security services (SecurityHub, GuardDuty, Config) with compliance controls"
  instance_arn     = var.instance_arn
  session_duration = "PT4H"

  tags = merge(var.common_tags, {
    Name        = "SecurityAdministrator"
    Role        = "SecurityAdmin"
    Compliance  = "UK-Security Standards"
    AccessLevel = "Administrative"
  })
}

# Attach AWS managed policy for security audit
resource "aws_ssoadmin_managed_policy_attachment" "security_admin_audit" {
  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.security_admin.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# Attach custom inline policy for enhanced security permissions
resource "aws_ssoadmin_permission_set_inline_policy" "security_admin" {
  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.security_admin.arn
  inline_policy      = file("${path.root}/policies/iam-policies/security-admin.json")
}

# Configure MFA requirement
resource "aws_ssoadmin_permission_set_inline_policy" "security_admin_mfa" {
  instance_arn       = var.instance_arn
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