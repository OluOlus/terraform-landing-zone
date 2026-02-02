# Network Administrator Permission Set
# Provides comprehensive access to networking services with compliance controls

resource "aws_ssoadmin_permission_set" "network_admin" {
  name             = "NetworkAdministrator"
  description      = "Full access to networking services with specified region restrictions and compliance controls"
  instance_arn     = var.instance_arn
  session_duration = "PT4H"

  tags = merge(var.common_tags, {
    Name        = "NetworkAdministrator"
    Role        = "NetworkAdmin"
    Compliance  = "UK-Security Standards"
    AccessLevel = "Administrative"
  })
}

# Attach AWS managed policy for network administration
resource "aws_ssoadmin_managed_policy_attachment" "network_admin" {
  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.network_admin.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/job-function/NetworkAdministrator"
}

# Attach custom inline policy for enhanced network permissions
resource "aws_ssoadmin_permission_set_inline_policy" "network_admin" {
  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.network_admin.arn
  inline_policy      = file("${path.root}/policies/iam-policies/network-admin.json")
}

# Configure MFA requirement
resource "aws_ssoadmin_permission_set_inline_policy" "network_admin_mfa" {
  instance_arn       = var.instance_arn
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