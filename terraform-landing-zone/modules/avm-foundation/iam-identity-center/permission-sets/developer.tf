# Developer Permission Set
# Provides development access with guardrails and compliance controls

resource "aws_ssoadmin_permission_set" "developer" {
  name             = "Developer"
  description      = "Development access with guardrails, specified region restrictions, and mandatory tagging"
  instance_arn     = var.instance_arn
  session_duration = "PT8H"

  tags = merge(var.common_tags, {
    Name        = "Developer"
    Role        = "Developer"
    Compliance  = "UK-Security Standards"
    AccessLevel = "Development"
  })
}

# Attach AWS managed policy for power user access (with some restrictions)
resource "aws_ssoadmin_managed_policy_attachment" "developer_power_user" {
  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.developer.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# Attach custom inline policy for developer-specific permissions and restrictions
resource "aws_ssoadmin_permission_set_inline_policy" "developer" {
  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.developer.arn
  inline_policy      = file("${path.root}/policies/iam-policies/developer.json")
}

# Configure MFA requirement (less strict than admin roles)
resource "aws_ssoadmin_permission_set_inline_policy" "developer_mfa" {
  instance_arn       = var.instance_arn
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