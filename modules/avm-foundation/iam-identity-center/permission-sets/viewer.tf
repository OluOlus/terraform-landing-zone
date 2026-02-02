# Viewer Permission Set
# Provides read-only access across all services with compliance controls

resource "aws_ssoadmin_permission_set" "viewer" {
  name             = "ReadOnlyViewer"
  description      = "Read-only access across all services with specified region restrictions"
  instance_arn     = var.instance_arn
  session_duration = "PT8H"

  tags = merge(var.common_tags, {
    Name        = "ReadOnlyViewer"
    Role        = "Viewer"
    Compliance  = "UK-Security Standards"
    AccessLevel = "ReadOnly"
  })
}

# Attach AWS managed policy for read-only access
resource "aws_ssoadmin_managed_policy_attachment" "viewer" {
  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.viewer.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Attach custom inline policy for enhanced read-only permissions with UK restrictions
resource "aws_ssoadmin_permission_set_inline_policy" "viewer" {
  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.viewer.arn
  inline_policy      = file("${path.root}/policies/iam-policies/viewer.json")
}

# Configure basic MFA requirement for sensitive read operations
resource "aws_ssoadmin_permission_set_inline_policy" "viewer_mfa" {
  instance_arn       = var.instance_arn
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